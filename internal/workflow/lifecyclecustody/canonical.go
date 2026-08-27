package lifecyclecustody

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	mediaPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_.+\-]{0,126}/[a-z0-9][a-z0-9!#$&^_.+\-]{0,126}$`)
)

type requestWire struct {
	Operation                    evidencelifecycle.Operation `json:"operation"`
	Phase                        evidencelifecycle.Phase     `json:"phase"`
	Case                         caseWire                    `json:"case"`
	ActorID                      string                      `json:"actor_id"`
	ActorRevision                uint64                      `json:"actor_revision"`
	ArtifactSetDigest            string                      `json:"artifact_set_digest"`
	Subjects                     []evidenceWire              `json:"subjects"`
	ManifestDigest               *string                     `json:"manifest_digest"`
	PackageDigest                *string                     `json:"package_digest"`
	SourceDigest                 *string                     `json:"source_digest"`
	PurposeDigest                *string                     `json:"purpose_digest"`
	DestinationDigest            *string                     `json:"destination_digest"`
	ReasonDigest                 *string                     `json:"reason_digest"`
	ApprovalDigest               *string                     `json:"approval_digest"`
	SignatureDigest              *string                     `json:"signature_digest"`
	LifecycleReceiptDigest       *string                     `json:"lifecycle_receipt_digest"`
	PriorAuthorizationDigest     *string                     `json:"prior_authorization_digest"`
	DispositionAttestationDigest *string                     `json:"disposition_attestation_digest"`
	PolicyDigest                 string                      `json:"policy_digest"`
	ExpectedCaseRevision         uint64                      `json:"expected_case_revision"`
	ExpectedHead                 headWire                    `json:"expected_head"`
	Deadline                     string                      `json:"deadline"`
}

type caseWire struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type artifactWire struct {
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Classification string `json:"classification"`
	Length         int64  `json:"length"`
}

type evidenceWire struct {
	Artifact                 artifactWire `json:"artifact"`
	Manifest                 artifactWire `json:"manifest"`
	ManifestProvenanceDigest string       `json:"manifest_provenance_digest"`
	IngestionReceiptDigest   string       `json:"ingestion_receipt_digest"`
}

type headWire struct {
	Case         caseWire `json:"case"`
	Sequence     uint64   `json:"sequence"`
	ChainHash    string   `json:"chain_hash"`
	LastRecordAt *string  `json:"last_record_at"`
}

type proofWire struct {
	ReceiptDigest string `json:"receipt_digest"`
	RecordDigest  string `json:"record_digest"`
	AuditDigest   string `json:"audit_digest"`
	Sequence      uint64 `json:"sequence"`
	ChainHash     string `json:"chain_hash"`
	CreatedAt     string `json:"created_at"`
}

type setWire struct {
	Case          caseWire    `json:"case"`
	RequestDigest string      `json:"request_digest"`
	InitialHead   headWire    `json:"initial_head"`
	Proofs        []proofWire `json:"proofs"`
	SetDigest     string      `json:"set_digest"`
}

func requestDigest(value evidencelifecycle.CustodyRequest) (string, error) {
	if !validRequest(value) {
		return "", lifecycleError(evidencelifecycle.InvalidInput, "custody_request_invalid", false)
	}
	canonical, err := canonicalValue(requestToWire(value))
	if err != nil {
		return "", err
	}
	return digest("COH-LIFECYCLE-CUSTODY-REQUEST-V1\x00", canonical), nil
}

func validRequest(value evidencelifecycle.CustodyRequest) bool {
	if !validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) || value.ActorRevision == 0 ||
		value.ExpectedCaseRevision == 0 || !digestPattern.MatchString(value.ArtifactSetDigest) ||
		!digestPattern.MatchString(value.PolicyDigest) || !validHead(value.ExpectedHead, value.Case) ||
		value.Deadline.IsZero() || len(value.Subjects) == 0 || len(value.Subjects) > 4096 ||
		!validOperationPhase(value.Operation, value.Phase) || !validRequestFields(value) {
		return false
	}
	seenSubjects := make(map[evidencelifecycle.EvidenceReference]struct{}, len(value.Subjects))
	for _, subject := range value.Subjects {
		if !validEvidence(subject) {
			return false
		}
		if _, duplicate := seenSubjects[subject]; duplicate {
			return false
		}
		seenSubjects[subject] = struct{}{}
	}
	for _, optional := range []*string{value.ManifestDigest, value.PackageDigest, value.SourceDigest,
		value.PurposeDigest, value.DestinationDigest, value.ReasonDigest, value.ApprovalDigest,
		value.SignatureDigest, value.LifecycleReceiptDigest, value.PriorAuthorizationDigest,
		value.DispositionAttestationDigest} {
		if optional != nil && !digestPattern.MatchString(*optional) {
			return false
		}
	}
	return value.PackageDigest == nil || value.DispositionAttestationDigest == nil
}

func validRequestFields(value evidencelifecycle.CustodyRequest) bool {
	switch value.Operation {
	case evidencelifecycle.Import:
		return value.Phase == evidencelifecycle.Completed && value.SourceDigest != nil &&
			value.PriorAuthorizationDigest == nil && value.DispositionAttestationDigest == nil
	case evidencelifecycle.Export:
		if value.PurposeDigest == nil || value.DestinationDigest == nil {
			return false
		}
		if value.Phase == evidencelifecycle.Authorized {
			return value.PackageDigest == nil && value.PriorAuthorizationDigest == nil
		}
		return value.Phase == evidencelifecycle.Completed && value.PackageDigest != nil &&
			value.PriorAuthorizationDigest != nil
	case evidencelifecycle.PlaceHold, evidencelifecycle.ReleaseHold:
		return value.Phase == evidencelifecycle.Completed && value.ReasonDigest != nil &&
			value.LifecycleReceiptDigest != nil && value.PriorAuthorizationDigest == nil
	case evidencelifecycle.Delete:
		if value.ReasonDigest == nil {
			return false
		}
		if value.Phase == evidencelifecycle.Authorized {
			return value.PriorAuthorizationDigest == nil && value.LifecycleReceiptDigest == nil &&
				value.DispositionAttestationDigest == nil
		}
		return value.Phase == evidencelifecycle.Completed && value.PriorAuthorizationDigest != nil &&
			value.LifecycleReceiptDigest != nil && value.DispositionAttestationDigest != nil
	default:
		return false
	}
}

func validOperationPhase(operation evidencelifecycle.Operation, phase evidencelifecycle.Phase) bool {
	if phase != evidencelifecycle.Authorized && phase != evidencelifecycle.Completed {
		return false
	}
	switch operation {
	case evidencelifecycle.Import, evidencelifecycle.Export, evidencelifecycle.PlaceHold,
		evidencelifecycle.ReleaseHold, evidencelifecycle.Delete:
		return true
	default:
		return false
	}
}

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func validEvidence(value evidencelifecycle.EvidenceReference) bool {
	return validArtifact(value.Artifact) && validArtifact(value.Manifest) &&
		value.Manifest.MediaType == "application/vnd.coh.artifact-manifest+json" &&
		value.Manifest.Classification == value.Artifact.Classification && value.Manifest.Digest != value.Artifact.Digest &&
		digestPattern.MatchString(value.ManifestProvenanceDigest) && digestPattern.MatchString(value.IngestionReceiptDigest)
}

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && mediaPattern.MatchString(value.MediaType) &&
		(value.Classification == "public" || value.Classification == "internal" ||
			value.Classification == "confidential" || value.Classification == "restricted") && value.Length > 0
}

func validHead(value evidencelifecycle.CustodyHead, scope domain.CaseRef) bool {
	if value.Case != scope || !digestPattern.MatchString(value.ChainHash) {
		return false
	}
	if value.Sequence == 0 {
		return value.ChainHash == custody.GenesisHash && value.LastRecordAt == nil
	}
	return value.ChainHash != custody.GenesisHash && value.LastRecordAt != nil && !value.LastRecordAt.IsZero()
}

func requestToWire(value evidencelifecycle.CustodyRequest) requestWire {
	subjects := make([]evidenceWire, len(value.Subjects))
	for index, subject := range value.Subjects {
		subjects[index] = evidenceToWire(subject)
	}
	return requestWire{value.Operation, value.Phase, caseToWire(value.Case), value.ActorID, value.ActorRevision,
		value.ArtifactSetDigest, subjects, clone(value.ManifestDigest), clone(value.PackageDigest), clone(value.SourceDigest),
		clone(value.PurposeDigest), clone(value.DestinationDigest), clone(value.ReasonDigest), clone(value.ApprovalDigest),
		clone(value.SignatureDigest), clone(value.LifecycleReceiptDigest), clone(value.PriorAuthorizationDigest),
		clone(value.DispositionAttestationDigest), value.PolicyDigest, value.ExpectedCaseRevision,
		lifecycleHeadToWire(value.ExpectedHead), formatTime(value.Deadline)}
}

func setToWire(value storedSet) setWire {
	proofs := make([]proofWire, len(value.Proofs))
	for index, proof := range value.Proofs {
		proofs[index] = proofWire(proof)
	}
	return setWire{caseToWire(value.Case), value.RequestDigest, custodyHeadToWire(value.InitialHead), proofs, value.SetDigest}
}

func setFromWire(value setWire) (storedSet, error) {
	head, err := headFromWire(value.InitialHead)
	if err != nil {
		return storedSet{}, err
	}
	proofs := make([]storedProof, len(value.Proofs))
	for index, proof := range value.Proofs {
		if _, err = time.Parse(time.RFC3339Nano, proof.CreatedAt); err != nil {
			return storedSet{}, err
		}
		proofs[index] = storedProof(proof)
	}
	return storedSet{Case: caseFromWire(value.Case), RequestDigest: value.RequestDigest,
		InitialHead: head, Proofs: proofs, SetDigest: value.SetDigest}, nil
}

func caseToWire(value domain.CaseRef) caseWire {
	return caseWire{value.OrganizationID, value.TenantID, value.CaseID}
}
func caseFromWire(value caseWire) domain.CaseRef {
	return domain.CaseRef{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}
func artifactToWire(value domain.ArtifactRef) artifactWire {
	return artifactWire{value.Digest, value.MediaType, value.Classification, value.Length}
}
func evidenceToWire(value evidencelifecycle.EvidenceReference) evidenceWire {
	return evidenceWire{artifactToWire(value.Artifact), artifactToWire(value.Manifest),
		value.ManifestProvenanceDigest, value.IngestionReceiptDigest}
}
func lifecycleHeadToWire(value evidencelifecycle.CustodyHead) headWire {
	return headWire{caseToWire(value.Case), value.Sequence, value.ChainHash, timePointer(value.LastRecordAt)}
}
func custodyHeadToWire(value custody.Head) headWire {
	return headWire{caseToWire(value.Case), value.Sequence, value.ChainHash, timePointer(value.LastRecordAt)}
}
func headFromWire(value headWire) (custody.Head, error) {
	result := custody.Head{Case: caseFromWire(value.Case), Sequence: value.Sequence, ChainHash: value.ChainHash}
	if value.LastRecordAt != nil {
		parsed, err := time.Parse(time.RFC3339Nano, *value.LastRecordAt)
		if err != nil || formatTime(parsed) != *value.LastRecordAt {
			return custody.Head{}, lifecycleError(evidencelifecycle.Denied, "custody_set_time_invalid", false)
		}
		result.LastRecordAt = &parsed
	}
	return result, nil
}
func timePointer(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := formatTime(*value)
	return &formatted
}
func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return domaincontract.Canonicalize(encoded)
}

func decodeCanonical(data []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return lifecycleError(evidencelifecycle.Denied, "custody_set_encoding_invalid", false)
	}
	canonical, err := canonicalValue(output)
	if err != nil || !bytes.Equal(canonical, data) {
		return lifecycleError(evidencelifecycle.Denied, "custody_set_noncanonical", false)
	}
	return nil
}

func digest(domainName string, value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domainName))
	_, _ = hash.Write(value)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func deterministicUUID(domainName, value string) string {
	sum := sha256.Sum256([]byte(domainName + value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func clone[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

func lifecycleError(code evidencelifecycle.ErrorCode, reason string, retryable bool) error {
	return &evidencelifecycle.Error{Code: code, Reason: reason, Retryable: retryable}
}
