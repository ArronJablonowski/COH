package lifecycledisposition

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func dispositionRequestDigest(value evidencelifecycle.DispositionRequest) (string, error) {
	if !validRequest(value) {
		return "", lifecycleError(evidencelifecycle.InvalidInput, "disposition_request_invalid", false)
	}
	canonical, err := canonicalValue(value)
	if err != nil {
		return "", lifecycleError(evidencelifecycle.InvalidInput, "disposition_request_invalid", false)
	}
	return digest("COH-LIFECYCLE-DISPOSITION-REQUEST-V1\x00", canonical), nil
}

func validRequest(value evidencelifecycle.DispositionRequest) bool {
	if !validCase(value.Case) || !uuidPattern.MatchString(value.OperationID) ||
		!digestPattern.MatchString(value.ArtifactSetDigest) ||
		!digestPattern.MatchString(value.AuthorizationCustodyReceiptDigest) ||
		!digestPattern.MatchString(value.LifecycleReceiptDigest) || value.Deadline.IsZero() ||
		value.Evidence.Case != value.Case || value.Evidence.ArtifactSetDigest != value.ArtifactSetDigest ||
		!digestPattern.MatchString(value.Evidence.LineageDigest) ||
		!digestPattern.MatchString(value.Evidence.ComponentSetDigest) || len(value.Evidence.Artifacts) == 0 ||
		len(value.Evidence.Artifacts) > 8192 {
		return false
	}
	seen := make(map[string]struct{}, len(value.Evidence.Artifacts))
	for _, artifact := range value.Evidence.Artifacts {
		reference := artifact.Reference
		if !validArtifact(reference.Artifact) || !validArtifact(reference.Manifest) ||
			reference.Manifest.MediaType != "application/vnd.coh.artifact-manifest+json" ||
			reference.Manifest.Classification != reference.Artifact.Classification ||
			!digestPattern.MatchString(reference.ManifestProvenanceDigest) ||
			!digestPattern.MatchString(reference.IngestionReceiptDigest) {
			return false
		}
		if _, duplicate := seen[reference.Artifact.Digest]; duplicate {
			return false
		}
		seen[reference.Artifact.Digest] = struct{}{}
	}
	return true
}

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func validArtifact(value domain.ArtifactRef) bool {
	return digestPattern.MatchString(value.Digest) && value.Length > 0 && value.MediaType != "" &&
		(value.Classification == "public" || value.Classification == "internal" ||
			value.Classification == "confidential" || value.Classification == "restricted")
}

func validateStored(value storedOperation) bool {
	if !validCase(value.Case) || !uuidPattern.MatchString(value.OperationID) ||
		!digestPattern.MatchString(value.RequestDigest) || !digestPattern.MatchString(value.ArtifactSetDigest) ||
		!digestPattern.MatchString(value.AuthorizationCustodyReceiptDigest) ||
		!digestPattern.MatchString(value.LifecycleReceiptDigest) || value.AttemptedAt.IsZero() ||
		len(value.Objects) == 0 || len(value.Objects) > 8192 {
		return false
	}
	previous := ""
	for _, object := range value.Objects {
		_, referenceErr := evidenceingest.PublishedObjectBindingDigest(object.Reference)
		if !digestPattern.MatchString(object.ArtifactDigest) ||
			!digestPattern.MatchString(object.IngestionReceiptDigest) ||
			!digestPattern.MatchString(object.EncryptedObjectDigest) || object.KeyRevision == 0 ||
			object.Reference.Case != value.Case || object.Reference.PlaintextDigest != object.ArtifactDigest ||
			referenceErr != nil || previous != "" && object.ArtifactDigest <= previous {
			return false
		}
		previous = object.ArtifactDigest
	}
	return value.Attestation == nil || exactAttestation(value)
}

func exactAttestation(value storedOperation) bool {
	if value.Attestation == nil || evidencelifecycle.ValidateDispositionAttestation(*value.Attestation) != nil {
		return false
	}
	attestation := value.Attestation
	if attestation.Case != value.Case || attestation.OperationID != value.OperationID ||
		attestation.AttestationID != deterministicUUID("COH-LIFECYCLE-DISPOSITION-ATTESTATION-V1\x00",
			value.RequestDigest) ||
		attestation.ArtifactSetDigest != value.ArtifactSetDigest ||
		attestation.AuthorizationCustodyReceiptDigest != value.AuthorizationCustodyReceiptDigest ||
		attestation.LifecycleReceiptDigest != value.LifecycleReceiptDigest ||
		attestation.Mechanism != "encrypted_object_removal" || len(attestation.Objects) != len(value.Objects) ||
		!attestation.AttemptedAt.Equal(value.AttemptedAt) || !attestation.CompletedAt.Equal(value.AttemptedAt) {
		return false
	}
	for index, object := range value.Objects {
		outcome := attestation.Objects[index]
		if outcome.Ordinal != uint16(index+1) || outcome.ArtifactDigest != object.ArtifactDigest ||
			outcome.EncryptedObjectDigest != object.EncryptedObjectDigest || outcome.KeyRevision != object.KeyRevision ||
			outcome.Outcome != evidencelifecycle.DispositionRemoved ||
			outcome.OutcomeDigest != outcomeDigest(object, evidencelifecycle.DispositionRemoved) {
			return false
		}
	}
	return true
}

func sortedPlans(values []plannedObject) []plannedObject {
	result := append([]plannedObject(nil), values...)
	sort.Slice(result, func(left, right int) bool { return result[left].ArtifactDigest < result[right].ArtifactDigest })
	return result
}

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
		return lifecycleError(evidencelifecycle.Denied, "disposition_encoding_invalid", false)
	}
	canonical, err := canonicalValue(output)
	if err != nil || !bytes.Equal(canonical, data) {
		return lifecycleError(evidencelifecycle.Denied, "disposition_noncanonical", false)
	}
	return nil
}

func digest(domainName string, value []byte) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domainName))
	_, _ = hash.Write(value)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func outcomeDigest(value plannedObject, outcome evidencelifecycle.DispositionOutcome) string {
	canonical, _ := canonicalValue(struct {
		ArtifactDigest        string `json:"artifact_digest"`
		EncryptedObjectDigest string `json:"encrypted_object_digest"`
		KeyRevision           uint64 `json:"key_revision"`
		Outcome               string `json:"outcome"`
	}{value.ArtifactDigest, value.EncryptedObjectDigest, value.KeyRevision, string(outcome)})
	return digest("COH-EVIDENCE-DISPOSITION-OUTCOME-V1\x00", canonical)
}

func deterministicUUID(domainName, value string) string {
	sum := sha256.Sum256([]byte(domainName + value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func lifecycleError(code evidencelifecycle.ErrorCode, reason string, retryable bool) error {
	return &evidencelifecycle.Error{Code: code, Reason: reason, Retryable: retryable}
}

func validNow(value time.Time) bool { return !value.IsZero() && value.Equal(value.UTC()) }
