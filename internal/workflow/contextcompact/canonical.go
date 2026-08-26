package contextcompact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

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

type intentWire struct {
	SchemaVersion   string   `json:"schema_version"`
	ContractVersion string   `json:"contract_version"`
	CompactionID    string   `json:"compaction_id"`
	RunID           string   `json:"run_id"`
	TaskID          string   `json:"task_id"`
	Case            caseWire `json:"case"`
	PolicyDigest    string   `json:"policy_digest"`
	ProviderRoute   string   `json:"provider_route"`
	Sources         []Source `json:"sources"`
	CreatedAt       string   `json:"created_at"`
	Deadline        string   `json:"deadline"`
}

type stateWire struct {
	SchemaVersion            string       `json:"schema_version"`
	ContractVersion          string       `json:"contract_version"`
	CompactionID             string       `json:"compaction_id"`
	RunID                    string       `json:"run_id"`
	TaskID                   string       `json:"task_id"`
	Case                     caseWire     `json:"case"`
	PolicyDigest             string       `json:"policy_digest"`
	ProviderRoute            string       `json:"provider_route"`
	Sources                  []Source     `json:"sources"`
	SourceManifestDigest     string       `json:"source_manifest_digest"`
	IntentDigest             string       `json:"intent_digest"`
	IdempotencyDigest        string       `json:"idempotency_digest"`
	Summary                  artifactWire `json:"summary"`
	SummaryTrust             TrustLabel   `json:"summary_trust"`
	Status                   Status       `json:"status"`
	ReasonCode               string       `json:"reason_code"`
	PreviousProvenanceDigest string       `json:"previous_provenance_digest"`
	ProvenanceDigest         string       `json:"provenance_digest"`
	CreatedAt                string       `json:"created_at"`
	Deadline                 string       `json:"deadline"`
	UpdatedAt                string       `json:"updated_at"`
	Revision                 uint64       `json:"revision"`
}

func CanonicalIntent(value Intent) ([]byte, error) {
	if err := validateIntent(value); err != nil {
		return nil, err
	}
	return canonicalValue(intentToWire(value))
}

func CanonicalState(value State) ([]byte, error) {
	if err := validateState(value); err != nil {
		return nil, err
	}
	return canonicalValue(stateToWire(value))
}

func intentDigest(value Intent) (string, error) {
	canonical, err := CanonicalIntent(value)
	if err != nil {
		return "", err
	}
	return compactDigest("COH-CONTEXT-COMPACTION-INTENT-V1\x00", canonical), nil
}

func sourceManifestDigest(values []Source) (string, error) {
	if len(values) == 0 || len(values) > MaximumSources {
		return "", newError(InvalidInput, "compaction_source_manifest_invalid", false, nil)
	}
	for index, source := range values {
		if source.Sequence != uint32(index+1) || !validSource(source) {
			return "", newError(InvalidInput, "compaction_source_manifest_invalid", false, nil)
		}
	}
	canonical, err := canonicalValue(cloneSources(values))
	if err != nil {
		return "", err
	}
	return compactDigest("COH-CONTEXT-COMPACTION-SOURCE-MANIFEST-V1\x00", canonical), nil
}

func provenanceDigest(prior, reason string, value State) (string, error) {
	copyValue := cloneState(value)
	copyValue.ProvenanceDigest = ""
	canonical, err := canonicalValue(stateToWire(copyValue))
	if err != nil {
		return "", err
	}
	payload := slices.Concat([]byte(prior), []byte{0}, []byte(reason), []byte{0}, canonical)
	return compactDigest("COH-CONTEXT-COMPACTION-PROVENANCE-V1\x00", payload), nil
}

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(Internal, "compaction_encoding_failed", false, nil)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(Internal, "compaction_canonicalization_failed", false, nil)
	}
	return canonical, nil
}

func compactDigest(domain string, value []byte) string {
	sum := sha256.Sum256(append([]byte(domain), value...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func intentToWire(value Intent) intentWire {
	return intentWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		CompactionID: value.CompactionID, RunID: value.RunID, TaskID: value.TaskID, Case: caseToWire(value.Case),
		PolicyDigest: value.PolicyDigest, ProviderRoute: value.ProviderRoute, Sources: cloneSources(value.Sources),
		CreatedAt: formatTime(value.CreatedAt), Deadline: formatTime(value.Deadline)}
}

func stateToWire(value State) stateWire {
	return stateWire{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		CompactionID: value.CompactionID, RunID: value.RunID, TaskID: value.TaskID, Case: caseToWire(value.Case),
		PolicyDigest: value.PolicyDigest, ProviderRoute: value.ProviderRoute, Sources: cloneSources(value.Sources),
		SourceManifestDigest: value.SourceManifestDigest, IntentDigest: value.IntentDigest,
		IdempotencyDigest: value.IdempotencyDigest,
		Summary:           artifactToWire(value.Summary), SummaryTrust: value.SummaryTrust,
		Status: value.Status, ReasonCode: value.ReasonCode,
		PreviousProvenanceDigest: value.PreviousProvenanceDigest, ProvenanceDigest: value.ProvenanceDigest,
		CreatedAt: formatTime(value.CreatedAt), Deadline: formatTime(value.Deadline),
		UpdatedAt: formatTime(value.UpdatedAt), Revision: value.Revision}
}

func caseToWire(value domain.CaseRef) caseWire {
	return caseWire{OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID}
}

func artifactToWire(value domain.ArtifactRef) artifactWire {
	return artifactWire{Digest: value.Digest, MediaType: value.MediaType,
		Classification: value.Classification, Length: value.Length}
}

func formatTime(value time.Time) string { return value.UTC().Format(timestampLayout) }

func cloneSources(values []Source) []Source { return append([]Source{}, values...) }

func cloneState(value State) State {
	copyValue := value
	copyValue.Sources = cloneSources(value.Sources)
	return copyValue
}
