package retrievalguard

import (
	"github.com/ArronJablonowski/COH/internal/domain"
)

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
type sourceWire struct {
	Kind             SourceKind   `json:"kind"`
	Artifact         artifactWire `json:"artifact"`
	Trust            TrustLabel   `json:"trust"`
	ProvenanceDigest string       `json:"provenance_digest"`
}
type profileWire struct {
	Name                 string   `json:"name"`
	Revision             uint64   `json:"revision"`
	MaximumBytes         int64    `json:"maximum_bytes"`
	AllowedMediaTypes    []string `json:"allowed_media_types"`
	DenyActiveFormats    bool     `json:"deny_active_formats"`
	RedactSecrets        bool     `json:"redact_secrets"`
	NeutralizeDirectives bool     `json:"neutralize_directives"`
	ProfileDigest        string   `json:"profile_digest"`
}
type requestWire struct {
	SchemaVersion   string      `json:"schema_version"`
	ContractVersion string      `json:"contract_version"`
	RequestID       string      `json:"request_id"`
	IdempotencyKey  string      `json:"idempotency_key"`
	Case            caseWire    `json:"case"`
	TaskID          string      `json:"task_id"`
	ActorID         string      `json:"actor_id"`
	ActorRevision   uint64      `json:"actor_revision"`
	Source          sourceWire  `json:"source"`
	Profile         profileWire `json:"profile"`
	PolicyDigest    string      `json:"policy_digest"`
	Deadline        string      `json:"deadline"`
}
type decisionWire struct {
	SchemaVersion    string   `json:"schema_version"`
	ContractVersion  string   `json:"contract_version"`
	DecisionID       string   `json:"decision_id"`
	DecisionDigest   string   `json:"decision_digest"`
	RequestDigest    string   `json:"request_digest"`
	Case             caseWire `json:"case"`
	TaskID           string   `json:"task_id"`
	ActorID          string   `json:"actor_id"`
	ActorRevision    uint64   `json:"actor_revision"`
	PolicyDigest     string   `json:"policy_digest"`
	RevocationDigest string   `json:"revocation_digest"`
	Outcome          string   `json:"outcome"`
	ReasonCode       string   `json:"reason_code"`
	Revision         uint64   `json:"revision"`
	IssuedAt         string   `json:"issued_at"`
	ExpiresAt        string   `json:"expires_at"`
}
type inspectionWire struct {
	SourceDigest           string       `json:"source_digest"`
	SourceProvenanceDigest string       `json:"source_provenance_digest"`
	Sanitized              artifactWire `json:"sanitized"`
	Trust                  TrustLabel   `json:"trust"`
	Findings               []Finding    `json:"findings"`
	FindingsDigest         string       `json:"findings_digest"`
	RedactionCount         uint32       `json:"redaction_count"`
	Complete               bool         `json:"complete"`
	InspectorDigest        string       `json:"inspector_digest"`
}
type recordWire struct {
	SchemaVersion            string         `json:"schema_version"`
	ContractVersion          string         `json:"contract_version"`
	Request                  requestWire    `json:"request"`
	IntentDigest             string         `json:"intent_digest"`
	IdempotencyDigest        string         `json:"idempotency_digest"`
	DecisionDigest           string         `json:"decision_digest"`
	RevocationDigest         string         `json:"revocation_digest"`
	Inspection               inspectionWire `json:"inspection"`
	AuditEventDigest         string         `json:"audit_event_digest"`
	PreviousProvenanceDigest string         `json:"previous_provenance_digest"`
	ProvenanceDigest         string         `json:"provenance_digest"`
	CreatedAt                string         `json:"created_at"`
	Revision                 uint64         `json:"revision"`
}

func caseToWire(v domain.CaseRef) caseWire { return caseWire{v.OrganizationID, v.TenantID, v.CaseID} }
func artifactToWire(v domain.ArtifactRef) artifactWire {
	return artifactWire{v.Digest, v.MediaType, v.Classification, v.Length}
}
func sourceToWire(v Source) sourceWire {
	return sourceWire{v.Kind, artifactToWire(v.Artifact), v.Trust, v.ProvenanceDigest}
}
func profileToWire(v InspectionProfile) profileWire {
	return profileWire{v.Name, v.Revision, v.MaximumBytes, append([]string{}, v.AllowedMediaTypes...), v.DenyActiveFormats, v.RedactSecrets, v.NeutralizeDirectives, v.ProfileDigest}
}
func requestToWire(v Request) requestWire {
	return requestWire{v.SchemaVersion, v.ContractVersion, v.RequestID, v.IdempotencyKey, caseToWire(v.Case), v.TaskID, v.ActorID, v.ActorRevision, sourceToWire(v.Source), profileToWire(v.Profile), v.PolicyDigest, formatTime(v.Deadline)}
}
func decisionToWire(v Decision) decisionWire {
	return decisionWire{v.SchemaVersion, v.ContractVersion, v.DecisionID, v.DecisionDigest, v.RequestDigest, caseToWire(v.Case), v.TaskID, v.ActorID, v.ActorRevision, v.PolicyDigest, v.RevocationDigest, v.Outcome, v.ReasonCode, v.Revision, formatTime(v.IssuedAt), formatTime(v.ExpiresAt)}
}
func inspectionToWire(v InspectionResult) inspectionWire {
	return inspectionWire{v.SourceDigest, v.SourceProvenanceDigest, artifactToWire(v.Sanitized), v.Trust, append([]Finding{}, v.Findings...), v.FindingsDigest, v.RedactionCount, v.Complete, v.InspectorDigest}
}
func recordToWire(v Record) recordWire {
	return recordWire{v.SchemaVersion, v.ContractVersion, requestToWire(v.Request), v.IntentDigest, v.IdempotencyDigest, v.DecisionDigest, v.RevocationDigest, inspectionToWire(v.Inspection), v.AuditEventDigest, v.PreviousProvenanceDigest, v.ProvenanceDigest, formatTime(v.CreatedAt), v.Revision}
}
