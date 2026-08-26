// Package retrievalguard keeps hostile retrieved content in a data-only,
// policy-authorized inspection boundary.
package retrievalguard

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

const (
	RequestSchemaVersion  = "coh.retrieval-inspection/v1"
	DecisionSchemaVersion = "coh.retrieval-decision/v1"
	RecordSchemaVersion   = "coh.retrieval-record/v1"
	ContractVersion       = "1.0.0"
	MaximumFindings       = 64
	MaximumSourceBytes    = int64(64 << 20)
)

type SourceKind string

const (
	LogSource         SourceKind = "log"
	DocumentSource    SourceKind = "document"
	FeedSource        SourceKind = "feed"
	QueryOutputSource SourceKind = "query_output"
	ToolOutputSource  SourceKind = "tool_output"
	ToolErrorSource   SourceKind = "tool_error"
	MemorySource      SourceKind = "memory"
	ReportSource      SourceKind = "report"
	AttachmentSource  SourceKind = "attachment"
)

type TrustLabel string

const UntrustedContent TrustLabel = "untrusted_content"

type Source struct {
	Kind             SourceKind         `json:"kind"`
	Artifact         domain.ArtifactRef `json:"artifact"`
	Trust            TrustLabel         `json:"trust"`
	ProvenanceDigest string             `json:"provenance_digest"`
}

type InspectionProfile struct {
	Name                 string   `json:"name"`
	Revision             uint64   `json:"revision"`
	MaximumBytes         int64    `json:"maximum_bytes"`
	AllowedMediaTypes    []string `json:"allowed_media_types"`
	DenyActiveFormats    bool     `json:"deny_active_formats"`
	RedactSecrets        bool     `json:"redact_secrets"`
	NeutralizeDirectives bool     `json:"neutralize_directives"`
	ProfileDigest        string   `json:"profile_digest"`
}

type Request struct {
	SchemaVersion   string            `json:"schema_version"`
	ContractVersion string            `json:"contract_version"`
	RequestID       string            `json:"request_id"`
	IdempotencyKey  string            `json:"idempotency_key"`
	Case            domain.CaseRef    `json:"case"`
	TaskID          string            `json:"task_id"`
	ActorID         string            `json:"actor_id"`
	ActorRevision   uint64            `json:"actor_revision"`
	Source          Source            `json:"source"`
	Profile         InspectionProfile `json:"profile"`
	PolicyDigest    string            `json:"policy_digest"`
	Deadline        time.Time         `json:"deadline"`
}

type AuthorizationRequest struct {
	RequestDigest string            `json:"request_digest"`
	RequestID     string            `json:"request_id"`
	Case          domain.CaseRef    `json:"case"`
	TaskID        string            `json:"task_id"`
	ActorID       string            `json:"actor_id"`
	ActorRevision uint64            `json:"actor_revision"`
	Source        Source            `json:"source"`
	Profile       InspectionProfile `json:"profile"`
	PolicyDigest  string            `json:"policy_digest"`
	Deadline      time.Time         `json:"deadline"`
}

type Decision struct {
	SchemaVersion    string         `json:"schema_version"`
	ContractVersion  string         `json:"contract_version"`
	DecisionID       string         `json:"decision_id"`
	DecisionDigest   string         `json:"decision_digest"`
	RequestDigest    string         `json:"request_digest"`
	Case             domain.CaseRef `json:"case"`
	TaskID           string         `json:"task_id"`
	ActorID          string         `json:"actor_id"`
	ActorRevision    uint64         `json:"actor_revision"`
	PolicyDigest     string         `json:"policy_digest"`
	RevocationDigest string         `json:"revocation_digest"`
	Outcome          string         `json:"outcome"`
	ReasonCode       string         `json:"reason_code"`
	Revision         uint64         `json:"revision"`
	IssuedAt         time.Time      `json:"issued_at"`
	ExpiresAt        time.Time      `json:"expires_at"`
}

type FindingCode string

const (
	InstructionLike      FindingCode = "instruction_like"
	ScopeChangeAttempt   FindingCode = "scope_change_attempt"
	AuthorizationForgery FindingCode = "authorization_forgery"
	CredentialRequest    FindingCode = "credential_request"
	ToolDirective        FindingCode = "tool_directive"
	ExfiltrationAttempt  FindingCode = "exfiltration_attempt"
	ActiveContent        FindingCode = "active_content"
	EncodedPayload       FindingCode = "encoded_payload"
	SecretRedacted       FindingCode = "secret_redacted"
)

type Finding struct {
	Code  FindingCode `json:"code"`
	Count uint32      `json:"count"`
}

// InspectionRequest is data-only. The inspector resolves the immutable source
// internally and receives no actor, policy, approval, credential, or tool authority.
type InspectionRequest struct {
	Source       Source            `json:"source"`
	Profile      InspectionProfile `json:"profile"`
	IntentDigest string            `json:"intent_digest"`
	Deadline     time.Time         `json:"deadline"`
}

type InspectionResult struct {
	SourceDigest           string             `json:"source_digest"`
	SourceProvenanceDigest string             `json:"source_provenance_digest"`
	Sanitized              domain.ArtifactRef `json:"sanitized"`
	Trust                  TrustLabel         `json:"trust"`
	Findings               []Finding          `json:"findings"`
	FindingsDigest         string             `json:"findings_digest"`
	RedactionCount         uint32             `json:"redaction_count"`
	Complete               bool               `json:"complete"`
	InspectorDigest        string             `json:"inspector_digest"`
}

type Record struct {
	SchemaVersion            string           `json:"schema_version"`
	ContractVersion          string           `json:"contract_version"`
	Request                  Request          `json:"request"`
	IntentDigest             string           `json:"intent_digest"`
	IdempotencyDigest        string           `json:"idempotency_digest"`
	DecisionDigest           string           `json:"decision_digest"`
	RevocationDigest         string           `json:"revocation_digest"`
	Inspection               InspectionResult `json:"inspection"`
	AuditEventDigest         string           `json:"audit_event_digest"`
	PreviousProvenanceDigest string           `json:"previous_provenance_digest"`
	ProvenanceDigest         string           `json:"provenance_digest"`
	CreatedAt                time.Time        `json:"created_at"`
	Revision                 uint64           `json:"revision"`
}

type Result struct {
	Inspection       InspectionResult
	AuditEventDigest string
	ProvenanceDigest string
	Replayed         bool
}

type Authority interface {
	AuthorizeRetrieval(context.Context, AuthorizationRequest) (Decision, error)
}

type Inspector interface {
	Inspect(context.Context, InspectionRequest) (InspectionResult, error)
}

type ArtifactVerifier interface {
	VerifyArtifact(context.Context, domain.ArtifactRef) error
}

type Auditor interface {
	AppendAuditEvent(context.Context, tamperaudit.Event) error
}

type Store interface {
	Load(context.Context, domain.CaseRef, string, string) (Record, bool, error)
	Commit(context.Context, string, Record) (Record, bool, error)
}

type Clock interface{ Now() time.Time }
