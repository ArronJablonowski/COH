// Package custody owns the case-scoped, append-only evidence custody boundary.
package custody

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

const (
	CommandSchemaVersion       = "coh.custody-command/v1"
	AuthorizationSchemaVersion = "coh.custody-authorization/v1"
	DecisionSchemaVersion      = "coh.custody-decision/v1"
	RecordSchemaVersion        = "coh.custody-record/v1"
	ReceiptSchemaVersion       = "coh.custody-receipt/v1"
	VerificationSchemaVersion  = "coh.custody-verification/v1"
	ContractVersion            = "1.0.0"
	GenesisHash                = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
)

type Operation string

const (
	Acquire     Operation = "acquire"
	Access      Operation = "access"
	Transform   Operation = "transform"
	Redact      Operation = "redact"
	Transfer    Operation = "transfer"
	Export      Operation = "export"
	PlaceHold   Operation = "place_hold"
	ReleaseHold Operation = "release_hold"
	Delete      Operation = "delete"
)

type Phase string

const (
	Authorized Phase = "authorized"
	Completed  Phase = "completed"
)

type DecisionOutcome string

const (
	Allow DecisionOutcome = "allow"
	Deny  DecisionOutcome = "deny"
)

type DecisionReason string

const (
	ReasonAuthorized       DecisionReason = "authorized"
	ReasonInvalidInput     DecisionReason = "invalid_input"
	ReasonCaseNotFound     DecisionReason = "case_not_found"
	ReasonCaseStateDenied  DecisionReason = "case_state_denied"
	ReasonArtifactNotFound DecisionReason = "artifact_not_found"
	ReasonArtifactInvalid  DecisionReason = "artifact_invalid"
	ReasonManifestInvalid  DecisionReason = "manifest_invalid"
	ReasonLineageInvalid   DecisionReason = "lineage_invalid"
	ReasonAuthorityDenied  DecisionReason = "authority_denied"
	ReasonApprovalRequired DecisionReason = "approval_required"
	ReasonApprovalInvalid  DecisionReason = "approval_invalid"
	ReasonRevoked          DecisionReason = "revoked"
	ReasonStaleActor       DecisionReason = "stale_actor"
	ReasonStaleCase        DecisionReason = "stale_case"
	ReasonStaleHead        DecisionReason = "stale_head"
	ReasonChangedReplay    DecisionReason = "changed_replay"
	ReasonRetentionActive  DecisionReason = "retention_active"
	ReasonLegalHoldActive  DecisionReason = "legal_hold_active"
)

type VerificationOutcome string

const (
	VerificationValid      VerificationOutcome = "valid"
	VerificationInvalid    VerificationOutcome = "invalid"
	VerificationIncomplete VerificationOutcome = "incomplete"
)

type VerificationReason string

const (
	VerifySuccess           VerificationReason = "verified"
	VerifyInvalidScope      VerificationReason = "invalid_scope"
	VerifyInvalidSequence   VerificationReason = "invalid_sequence"
	VerifyInvalidRecord     VerificationReason = "invalid_record"
	VerifyInvalidChain      VerificationReason = "invalid_chain"
	VerifyInvalidReceipt    VerificationReason = "invalid_receipt"
	VerifyInvalidArtifact   VerificationReason = "invalid_artifact"
	VerifyInvalidManifest   VerificationReason = "invalid_manifest"
	VerifyBrokenLineage     VerificationReason = "broken_lineage"
	VerifyInvalidOperation  VerificationReason = "invalid_operation"
	VerifyMissingAudit      VerificationReason = "missing_audit"
	VerifyInvalidAudit      VerificationReason = "invalid_audit"
	VerifyInvalidCheckpoint VerificationReason = "invalid_checkpoint"
	VerifyTruncatedInterval VerificationReason = "truncated_interval"
)

// EvidenceReference carries immutable public facts only. Manifest plaintext
// and evidence bytes remain inside the encrypted evidence resolver.
type EvidenceReference struct {
	Artifact                 domain.ArtifactRef
	Manifest                 domain.ArtifactRef
	ManifestProvenanceDigest string
	IngestionReceiptDigest   string
}

type Head struct {
	Case         domain.CaseRef
	Sequence     uint64
	ChainHash    string
	LastRecordAt *time.Time
}

type Command struct {
	SchemaVersion            string
	ContractVersion          string
	RequestID                string
	IdempotencyKey           string
	Operation                Operation
	Phase                    Phase
	Case                     domain.CaseRef
	ActorID                  string
	ActorRevision            uint64
	Subject                  EvidenceReference
	Parents                  []EvidenceReference
	SourceIdentityDigest     *string
	PurposeDigest            *string
	DestinationDigest        *string
	RecipientDigest          *string
	TransformationDigest     *string
	RuleDigest               *string
	ReasonDigest             *string
	MappingDigest            *string
	ApprovalDigest           *string
	ExternalReceiptDigest    *string
	LifecycleReceiptDigest   *string
	PriorAuthorizationDigest *string
	ArtifactSetDigest        *string
	PolicyDigest             string
	ExpectedCaseRevision     uint64
	ExpectedHead             Head
	Deadline                 time.Time
}

type CaseSnapshot struct {
	Case                  domain.CaseRef
	State                 string
	Classification        string
	Revision              uint64
	RetentionPolicyDigest string
	RetainUntil           time.Time
	LegalHold             bool
	ProvenanceDigest      string
}

type LifecycleReceiptSnapshot struct {
	Case             domain.CaseRef
	Operation        string
	Revision         uint64
	ReceiptDigest    string
	ProvenanceDigest string
	LegalHold        bool
}

type VerifiedEvidence struct {
	Reference             EvidenceReference
	SourceIdentityDigest  string
	ParentArtifacts       []domain.ArtifactRef
	ParentManifestDigests []string
	VerificationDigest    string
}

type AuthorizationRequest struct {
	SchemaVersion          string
	ContractVersion        string
	AuthorizationDigest    string
	IntentDigest           string
	Command                Command
	CaseState              string
	CaseClassification     string
	CaseRevision           uint64
	RetentionPolicyDigest  string
	RetainUntil            time.Time
	LegalHold              bool
	CaseProvenanceDigest   string
	EvidenceVerifiedDigest string
	CurrentHead            Head
}

type Decision struct {
	SchemaVersion        string
	ContractVersion      string
	DecisionID           string
	DecisionDigest       string
	AuthorizationDigest  string
	IntentDigest         string
	Operation            Operation
	Phase                Phase
	Case                 domain.CaseRef
	ActorID              string
	ActorRevision        uint64
	ExpectedCaseRevision uint64
	ExpectedHead         Head
	PolicyDigest         string
	RevocationDigest     string
	Outcome              DecisionOutcome
	ReasonCode           DecisionReason
	IssuedAt             time.Time
	ExpiresAt            time.Time
	Revision             uint64
}

type Record struct {
	SchemaVersion            string
	ContractVersion          string
	CustodyID                string
	Case                     domain.CaseRef
	Sequence                 uint64
	PreviousChainHash        string
	Command                  Command
	IntentDigest             string
	AuthorizationDigest      string
	DecisionDigest           string
	RevocationDigest         string
	EvidenceVerifiedDigest   string
	PreviousProvenanceDigest *string
	ProvenanceDigest         string
	AuditEventDigest         string
	OccurredAt               time.Time
	RecordDigest             string
	ChainHash                string
}

type Receipt struct {
	SchemaVersion     string
	ContractVersion   string
	RequestID         string
	Case              domain.CaseRef
	IdempotencyDigest string
	IntentDigest      string
	DecisionDigest    string
	CustodyID         string
	Sequence          uint64
	RecordDigest      string
	ChainHash         string
	AuditEventDigest  string
	ProvenanceDigest  string
	CreatedAt         time.Time
	ReceiptDigest     string
}

type AuditProof struct {
	EventDigest      string
	Sequence         uint64
	ChainHash        string
	CheckpointID     *string
	CheckpointDigest *string
}

type Result struct {
	Receipt  Receipt
	Audit    AuditProof
	Replayed bool
}

type VerificationReport struct {
	SchemaVersion         string
	ContractVersion       string
	Case                  domain.CaseRef
	FromSequence          uint64
	ToSequence            uint64
	HeadChainHash         string
	AuditCheckpointID     *string
	AuditCheckpointDigest *string
	Outcome               VerificationOutcome
	ReasonCode            VerificationReason
	VerifiedAt            time.Time
	ReportDigest          string
}

type Authority interface {
	AuthorizeCustody(context.Context, AuthorizationRequest) (Decision, error)
}

type CaseStore interface {
	LoadCase(context.Context, domain.CaseRef) (CaseSnapshot, bool, error)
	ResolveLifecycleReceipt(context.Context, domain.CaseRef, string) (LifecycleReceiptSnapshot, bool, error)
}

type EvidenceResolver interface {
	ResolveEvidence(context.Context, domain.CaseRef, EvidenceReference) (VerifiedEvidence, error)
}

type Ledger interface {
	LoadHead(context.Context, domain.CaseRef) (Head, error)
	Recover(context.Context, domain.CaseRef, string) (Receipt, bool, error)
	ResolveReceipt(context.Context, domain.CaseRef, string) (Receipt, bool, error)
	Append(context.Context, string, string, Head, Record, Receipt) (Receipt, bool, error)
	Read(context.Context, domain.CaseRef, uint64, uint16) ([]Record, error)
}

type Auditor interface {
	AppendCustodyEvent(context.Context, tamperaudit.Event) (AuditProof, error)
	VerifyCustodyEvent(context.Context, domain.CaseRef, string, string) (AuditProof, error)
}

type Clock interface{ Now() time.Time }
