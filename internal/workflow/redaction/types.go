// Package redaction owns governed creation of immutable redacted derivatives.
package redaction

import (
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	CommandSchemaVersion       = "coh.redaction-command/v1"
	RuleSetSchemaVersion       = "coh.redaction-rule-set/v1"
	PlanSchemaVersion          = "coh.redaction-approved-plan/v1"
	MappingSchemaVersion       = "coh.redaction-mapping/v1"
	AuthorizationSchemaVersion = "coh.redaction-authorization/v1"
	DecisionSchemaVersion      = "coh.redaction-decision/v1"
	RecordSchemaVersion        = "coh.redaction-record/v1"
	ReceiptSchemaVersion       = "coh.redaction-receipt/v1"
	ContractVersion            = "1.0.0"
)

type ReplacementMode string

const (
	Remove ReplacementMode = "remove"
	Mask   ReplacementMode = "mask"
	Token  ReplacementMode = "token"
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
	ReasonSourceNotFound   DecisionReason = "source_not_found"
	ReasonSourceInvalid    DecisionReason = "source_invalid"
	ReasonRuleInvalid      DecisionReason = "rule_invalid"
	ReasonPlanInvalid      DecisionReason = "plan_invalid"
	ReasonApprovalRequired DecisionReason = "approval_required"
	ReasonApprovalInvalid  DecisionReason = "approval_invalid"
	ReasonRevoked          DecisionReason = "revoked"
	ReasonStaleActor       DecisionReason = "stale_actor"
	ReasonStaleCase        DecisionReason = "stale_case"
	ReasonStaleCustody     DecisionReason = "stale_custody"
	ReasonSourceDrift      DecisionReason = "source_drift"
	ReasonMappingInvalid   DecisionReason = "mapping_invalid"
	ReasonTransformInvalid DecisionReason = "transform_invalid"
	ReasonPublishFailed    DecisionReason = "publish_failed"
	ReasonCustodyFailed    DecisionReason = "custody_failed"
	ReasonChangedReplay    DecisionReason = "changed_replay"
)

type ProgressPhase string

const (
	PhasePlanned   ProgressPhase = "planned"
	PhasePublished ProgressPhase = "published"
	PhaseCustodied ProgressPhase = "custodied"
)

type EvidenceReference struct {
	Artifact                 domain.ArtifactRef
	Manifest                 domain.ArtifactRef
	ManifestProvenanceDigest string
	IngestionReceiptDigest   string
}

type CustodyHead struct {
	Case         domain.CaseRef
	Sequence     uint64
	ChainHash    string
	LastRecordAt *time.Time
}

type Command struct {
	SchemaVersion        string
	ContractVersion      string
	RequestID            string
	IdempotencyKey       string
	Case                 domain.CaseRef
	ActorID              string
	ActorRevision        uint64
	Source               EvidenceReference
	RuleDigest           string
	PlanDigest           string
	ReasonDigest         string
	OutputMediaType      string
	OutputClassification string
	KeyProfile           string
	KeyProfileDigest     string
	PolicyDigest         string
	ExpectedCaseRevision uint64
	ExpectedCustodyHead  CustodyHead
	Deadline             time.Time
}

type RuleSet struct {
	SchemaVersion        string
	ContractVersion      string
	RuleID               string
	Revision             uint64
	RuleDigest           string
	AllowedMediaTypes    []string
	PermittedModes       []ReplacementMode
	TokenDigest          *string
	MaximumSpans         uint16
	MaximumSelectedBytes int64
	MaximumOutputBytes   int64
	SignerKeyID          string
	SignerKeyRevision    uint64
	Signature            string
}

type PlanSpan struct {
	Ordinal             uint16
	SourceStart         int64
	SourceEnd           int64
	SourceSegmentDigest string
	ReplacementMode     ReplacementMode
	ExpectedOutputStart int64
	ExpectedOutputEnd   int64
}

type ApprovedPlan struct {
	SchemaVersion             string
	ContractVersion           string
	PlanID                    string
	Case                      domain.CaseRef
	Source                    EvidenceReference
	RuleID                    string
	RuleRevision              uint64
	RuleDigest                string
	ReasonDigest              string
	Spans                     []PlanSpan
	MappingPlanDigest         string
	OutputMediaType           string
	OutputClassification      string
	MaximumOutputBytes        int64
	ApprovalID                string
	ApprovalFingerprintDigest string
	ApprovalManifestDigest    string
	PolicyDecisionDigest      string
	PolicyDigest              string
	ValidFrom                 time.Time
	ValidUntil                time.Time
	PlanDigest                string
}

type MappingEntry struct {
	Ordinal             uint16
	SourceStart         int64
	SourceEnd           int64
	SourceSegmentDigest string
	OutputStart         int64
	OutputEnd           int64
	ReplacementMode     ReplacementMode
	ReplacementDigest   string
}

type Mapping struct {
	SchemaVersion             string
	ContractVersion           string
	MappingID                 string
	Case                      domain.CaseRef
	Source                    EvidenceReference
	DerivedArtifact           domain.ArtifactRef
	PlanDigest                string
	RuleDigest                string
	ReasonDigest              string
	ApprovalFingerprintDigest string
	Entries                   []MappingEntry
	CreatedAt                 time.Time
	PreviousProvenanceDigest  string
	ProvenanceDigest          string
	MappingDigest             string
}

type ApprovalUseRequest struct {
	Case                 domain.CaseRef
	ApprovalID           string
	FingerprintDigest    string
	ManifestDigest       string
	PolicyDecisionDigest string
	IntentDigest         string
	ActorID              string
	ActorRevision        uint64
	IdempotencyKey       string
	Deadline             time.Time
}

type ApprovalUseProof struct {
	ApprovalID           string
	FingerprintDigest    string
	ManifestDigest       string
	PolicyDecisionDigest string
	IntentDigest         string
	State                string
	Revision             uint64
	UseCount             uint64
	MaximumUseCount      uint64
	ValidFrom            time.Time
	ValidUntil           time.Time
	UseDigest            string
	UsedAt               time.Time
	ProofDigest          string
}

type CaseSnapshot struct {
	Case             domain.CaseRef
	State            string
	Classification   string
	Revision         uint64
	ProvenanceDigest string
}

type VerifiedSource struct {
	Reference            EvidenceReference
	SourceIdentityDigest string
	VerificationDigest   string
}

type AuthorizationRequest struct {
	SchemaVersion            string
	ContractVersion          string
	AuthorizationDigest      string
	IntentDigest             string
	Command                  Command
	Plan                     ApprovedPlan
	CaseState                string
	CaseClassification       string
	CaseRevision             uint64
	CaseProvenanceDigest     string
	SourceVerificationDigest string
	ApprovalUse              ApprovalUseProof
	CurrentCustodyHead       CustodyHead
}

type Decision struct {
	SchemaVersion             string
	ContractVersion           string
	DecisionID                string
	DecisionDigest            string
	AuthorizationDigest       string
	IntentDigest              string
	Case                      domain.CaseRef
	ActorID                   string
	ActorRevision             uint64
	SourceArtifactDigest      string
	PlanDigest                string
	ApprovalFingerprintDigest string
	PolicyDigest              string
	RevocationDigest          string
	ExpectedCaseRevision      uint64
	ExpectedCustodyHead       CustodyHead
	Outcome                   DecisionOutcome
	ReasonCode                DecisionReason
	IssuedAt                  time.Time
	ExpiresAt                 time.Time
	Revision                  uint64
}

type Record struct {
	SchemaVersion                 string
	ContractVersion               string
	RedactionID                   string
	Case                          domain.CaseRef
	Command                       Command
	IntentDigest                  string
	PlanDigest                    string
	DecisionDigest                string
	RevocationDigest              string
	ApprovalUseDigest             string
	SourceVerificationDigest      string
	Derived                       EvidenceReference
	DerivedIngestionReceiptDigest string
	MappingReference              EvidenceReference
	MappingDigest                 string
	MappingIngestionReceiptDigest string
	CustodyReceiptDigest          string
	AuditEventDigest              string
	CreatedAt                     time.Time
	PreviousProvenanceDigest      string
	ProvenanceDigest              string
	RecordDigest                  string
}

type Receipt struct {
	SchemaVersion        string
	ContractVersion      string
	RequestID            string
	Case                 domain.CaseRef
	IdempotencyDigest    string
	IntentDigest         string
	RedactionID          string
	RecordDigest         string
	Derived              EvidenceReference
	MappingReference     EvidenceReference
	MappingDigest        string
	CustodyReceiptDigest string
	AuditEventDigest     string
	ProvenanceDigest     string
	CreatedAt            time.Time
	ReceiptDigest        string
}

type Result struct {
	Receipt  Receipt
	Replayed bool
}

type DerivationRequest struct {
	Case     domain.CaseRef
	Source   EvidenceReference
	Verified VerifiedSource
	Rule     RuleSet
	Plan     ApprovedPlan
	Deadline time.Time
}

type Derivation struct {
	DerivedArtifact  domain.ArtifactRef
	Mapping          Mapping
	DerivationDigest string
}

type PublicationRole string

const (
	DerivedPublication PublicationRole = "derived"
	MappingPublication PublicationRole = "mapping"
)

type PublicationRequest struct {
	Role                 PublicationRole
	Case                 domain.CaseRef
	ExpectedArtifact     domain.ArtifactRef
	Parents              []EvidenceReference
	SourceIdentityDigest string
	RuleDigest           string
	PlanDigest           string
	PolicyDigest         string
	KeyProfileDigest     string
	Deadline             time.Time
}

type PublishedEvidence struct {
	Reference     EvidenceReference
	ReceiptDigest string
}

type CustodyRequest struct {
	Command        Command
	Derived        EvidenceReference
	MappingDigest  string
	ApprovalDigest string
	DecisionDigest string
	ExpectedHead   CustodyHead
	Deadline       time.Time
}

type CustodyProof struct {
	ReceiptDigest string
	RecordDigest  string
	ChainHash     string
	Sequence      uint64
	AuditDigest   string
}

type AuditProof struct {
	EventDigest string
	Sequence    uint64
	ChainHash   string
}

type Progress struct {
	Case              domain.CaseRef
	IdempotencyDigest string
	IntentDigest      string
	Phase             ProgressPhase
	Revision          uint64
	PlanDigest        string
	DecisionDigest    string
	ApprovalUseDigest string
	Derived           *PublishedEvidence
	Mapping           *PublishedEvidence
	MappingDigest     *string
	Custody           *CustodyProof
	UpdatedAt         time.Time
}
