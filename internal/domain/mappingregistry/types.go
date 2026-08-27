// Package mappingregistry verifies and applies signed, source-specific,
// data-only normalization mappings without exposing evidence or authority.
package mappingregistry

import (
	"encoding/json"
	"time"
)

const (
	SignedSchemaVersion   = "coh.signed-normalization-mapping/v1"
	ManifestSchemaVersion = "coh.normalization-mapping/v1"
	CommandSchemaVersion  = "coh.mapping-registry-command/v1"
	OutcomeSchemaVersion  = "coh.mapping-registry-outcome/v1"
	ReceiptSchemaVersion  = "coh.mapping-registry-receipt/v1"
	ContractVersion       = "1.0.0"
	TargetManifestDigest  = "sha256:82b23c1229c4bb1dbdc047859614d8da924d5bd3e5bdf9efba62b31a397408c1"
	OCSFVersion           = "1.9.0"
	OCSFCommit            = "856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba"
	ECSVersion            = "9.5.0"
	ECSCommit             = "401807e0547301525acd28c4fb667203fec66d59"
	MaximumInputBytes     = 1 << 20
)

type Case struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type SourceBinding struct {
	EnvelopeID             string `json:"envelope_id"`
	EnvelopeDigest         string `json:"envelope_digest"`
	ArtifactDigest         string `json:"artifact_digest"`
	ManifestDigest         string `json:"manifest_digest"`
	IngestReceiptDigest    string `json:"ingest_receipt_digest"`
	SourceProvenanceDigest string `json:"source_provenance_digest"`
	OriginalFieldsDigest   string `json:"original_fields_digest"`
}

type SourceMatcher struct {
	SourceKind              string  `json:"source_kind"`
	Product                 string  `json:"product"`
	ProductDigest           string  `json:"product_digest"`
	SourceSchema            string  `json:"source_schema"`
	SourceSchemaVersion     string  `json:"source_schema_version"`
	SourceSchemaDigest      string  `json:"source_schema_digest"`
	CollectionMethod        string  `json:"collection_method"`
	CollectionMethodVersion string  `json:"collection_method_version"`
	SourceIdentityDigest    *string `json:"source_identity_digest"`
}

type Compatibility struct {
	TargetManifestDigest     string `json:"target_manifest_digest"`
	NormalizedEnvelopeSchema string `json:"normalized_envelope_schema"`
	OCSFVersion              string `json:"ocsf_version"`
	OCSFCommit               string `json:"ocsf_commit"`
	ECSVersion               string `json:"ecs_version"`
	ECSCommit                string `json:"ecs_commit"`
}

type Operation string

const (
	Copy               Operation = "copy"
	Constant           Operation = "constant"
	Enum               Operation = "enum"
	ToInteger          Operation = "to_integer"
	ToString           Operation = "to_string"
	TimestampReference Operation = "timestamp_reference"
)

type ValueType string

const (
	String        ValueType = "string"
	Integer       ValueType = "integer"
	Boolean       ValueType = "boolean"
	Null          ValueType = "null"
	TimestampText ValueType = "timestamp_text"
)

type EnumEntry struct {
	Source json.RawMessage `json:"source"`
	Target json.RawMessage `json:"target"`
}

type IntegerRange struct {
	Minimum int64 `json:"minimum"`
	Maximum int64 `json:"maximum"`
}

type EntityHint struct {
	Role                        string `json:"role"`
	IdentifierType              string `json:"identifier_type"`
	Normalization               string `json:"normalization"`
	ConfidenceCeilingMillionths uint32 `json:"confidence_ceiling_millionths"`
}

type Rule struct {
	RuleID          string          `json:"rule_id"`
	Sequence        uint16          `json:"sequence"`
	Operation       Operation       `json:"operation"`
	InputPath       *string         `json:"input_path"`
	OutputNamespace string          `json:"output_namespace"`
	OutputPath      string          `json:"output_path"`
	InputType       ValueType       `json:"input_type"`
	OutputType      ValueType       `json:"output_type"`
	Required        bool            `json:"required"`
	ConstantValue   json.RawMessage `json:"constant_value"`
	EnumTable       []EnumEntry     `json:"enum_table"`
	IntegerRange    *IntegerRange   `json:"integer_range"`
	Reversibility   string          `json:"reversibility"`
	LossState       string          `json:"loss_state"`
	LossReason      string          `json:"loss_reason"`
	EntityHint      *EntityHint     `json:"entity_hint"`
}

type IgnoredField struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type Limits struct {
	MaxRules        uint16 `json:"max_rules"`
	MaxInputLeaves  uint16 `json:"max_input_leaves"`
	MaxOutputLeaves uint16 `json:"max_output_leaves"`
	MaxValueBytes   uint32 `json:"max_value_bytes"`
	MaxDepth        uint8  `json:"max_depth"`
}

type RevocationBinding struct {
	ListID          string `json:"list_id"`
	ListDigest      string `json:"list_digest"`
	MinimumRevision uint64 `json:"minimum_revision"`
}

type Manifest struct {
	SchemaVersion     string            `json:"schema_version"`
	ContractVersion   string            `json:"contract_version"`
	MappingID         string            `json:"mapping_id"`
	Name              string            `json:"name"`
	Version           string            `json:"version"`
	Revision          uint64            `json:"revision"`
	PredecessorDigest *string           `json:"predecessor_digest"`
	Source            SourceMatcher     `json:"source"`
	Compatibility     Compatibility     `json:"compatibility"`
	Rules             []Rule            `json:"rules"`
	IgnoredFields     []IgnoredField    `json:"ignored_fields"`
	UnmappedPolicy    string            `json:"unmapped_policy"`
	Limits            Limits            `json:"limits"`
	IssuerID          string            `json:"issuer_id"`
	ReviewDigest      string            `json:"review_digest"`
	CreatedAt         string            `json:"created_at"`
	NotBefore         string            `json:"not_before"`
	NotAfter          string            `json:"not_after"`
	Revocation        RevocationBinding `json:"revocation"`
}

type SignedMapping struct {
	SchemaVersion        string   `json:"schema_version"`
	ContractVersion      string   `json:"contract_version"`
	Manifest             Manifest `json:"manifest"`
	ManifestDigest       string   `json:"manifest_digest"`
	PublisherID          string   `json:"publisher_id"`
	PublisherKeyID       string   `json:"publisher_key_id"`
	PublisherKeyRevision uint64   `json:"publisher_key_revision"`
	SignatureAlgorithm   string   `json:"signature_algorithm"`
	Signature            string   `json:"signature"`
}

type RegistryOperation string

const (
	Register RegistryOperation = "register"
	Promote  RegistryOperation = "promote"
	Rollback RegistryOperation = "rollback"
	Revoke   RegistryOperation = "revoke"
	Apply    RegistryOperation = "apply"
)

type Command struct {
	SchemaVersion            string            `json:"schema_version"`
	ContractVersion          string            `json:"contract_version"`
	OperationID              string            `json:"operation_id"`
	IdempotencyKey           string            `json:"idempotency_key"`
	Operation                RegistryOperation `json:"operation"`
	Case                     Case              `json:"case"`
	SourceBinding            SourceBinding     `json:"source_binding"`
	Source                   SourceMatcher     `json:"source"`
	MappingDigest            string            `json:"mapping_digest"`
	SignedMapping            *SignedMapping    `json:"signed_mapping"`
	ExpectedRegistryRevision uint64            `json:"expected_registry_revision"`
	RequestedAt              string            `json:"requested_at"`
	Deadline                 string            `json:"deadline"`
}

type Status string

const (
	Registered            Status = "registered"
	Promoted              Status = "promoted"
	RolledBack            Status = "rolled_back"
	Revoked               Status = "revoked"
	Applied               Status = "applied"
	Denied                Status = "denied"
	Canceled              Status = "canceled"
	Timeout               Status = "timeout"
	DependencyUnavailable Status = "dependency_unavailable"
)

type Reason string

const (
	ManifestInvalid             Reason = "manifest_invalid"
	ManifestDigestMismatch      Reason = "manifest_digest_mismatch"
	SignatureInvalid            Reason = "signature_invalid"
	PublisherUntrusted          Reason = "publisher_untrusted"
	ManifestNotYetValid         Reason = "manifest_not_yet_valid"
	ManifestExpired             Reason = "manifest_expired"
	ManifestRevoked             Reason = "manifest_revoked"
	RevocationStale             Reason = "revocation_stale"
	SourceMismatch              Reason = "source_mismatch"
	MappingNotFound             Reason = "mapping_not_found"
	MappingAmbiguous            Reason = "mapping_ambiguous"
	TargetIncompatible          Reason = "target_incompatible"
	MappingDowngrade            Reason = "mapping_downgrade"
	RuleInvalid                 Reason = "rule_invalid"
	OutputCollision             Reason = "output_collision"
	TypeMismatch                Reason = "type_mismatch"
	ConversionOverflow          Reason = "conversion_overflow"
	UnmappedFieldDenied         Reason = "unmapped_field_denied"
	CoverageInvalid             Reason = "coverage_invalid"
	ReverseValidationFailed     Reason = "reverse_validation_failed"
	EvidenceBindingMismatch     Reason = "evidence_binding_mismatch"
	IdempotencyConflict         Reason = "idempotency_conflict"
	ContextCanceled             Reason = "context_canceled"
	ContextDeadline             Reason = "context_deadline"
	DependencyUnavailableReason Reason = "dependency_unavailable"
)

type EmittedEntityHint struct {
	RuleID                      string `json:"rule_id"`
	OutputPath                  string `json:"output_path"`
	SourceFieldDigest           string `json:"source_field_digest"`
	Role                        string `json:"role"`
	IdentifierType              string `json:"identifier_type"`
	Normalization               string `json:"normalization"`
	ConfidenceCeilingMillionths uint32 `json:"confidence_ceiling_millionths"`
}

type ReverseResult struct {
	RuleID           string `json:"rule_id"`
	SourcePathDigest string `json:"source_path_digest"`
	OutputPathDigest string `json:"output_path_digest"`
	Result           string `json:"result"`
}

type Outcome struct {
	SchemaVersion            string              `json:"schema_version"`
	ContractVersion          string              `json:"contract_version"`
	OperationID              string              `json:"operation_id"`
	CommandDigest            string              `json:"command_digest"`
	MappingDigest            string              `json:"mapping_digest"`
	RegistryRevision         uint64              `json:"registry_revision"`
	Status                   Status              `json:"status"`
	ReasonCode               Reason              `json:"reason_code"`
	NormalizedEnvelopeDigest *string             `json:"normalized_envelope_digest"`
	Coverage                 string              `json:"coverage"`
	AppliedRules             []string            `json:"applied_rules"`
	UnmappedPaths            []string            `json:"unmapped_paths"`
	LossyPaths               []string            `json:"lossy_paths"`
	EntityHints              []EmittedEntityHint `json:"entity_hints"`
	ReverseResults           []ReverseResult     `json:"reverse_results"`
	CreatedAt                string              `json:"created_at"`
}

type Receipt struct {
	SchemaVersion            string  `json:"schema_version"`
	ContractVersion          string  `json:"contract_version"`
	OperationID              string  `json:"operation_id"`
	IdempotencyKey           string  `json:"idempotency_key"`
	CommandDigest            string  `json:"command_digest"`
	OutcomeDigest            string  `json:"outcome_digest"`
	Status                   Status  `json:"status"`
	ReasonCode               Reason  `json:"reason_code"`
	AuditDigest              string  `json:"audit_digest"`
	PreviousProvenanceDigest *string `json:"previous_provenance_digest"`
	ProvenanceDigest         string  `json:"provenance_digest"`
	CreatedAt                string  `json:"created_at"`
	UpdatedAt                string  `json:"updated_at"`
}

type RegistrySnapshot struct {
	Source                    SourceMatcher
	Revision                  uint64
	CurrentManifestDigest     string
	PredecessorManifestDigest string
	Revocation                RevocationBinding
}

type SignatureRequest struct {
	ManifestDigest string
	PublisherID    string
	KeyID          string
	KeyRevision    uint64
	Algorithm      string
	Signature      string
	Domain         string
	Purpose        string
	NotBefore      string
	NotAfter       string
	Revocation     RevocationBinding
}

type SignatureDecision struct {
	Verified      bool
	Revoked       bool
	TrustRevision uint64
	Revocation    RevocationBinding
}

type AuditRecord struct {
	OperationID, CommandDigest string
	Status                     Status
	Reason                     Reason
	Digest                     string
}
type ProvenanceRecord struct{ OperationID, CommandDigest, OutcomeDigest, PreviousDigest, Digest string }
type Commit struct {
	Command    Command
	Outcome    Outcome
	Receipt    Receipt
	Audit      AuditRecord
	Provenance ProvenanceRecord
}
type Clock interface{ Now() time.Time }
