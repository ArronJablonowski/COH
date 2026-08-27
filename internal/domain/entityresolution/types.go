// Package entityresolution creates case-local, evidence-linked analytical
// entity projections without receiving raw identifiers or evidence bytes.
package entityresolution

import "time"

const (
	ObservationSchemaVersion = "coh.entity-observation/v1"
	CandidateSchemaVersion   = "coh.entity-candidate/v1"
	EntitySchemaVersion      = "coh.entity-record/v1"
	DecisionSchemaVersion    = "coh.entity-decision/v1"
	HistorySchemaVersion     = "coh.entity-history/v1"
	CommandSchemaVersion     = "coh.entity-resolution-command/v1"
	OutcomeSchemaVersion     = "coh.entity-resolution-outcome/v1"
	ReceiptSchemaVersion     = "coh.entity-resolution-receipt/v1"
	ContractVersion          = "1.0.0"
	MethodVersion            = "1.0.0"
)

type Scope struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type IdentifierBinding struct {
	Role                  string `json:"role"`
	IdentifierType        string `json:"identifier_type"`
	Normalization         string `json:"normalization"`
	MatchDigest           string `json:"match_digest"`
	DerivationKeyRevision uint64 `json:"derivation_key_revision"`
}

type EvidenceBinding struct {
	EnvelopeID             string `json:"envelope_id"`
	EnvelopeDigest         string `json:"envelope_digest"`
	Classification         string `json:"classification"`
	SourceIdentityDigest   string `json:"source_identity_digest"`
	TransformationDigest   string `json:"transformation_digest"`
	ArtifactDigest         string `json:"artifact_digest"`
	RawManifestDigest      string `json:"raw_manifest_digest"`
	IngestReceiptDigest    string `json:"ingest_receipt_digest"`
	SourceProvenanceDigest string `json:"source_provenance_digest"`
	MappingManifestDigest  string `json:"mapping_manifest_digest"`
	MappingRevision        uint64 `json:"mapping_revision"`
	MappingOutcomeDigest   string `json:"mapping_outcome_digest"`
	RuleID                 string `json:"rule_id"`
	OutputField            string `json:"output_path"`
	OutputFieldDigest      string `json:"output_path_digest"`
	SourceFieldDigest      string `json:"source_field_digest"`
}

type Observation struct {
	SchemaVersion               string            `json:"schema_version"`
	ContractVersion             string            `json:"contract_version"`
	MethodVersion               string            `json:"method_version"`
	ObservationID               string            `json:"observation_id"`
	OperationID                 string            `json:"operation_id"`
	Scope                       Scope             `json:"scope"`
	Identifier                  IdentifierBinding `json:"identifier"`
	ConfidenceCeilingMillionths uint32            `json:"confidence_ceiling_millionths"`
	Evidence                    EvidenceBinding   `json:"evidence"`
	ObservedAt                  string            `json:"observed_at"`
	Validity                    string            `json:"validity"`
	SupersedesObservationDigest *string           `json:"supersedes_observation_digest"`
}

type ObservationRef struct {
	ObservationID     string `json:"observation_id"`
	ObservationDigest string `json:"observation_digest"`
}

type EvidenceLink struct {
	ObservationID           string `json:"observation_id"`
	ObservationDigest       string `json:"observation_digest"`
	EvidenceBindingDigest   string `json:"evidence_binding_digest"`
	SourceFamilyDigest      string `json:"source_family_digest"`
	IndependenceGroupDigest string `json:"independence_group_digest"`
}

type Counterevidence struct {
	CounterevidenceID string         `json:"counterevidence_id"`
	Reason            string         `json:"reason"`
	EvidenceLinks     []EvidenceLink `json:"evidence_links"`
	WeightMillionths  int32          `json:"weight_millionths"`
	BlocksMerge       bool           `json:"blocks_merge"`
	RecordDigest      string         `json:"record_digest"`
}

type ConfidenceComponent struct {
	ComponentID        string   `json:"component_id"`
	Kind               string   `json:"kind"`
	ValueMillionths    int32    `json:"value_millionths"`
	ObservationDigests []string `json:"observation_digests"`
	BasisDigest        string   `json:"basis_digest"`
}

type Confidence struct {
	Method               string                `json:"method"`
	MethodVersion        string                `json:"method_version"`
	Components           []ConfidenceComponent `json:"components"`
	SupportingEvidence   []EvidenceLink        `json:"supporting_evidence"`
	Counterevidence      []Counterevidence     `json:"counterevidence"`
	PreCeilingMillionths uint32                `json:"pre_ceiling_millionths"`
	CeilingMillionths    uint32                `json:"ceiling_millionths"`
	FinalMillionths      uint32                `json:"final_millionths"`
	Label                string                `json:"label"`
}

type ConfidenceAssessment struct {
	Observation   ObservationRef `json:"observation"`
	EvidenceLink  EvidenceLink   `json:"evidence_link"`
	SourceQuality string         `json:"source_quality"`
	Recency       string         `json:"recency"`
}

type EntityRef struct {
	EntityID     string `json:"entity_id"`
	Revision     uint64 `json:"revision"`
	RecordDigest string `json:"record_digest"`
}

type AliasProof struct {
	IdentifierType         string   `json:"identifier_type"`
	FromMatchDigest        string   `json:"from_match_digest"`
	FromKeyRevision        uint64   `json:"from_key_revision"`
	ToMatchDigest          string   `json:"to_match_digest"`
	ToKeyRevision          uint64   `json:"to_key_revision"`
	VerifierDecisionDigest string   `json:"verifier_decision_digest"`
	EvidenceLinkDigests    []string `json:"evidence_link_digests"`
	CreatedAt              string   `json:"created_at"`
}

type Partition struct {
	PartitionID           string                 `json:"partition_id"`
	OutputEntityID        string                 `json:"output_entity_id"`
	MemberObservations    []ObservationRef       `json:"member_observations"`
	AliasProofDigests     []string               `json:"alias_proof_digests"`
	Confidence            Confidence             `json:"confidence"`
	ConfidenceAssessments []ConfidenceAssessment `json:"confidence_assessments"`
}

type Candidate struct {
	SchemaVersion    string            `json:"schema_version"`
	ContractVersion  string            `json:"contract_version"`
	MethodVersion    string            `json:"method_version"`
	CandidateID      string            `json:"candidate_id"`
	OperationID      string            `json:"operation_id"`
	Scope            Scope             `json:"scope"`
	Identifier       IdentifierBinding `json:"identifier"`
	Observation      ObservationRef    `json:"observation"`
	MatchingEntities []EntityRef       `json:"matching_entities"`
	Result           string            `json:"result"`
	Confidence       Confidence        `json:"confidence"`
	CreatedAt        string            `json:"created_at"`
}

type Entity struct {
	SchemaVersion             string           `json:"schema_version"`
	ContractVersion           string           `json:"contract_version"`
	MethodVersion             string           `json:"method_version"`
	EntityID                  string           `json:"entity_id"`
	Revision                  uint64           `json:"revision"`
	Scope                     Scope            `json:"scope"`
	Status                    string           `json:"status"`
	Classification            string           `json:"classification"`
	MemberObservations        []ObservationRef `json:"member_observations"`
	AliasProofs               []AliasProof     `json:"alias_proofs"`
	Confidence                Confidence       `json:"confidence"`
	CreationDecisionDigest    string           `json:"creation_decision_digest"`
	HistoryHeadDigest         string           `json:"history_head_digest"`
	AuditDigest               string           `json:"audit_digest"`
	PreviousProvenanceDigests []string         `json:"previous_provenance_digests"`
	ProvenanceDigest          string           `json:"provenance_digest"`
	CreatedAt                 string           `json:"created_at"`
	UpdatedAt                 string           `json:"updated_at"`
}

type Operation string

const (
	Observe Operation = "observe"
	Resolve Operation = "resolve"
	Merge   Operation = "merge"
	Split   Operation = "split"
	Reject  Operation = "reject"
	Reindex Operation = "reindex"
)

type Decision struct {
	SchemaVersion               string            `json:"schema_version"`
	ContractVersion             string            `json:"contract_version"`
	MethodVersion               string            `json:"method_version"`
	DecisionID                  string            `json:"decision_id"`
	OperationID                 string            `json:"operation_id"`
	Operation                   Operation         `json:"operation"`
	Scope                       Scope             `json:"scope"`
	ActorID                     string            `json:"actor_id"`
	ActorRevision               uint64            `json:"actor_revision"`
	AuthorizationDecisionDigest *string           `json:"authorization_decision_digest"`
	ReversesHistoryDigest       *string           `json:"reverses_history_digest"`
	InputEntities               []EntityRef       `json:"input_entities"`
	OutputEntities              []EntityRef       `json:"output_entities"`
	Partitions                  []Partition       `json:"partitions"`
	SupportingEvidence          []EvidenceLink    `json:"supporting_evidence"`
	Counterevidence             []Counterevidence `json:"counterevidence"`
	Confidence                  Confidence        `json:"confidence"`
	Reason                      string            `json:"reason"`
	CreatedAt                   string            `json:"created_at"`
}

type History struct {
	SchemaVersion          string      `json:"schema_version"`
	ContractVersion        string      `json:"contract_version"`
	MethodVersion          string      `json:"method_version"`
	HistoryID              string      `json:"history_id"`
	Sequence               uint64      `json:"sequence"`
	Scope                  Scope       `json:"scope"`
	Operation              Operation   `json:"operation"`
	DecisionDigest         string      `json:"decision_digest"`
	InputEntities          []EntityRef `json:"input_entities"`
	OutputEntities         []EntityRef `json:"output_entities"`
	PreviousHistoryDigests []string    `json:"previous_history_digests"`
	ReversesHistoryDigest  *string     `json:"reverses_history_digest"`
	CreatedAt              string      `json:"created_at"`
}

type Command struct {
	SchemaVersion         string                 `json:"schema_version"`
	ContractVersion       string                 `json:"contract_version"`
	MethodVersion         string                 `json:"method_version"`
	OperationID           string                 `json:"operation_id"`
	IdempotencyKey        string                 `json:"idempotency_key"`
	Operation             Operation              `json:"operation"`
	Scope                 Scope                  `json:"scope"`
	ActorID               string                 `json:"actor_id"`
	ActorRevision         uint64                 `json:"actor_revision"`
	ReversesHistoryDigest *string                `json:"reverses_history_digest"`
	CandidateID           *string                `json:"candidate_id"`
	DecisionID            *string                `json:"decision_id"`
	HistoryID             *string                `json:"history_id"`
	HistorySequence       *uint64                `json:"history_sequence"`
	OutputEntityID        *string                `json:"output_entity_id"`
	Confidence            *Confidence            `json:"confidence"`
	ConfidenceAssessments []ConfidenceAssessment `json:"confidence_assessments"`
	Observation           *Observation           `json:"observation"`
	CandidateDigest       *string                `json:"candidate_digest"`
	InputEntities         []EntityRef            `json:"input_entities"`
	Partitions            []Partition            `json:"partitions"`
	SupportingEvidence    []EvidenceLink         `json:"supporting_evidence"`
	Counterevidence       []Counterevidence      `json:"counterevidence"`
	Reason                string                 `json:"reason"`
	RequestedAt           string                 `json:"requested_at"`
	Deadline              string                 `json:"deadline"`
}

type Status string

const (
	Observed              Status = "observed"
	Resolved              Status = "resolved"
	Merged                Status = "merged"
	SplitStatus           Status = "split"
	Rejected              Status = "rejected"
	Reindexed             Status = "reindexed"
	Denied                Status = "denied"
	Canceled              Status = "canceled"
	Timeout               Status = "timeout"
	DependencyUnavailable Status = "dependency_unavailable"
)

type Reason string

const (
	ObservedReason              Reason = "observed"
	ResolvedReason              Reason = "resolved"
	MergedReason                Reason = "merged"
	SplitReason                 Reason = "split"
	RejectedReason              Reason = "rejected"
	ReindexedReason             Reason = "reindexed"
	InvalidInput                Reason = "invalid_input"
	EvidenceBindingMismatch     Reason = "evidence_binding_mismatch"
	ScopeMismatch               Reason = "scope_mismatch"
	IdentifierIncompatible      Reason = "identifier_incompatible"
	CandidateAmbiguous          Reason = "candidate_ambiguous"
	ConfidenceInvalid           Reason = "confidence_invalid"
	CounterevidenceBlocked      Reason = "counterevidence_blocked"
	TransitionInvalid           Reason = "transition_invalid"
	RevisionConflict            Reason = "revision_conflict"
	AuthorizationDenied         Reason = "authorization_denied"
	IdempotencyConflict         Reason = "idempotency_conflict"
	ContextCanceled             Reason = "context_canceled"
	ContextDeadline             Reason = "context_deadline"
	DependencyUnavailableReason Reason = "dependency_unavailable"
)

type Outcome struct {
	SchemaVersion     string      `json:"schema_version"`
	ContractVersion   string      `json:"contract_version"`
	MethodVersion     string      `json:"method_version"`
	OperationID       string      `json:"operation_id"`
	CommandDigest     string      `json:"command_digest"`
	Status            Status      `json:"status"`
	ReasonCode        Reason      `json:"reason_code"`
	ObservationDigest *string     `json:"observation_digest"`
	CandidateDigest   *string     `json:"candidate_digest"`
	DecisionDigest    *string     `json:"decision_digest"`
	HistoryDigest     *string     `json:"history_digest"`
	Entities          []EntityRef `json:"entities"`
	CreatedAt         string      `json:"created_at"`
}

type Receipt struct {
	SchemaVersion            string  `json:"schema_version"`
	ContractVersion          string  `json:"contract_version"`
	MethodVersion            string  `json:"method_version"`
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

type CaseDecision struct {
	Verified       bool
	Current        bool
	CaseRevision   uint64
	Classification string
	DecisionDigest string
}

type EvidenceDecision struct {
	Verified       bool
	DecisionDigest string
}

type MatchRequest struct {
	Scope      Scope
	Identifier IdentifierBinding
	Evidence   EvidenceBinding
}

type MatchDecision struct {
	Verified       bool
	KeyRevision    uint64
	DecisionDigest string
}

type AuthorizationRequest struct {
	Operation     Operation
	OperationID   string
	Scope         Scope
	ActorID       string
	ActorRevision uint64
	CommandDigest string
	InputEntities []EntityRef
	Deadline      string
}

type AuthorizationDecision struct {
	Allowed          bool
	ActorRevision    uint64
	CaseRevision     uint64
	DecisionDigest   string
	RevocationDigest string
	ExpiresAt        string
}

type AuditRecord struct {
	OperationID, CommandDigest string
	Status                     Status
	Reason                     Reason
	Digest                     string
}

type ProvenanceRecord struct {
	OperationID, CommandDigest, OutcomeDigest, PreviousDigest, Digest string
}

type Commit struct {
	Command     Command
	Observation *Observation
	Candidate   *Candidate
	Decision    *Decision
	History     *History
	Entities    []Entity
	Outcome     Outcome
	Receipt     Receipt
	Audit       AuditRecord
	Provenance  ProvenanceRecord
}

type Clock interface{ Now() time.Time }
