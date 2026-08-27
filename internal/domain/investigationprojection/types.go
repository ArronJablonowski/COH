// Package investigationprojection builds deterministic, evidence-bound case
// views while preserving uncertainty and keeping authoritative stores external.
package investigationprojection

const (
	ContractVersion = "1.0.0"
	ReducerVersion  = "1.0.0"

	FactSchemaVersion       = "coh.investigation-fact/v1"
	ProjectionSchemaVersion = "coh.investigation-projection/v1"
	CheckpointSchemaVersion = "coh.projection-checkpoint/v1"
	WatermarkSchemaVersion  = "coh.projection-watermark/v1"
	QuerySchemaVersion      = "coh.projection-query/v1"
	CacheSchemaVersion      = "coh.projection-cache-entry/v1"

	MaximumFacts   = 4096
	MaximumOutputs = 4096
	MaximumBytes   = 1 << 20
)

type Kind string

const (
	Correlation Kind = "correlation"
	Hypothesis  Kind = "hypothesis"
	Timeline    Kind = "timeline"
)

type Scope struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type EntityRef struct {
	EntityID     string `json:"entity_id"`
	Revision     uint64 `json:"revision"`
	RecordDigest string `json:"record_digest"`
}

type TimeRef struct {
	TimeRecordDigest  string  `json:"time_record_digest"`
	ComparisonDigest  *string `json:"comparison_digest"`
	Precision         string  `json:"precision"`
	UncertaintyDigest string  `json:"uncertainty_digest"`
}

type Unknown struct {
	Code        string `json:"code"`
	BasisDigest string `json:"basis_digest"`
}

type Completeness struct {
	Status                  string   `json:"status"`
	QueriedSourceDigests    []string `json:"queried_source_digests"`
	CompletedSourceDigests  []string `json:"completed_source_digests"`
	GapDigests              []string `json:"gap_digests"`
	NegativeEvidenceDigests []string `json:"negative_evidence_digests"`
	ConflictDigests         []string `json:"conflict_digests"`
}

type Confidence struct {
	Method          string `json:"method"`
	MethodVersion   string `json:"method_version"`
	BasisDigest     string `json:"basis_digest"`
	ValueMillionths uint32 `json:"value_millionths"`
	Label           string `json:"label"`
}

type StateVersion struct {
	ReducerVersion               string `json:"reducer_version"`
	ProjectionSchemaVersion      string `json:"projection_schema_version"`
	NormalizedEventSchemaVersion string `json:"normalized_event_schema_version"`
	MappingContractVersion       string `json:"mapping_contract_version"`
	MappingManifestDigest        string `json:"mapping_manifest_digest"`
	MappingRevision              uint64 `json:"mapping_revision"`
	EntityContractVersion        string `json:"entity_contract_version"`
	EntityHeadDigest             string `json:"entity_head_digest"`
	TimeContractVersion          string `json:"time_contract_version"`
	TimeMethodVersion            string `json:"time_method_version"`
	AuthoritativeStateDigest     string `json:"authoritative_state_digest"`
}

type Watermark struct {
	Sequence                 uint64  `json:"sequence"`
	HeadFactDigest           *string `json:"head_fact_digest"`
	CommittedAt              string  `json:"committed_at"`
	AuthoritativeStateDigest string  `json:"authoritative_state_digest"`
}

type AuthoritativeBinding struct {
	CaseRevision                 uint64      `json:"case_revision"`
	CaseDigest                   string      `json:"case_digest"`
	ArtifactDigest               string      `json:"artifact_digest"`
	ManifestDigest               string      `json:"manifest_digest"`
	IngestReceiptDigest          string      `json:"ingest_receipt_digest"`
	CustodyHeadDigest            string      `json:"custody_head_digest"`
	AuditHeadDigest              string      `json:"audit_head_digest"`
	SourceProvenanceDigest       string      `json:"source_provenance_digest"`
	NormalizedEventDigest        string      `json:"normalized_event_digest"`
	NormalizedEventSchemaVersion string      `json:"normalized_event_schema_version"`
	MappingOutcomeDigest         string      `json:"mapping_outcome_digest"`
	MappingManifestDigest        string      `json:"mapping_manifest_digest"`
	MappingRevision              uint64      `json:"mapping_revision"`
	EntityRefs                   []EntityRef `json:"entity_refs"`
	TimeRefs                     []TimeRef   `json:"time_refs"`
	AuthoritativeStateDigest     string      `json:"authoritative_state_digest"`
}

type Fact struct {
	SchemaVersion             string               `json:"schema_version"`
	ContractVersion           string               `json:"contract_version"`
	ReducerVersion            string               `json:"reducer_version"`
	FactID                    string               `json:"fact_id"`
	Scope                     Scope                `json:"scope"`
	Sequence                  uint64               `json:"sequence"`
	PreviousFactDigest        *string              `json:"previous_fact_digest"`
	FactType                  string               `json:"fact_type"`
	SubjectID                 string               `json:"subject_id"`
	ClaimID                   *string              `json:"claim_id"`
	HypothesisID              *string              `json:"hypothesis_id"`
	HypothesisDisposition     *string              `json:"hypothesis_disposition"`
	TimeRelation              *string              `json:"time_relation"`
	OrderConfidenceMillionths *uint32              `json:"order_confidence_millionths"`
	DuplicateOf               *string              `json:"duplicate_of"`
	GapDigests                []string             `json:"gap_digests"`
	ConflictDigests           []string             `json:"conflict_digests"`
	SupportingEvidenceDigests []string             `json:"supporting_evidence_digests"`
	CounterevidenceDigests    []string             `json:"counterevidence_digests"`
	Unknowns                  []Unknown            `json:"unknowns"`
	EntityRefs                []EntityRef          `json:"entity_refs"`
	TimeRefs                  []TimeRef            `json:"time_refs"`
	Confidence                *Confidence          `json:"confidence"`
	Completeness              Completeness         `json:"completeness"`
	Binding                   AuthoritativeBinding `json:"binding"`
	PayloadDigest             string               `json:"payload_digest"`
	CommittedAt               string               `json:"committed_at"`
}

type Claim struct {
	ClaimID                   string       `json:"claim_id"`
	ClaimDigest               string       `json:"claim_digest"`
	SupportingEvidenceDigests []string     `json:"supporting_evidence_digests"`
	CounterevidenceDigests    []string     `json:"counterevidence_digests"`
	Unknowns                  []Unknown    `json:"unknowns"`
	EntityRefs                []EntityRef  `json:"entity_refs"`
	Confidence                Confidence   `json:"confidence"`
	Completeness              Completeness `json:"completeness"`
}

type HypothesisValue struct {
	HypothesisID              string       `json:"hypothesis_id"`
	ClaimIDs                  []string     `json:"claim_ids"`
	Disposition               string       `json:"disposition"`
	SupportingEvidenceDigests []string     `json:"supporting_evidence_digests"`
	CounterevidenceDigests    []string     `json:"counterevidence_digests"`
	Unknowns                  []Unknown    `json:"unknowns"`
	Confidence                Confidence   `json:"confidence"`
	Completeness              Completeness `json:"completeness"`
}

type TimelineEntry struct {
	EntryID                   string      `json:"entry_id"`
	FactSequence              uint64      `json:"fact_sequence"`
	ClaimIDs                  []string    `json:"claim_ids"`
	EntityRefs                []EntityRef `json:"entity_refs"`
	TimeRef                   TimeRef     `json:"time_ref"`
	RelationToPrevious        string      `json:"relation_to_previous"`
	OrderConfidenceMillionths uint32      `json:"order_confidence_millionths"`
	DuplicateOf               *string     `json:"duplicate_of"`
	GapDigests                []string    `json:"gap_digests"`
	ConflictDigests           []string    `json:"conflict_digests"`
	Unknowns                  []Unknown   `json:"unknowns"`
}

type Projection struct {
	SchemaVersion    string            `json:"schema_version"`
	ContractVersion  string            `json:"contract_version"`
	ReducerVersion   string            `json:"reducer_version"`
	ProjectionID     string            `json:"projection_id"`
	Scope            Scope             `json:"scope"`
	Kind             Kind              `json:"kind"`
	StateVersion     StateVersion      `json:"state_version"`
	Watermark        Watermark         `json:"watermark"`
	FactCount        uint64            `json:"fact_count"`
	FactSetDigest    string            `json:"fact_set_digest"`
	Claims           []Claim           `json:"claims"`
	Hypotheses       []HypothesisValue `json:"hypotheses"`
	Timeline         []TimelineEntry   `json:"timeline"`
	Completeness     Completeness      `json:"completeness"`
	AuditDigest      string            `json:"audit_digest"`
	ProvenanceDigest string            `json:"provenance_digest"`
	ProjectionDigest string            `json:"projection_digest"`
	CreatedAt        string            `json:"created_at"`
}

type Checkpoint struct {
	SchemaVersion            string       `json:"schema_version"`
	ContractVersion          string       `json:"contract_version"`
	CheckpointID             string       `json:"checkpoint_id"`
	Scope                    Scope        `json:"scope"`
	Kind                     Kind         `json:"kind"`
	StateVersion             StateVersion `json:"state_version"`
	Watermark                Watermark    `json:"watermark"`
	FactSetDigest            string       `json:"fact_set_digest"`
	ProjectionDigest         string       `json:"projection_digest"`
	PreviousCheckpointDigest *string      `json:"previous_checkpoint_digest"`
	AuditDigest              string       `json:"audit_digest"`
	ProvenanceDigest         string       `json:"provenance_digest"`
	CheckpointDigest         string       `json:"checkpoint_digest"`
	CreatedAt                string       `json:"created_at"`
}

type WatermarkRecord struct {
	SchemaVersion   string       `json:"schema_version"`
	ContractVersion string       `json:"contract_version"`
	Scope           Scope        `json:"scope"`
	StateVersion    StateVersion `json:"state_version"`
	Watermark       Watermark    `json:"watermark"`
}

type Query struct {
	SchemaVersion      string       `json:"schema_version"`
	ContractVersion    string       `json:"contract_version"`
	QueryID            string       `json:"query_id"`
	IdempotencyKey     string       `json:"idempotency_key"`
	Scope              Scope        `json:"scope"`
	Kind               Kind         `json:"kind"`
	Consistency        string       `json:"consistency"`
	RequestedWatermark *Watermark   `json:"requested_watermark"`
	StateVersion       StateVersion `json:"state_version"`
	MaxFacts           uint32       `json:"max_facts"`
	MaxOutputs         uint32       `json:"max_outputs"`
	RequestedAt        string       `json:"requested_at"`
	Deadline           string       `json:"deadline"`
	QueryDigest        string       `json:"query_digest"`
}

type CacheEntry struct {
	SchemaVersion    string       `json:"schema_version"`
	ContractVersion  string       `json:"contract_version"`
	CacheKey         string       `json:"cache_key"`
	QueryDigest      string       `json:"query_digest"`
	Scope            Scope        `json:"scope"`
	Kind             Kind         `json:"kind"`
	StateVersion     StateVersion `json:"state_version"`
	Watermark        Watermark    `json:"watermark"`
	CheckpointDigest string       `json:"checkpoint_digest"`
	ProjectionDigest string       `json:"projection_digest"`
	VerifiedAt       string       `json:"verified_at"`
}
