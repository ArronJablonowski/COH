// Package modelsurface owns strict durable records used to construct and bind
// the exact surface visible to a model. These records describe provenance and
// never grant provider, tool, policy, approval, or action authority.
package modelsurface

const (
	ContractVersion   = "1.0.0"
	ProjectionVersion = "1.0.0"

	VocabularySchema = "coh.model-surface-event-vocabulary/v1"
	PayloadSchema    = "coh.model-surface-payload/v1"
	SourceSchema     = "coh.model-surface-source/v1"
	ProjectionSchema = "coh.model-surface-projection/v1"
	BindingSchema    = "coh.inference-surface-binding/v1"
	StreamSchema     = "coh.model-surface-stream/v1"
	CompactionSchema = "coh.model-surface-compaction-replacement/v1"
	TransitionSchema = "coh.model-surface-transition/v1"

	MaximumInputBytes   = 16 << 20
	MaximumSurfaceBytes = 64 << 20
	MaximumDepth        = 32
	MaximumItems        = 16384
	MaximumRevision     = uint64(1<<63 - 1)

	vocabularyDigestDomain  = "COH-MODEL-SURFACE-VOCABULARY-V1\x00"
	surfaceDigestDomain     = "COH-MODEL-SURFACE-BYTES-V1\x00"
	sourceDigestDomain      = "COH-MODEL-SURFACE-SOURCE-V1\x00"
	projectionDigestDomain  = "COH-MODEL-SURFACE-PROJECTION-V1\x00"
	bindingDigestDomain     = "COH-INFERENCE-SURFACE-BINDING-V1\x00"
	streamDigestDomain      = "COH-MODEL-SURFACE-STREAM-V1\x00"
	streamChunkDigestDomain = "COH-MODEL-SURFACE-CHUNK-V1\x00"
	assembledDigestDomain   = "COH-MODEL-SURFACE-ASSEMBLED-V1\x00"
	coverageDigestDomain    = "COH-MODEL-SURFACE-COVERAGE-V1\x00"
	replacementDigestDomain = "COH-MODEL-SURFACE-COMPACTION-V1\x00"
	transitionDigestDomain  = "COH-MODEL-SURFACE-TRANSITION-V1\x00"
)

type Scope struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
	TaskID         string `json:"task_id"`
}

type EventDefinition struct {
	EventType           string   `json:"event_type"`
	EventVersion        uint64   `json:"event_version"`
	EventClass          string   `json:"event_class"`
	Persistence         string   `json:"persistence"`
	ProducerModule      string   `json:"producer_module"`
	ConsumerModules     []string `json:"consumer_modules"`
	ProjectionRule      string   `json:"projection_rule"`
	PayloadSchemaDigest string   `json:"payload_schema_digest"`
}

type EventVocabulary struct {
	SchemaVersion      string            `json:"schema_version"`
	ContractVersion    string            `json:"contract_version"`
	VocabularyRevision uint64            `json:"vocabulary_revision"`
	Definitions        []EventDefinition `json:"definitions"`
	VocabularyDigest   string            `json:"vocabulary_digest,omitempty"`
}

type ContentBinding struct {
	Kind           string `json:"kind"`
	ContentID      string `json:"content_id"`
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Length         uint64 `json:"length"`
	Classification string `json:"classification"`
	Immutable      bool   `json:"immutable"`
}

type Source struct {
	SchemaVersion          string         `json:"schema_version"`
	ContractVersion        string         `json:"contract_version"`
	SourceRecordID         string         `json:"source_record_id"`
	EventType              string         `json:"event_type"`
	EventVersion           uint64         `json:"event_version"`
	EventClass             string         `json:"event_class"`
	ProjectionRule         string         `json:"projection_rule"`
	Scope                  Scope          `json:"scope"`
	RunID                  string         `json:"run_id"`
	RecordRevision         uint64         `json:"record_revision"`
	RecordDigest           string         `json:"record_digest"`
	Content                ContentBinding `json:"content"`
	Trust                  string         `json:"trust"`
	InstructionDisposition string         `json:"instruction_disposition"`
	OccurredAt             string         `json:"occurred_at"`
	Sequence               uint64         `json:"sequence"`
	Immutable              bool           `json:"immutable"`
	SourceDigest           string         `json:"source_digest,omitempty"`
}

type ProjectedItem struct {
	Ordinal                uint64 `json:"ordinal"`
	SurfaceKind            string `json:"surface_kind"`
	Role                   string `json:"role"`
	SourceRecordID         string `json:"source_record_id"`
	SourceRevision         uint64 `json:"source_revision"`
	SourceDigest           string `json:"source_digest"`
	ContentKind            string `json:"content_kind"`
	ContentID              string `json:"content_id"`
	ContentDigest          string `json:"content_digest"`
	RenderedDigest         string `json:"rendered_digest"`
	RenderedLength         uint64 `json:"rendered_length"`
	InstructionDisposition string `json:"instruction_disposition"`
}

type Projection struct {
	SchemaVersion          string          `json:"schema_version"`
	ContractVersion        string          `json:"contract_version"`
	ProjectionID           string          `json:"projection_id"`
	ProjectionVersion      string          `json:"projection_version"`
	Scope                  Scope           `json:"scope"`
	RunID                  string          `json:"run_id"`
	VocabularyDigest       string          `json:"vocabulary_digest"`
	CompositionDigest      string          `json:"composition_digest"`
	OrderedItems           []ProjectedItem `json:"ordered_items"`
	OrderedSourceRecordIDs []string        `json:"ordered_source_record_ids"`
	ArtifactDigests        []string        `json:"artifact_digests"`
	SurfaceDigest          string          `json:"surface_digest"`
	ProjectionDigest       string          `json:"projection_digest,omitempty"`
	CreatedAt              string          `json:"created_at"`
}

type InferenceBinding struct {
	SchemaVersion          string   `json:"schema_version"`
	ContractVersion        string   `json:"contract_version"`
	RequestID              string   `json:"request_id"`
	AttemptID              string   `json:"attempt_id"`
	Scope                  Scope    `json:"scope"`
	RunID                  string   `json:"run_id"`
	ActorID                string   `json:"actor_id"`
	ProviderID             string   `json:"provider_id"`
	ProjectionID           string   `json:"projection_id"`
	ProjectionVersion      string   `json:"projection_version"`
	ProjectionDigest       string   `json:"projection_digest"`
	OrderedSourceRecordIDs []string `json:"ordered_source_record_ids"`
	ArtifactDigests        []string `json:"artifact_digests"`
	VocabularyDigest       string   `json:"vocabulary_digest"`
	CompositionDigest      string   `json:"composition_digest"`
	SurfaceDigest          string   `json:"surface_digest"`
	AuthorizationDigest    string   `json:"authorization_digest"`
	PolicyDecisionDigest   string   `json:"policy_decision_digest"`
	ApprovalDecisionDigest string   `json:"approval_decision_digest"`
	AuditReservationDigest string   `json:"audit_reservation_digest"`
	BindingDigest          string   `json:"binding_digest,omitempty"`
	CreatedAt              string   `json:"created_at"`
	Deadline               string   `json:"deadline"`
}

type StreamEvent struct {
	SchemaVersion      string   `json:"schema_version"`
	ContractVersion    string   `json:"contract_version"`
	RequestID          string   `json:"request_id"`
	AttemptID          string   `json:"attempt_id"`
	BindingDigest      string   `json:"binding_digest"`
	ProjectionDigest   string   `json:"projection_digest"`
	InputSurfaceDigest string   `json:"input_surface_digest"`
	Sequence           uint64   `json:"sequence"`
	Kind               string   `json:"kind"`
	SourceRecordIDs    []string `json:"source_record_ids"`
	ChunkDigest        string   `json:"chunk_digest"`
	AssembledDigest    string   `json:"assembled_digest"`
	Outcome            string   `json:"outcome"`
	ObservedAt         string   `json:"observed_at"`
	EventDigest        string   `json:"event_digest,omitempty"`
}
