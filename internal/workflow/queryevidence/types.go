package queryevidence

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/queryruntime"
)

const (
	ContractVersion     = "1.0.0"
	RecordSchemaVersion = "coh.query-evidence-record/v1"
	AuditSchemaVersion  = "coh.query-evidence-audit/v1"
	MaximumAppendWait   = 5 * time.Second
	MaximumAuditWait    = 5 * time.Second
)

type ArtifactBinding struct {
	Artifact                 ArtifactRef `json:"artifact"`
	Manifest                 ArtifactRef `json:"manifest"`
	ManifestProvenanceDigest string      `json:"manifest_provenance_digest"`
	IngestionReceiptDigest   string      `json:"ingestion_receipt_digest"`
}

type ArtifactRef struct {
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Classification string `json:"classification"`
	Length         int64  `json:"length"`
}

type CaseBinding struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
}

type StreamRef struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
	QueryID        string `json:"query_id"`
	AttemptID      string `json:"attempt_id"`
}

type Statistics struct {
	RowsScanned     uint64 `json:"rows_scanned"`
	RowsReturned    uint64 `json:"rows_returned"`
	BytesReturned   uint64 `json:"bytes_returned"`
	DurationMillis  uint64 `json:"duration_millis"`
	PagesReturned   uint32 `json:"pages_returned"`
	SlicesCompleted uint32 `json:"slices_completed"`
	CostMillionths  uint64 `json:"cost_millionths"`
}

type Record struct {
	SchemaVersion             string           `json:"schema_version"`
	ContractVersion           string           `json:"contract_version"`
	RecordDigest              string           `json:"record_digest"`
	ProvenanceDigest          string           `json:"provenance_digest"`
	PreviousProvenanceDigest  string           `json:"previous_provenance_digest,omitempty"`
	TransitionID              string           `json:"transition_id"`
	Revision                  uint64           `json:"revision"`
	Stream                    StreamRef        `json:"stream"`
	Case                      CaseBinding      `json:"case"`
	ActorID                   string           `json:"actor_id"`
	SourceID                  string           `json:"source_id"`
	QueryDigest               string           `json:"query_digest"`
	BoundsDecisionDigest      string           `json:"bounds_decision_digest"`
	ExecutionDigest           string           `json:"execution_digest"`
	ValidatorVersion          string           `json:"validator_version"`
	ValidatorProvenanceDigest string           `json:"validator_provenance_digest"`
	IntervalStart             string           `json:"interval_start"`
	IntervalEnd               string           `json:"interval_end"`
	ResourceScopeDigest       string           `json:"resource_scope_digest"`
	NativeQuery               ArtifactBinding  `json:"native_query"`
	Event                     string           `json:"event"`
	RuntimeSessionRevision    uint64           `json:"runtime_session_revision"`
	RuntimeSessionDigest      string           `json:"runtime_session_digest"`
	Result                    *ArtifactBinding `json:"result,omitempty"`
	ResultDigest              string           `json:"result_digest,omitempty"`
	Completeness              string           `json:"completeness"`
	ReasonCode                string           `json:"reason_code"`
	Statistics                Statistics       `json:"statistics"`
	CancellationIntentDigest  string           `json:"cancellation_intent_digest,omitempty"`
	CancellationOutcomeDigest string           `json:"cancellation_outcome_digest,omitempty"`
	OccurredAt                string           `json:"occurred_at"`
}

type StartCommand struct {
	RequestID                 string
	IdempotencyKey            string
	Case                      domain.CaseRef
	ActorID                   string
	ActorRevision             uint64
	SourceID                  string
	QueryDigest               string
	BoundsDecisionDigest      string
	ExecutionDigest           string
	ValidatorVersion          string
	ValidatorProvenanceDigest string
	IntervalStart             string
	IntervalEnd               string
	ResourceScopeDigest       string
	NativeQueryDigest         string
	NativeQueryLength         int64
	NativeQueryMediaType      string
	Classification            string
	PolicyDigest              string
	RuntimeSession            queryruntime.Session
	Deadline                  time.Time
}

type TransitionCommand struct {
	IdempotencyKey            string
	Event                     string
	RuntimeSession            queryruntime.Session
	Result                    *ArtifactBinding
	ResultDigest              string
	Completeness              string
	ReasonCode                string
	CancellationIntentDigest  string
	CancellationOutcomeDigest string
	Deadline                  time.Time
}

type ArtifactRequest struct {
	RequestID      string
	IdempotencyKey string
	Case           domain.CaseRef
	ActorID        string
	ActorRevision  uint64
	SourceID       string
	QueryDigest    string
	ExpectedDigest string
	ExpectedLength int64
	MediaType      string
	Classification string
	PolicyDigest   string
	CollectedAt    time.Time
	Deadline       time.Time
}

// Source is cancellation-aware and forward-only. It deliberately has no seek
// or replay method, so native text cannot be recovered from this component.
type Source interface {
	ReadContext(context.Context, []byte) (int, error)
}

type NativeQueryIngestor interface {
	IngestNativeQuery(context.Context, ArtifactRequest, Source) (ArtifactBinding, error)
}

type ExpectedHead struct {
	Revision         uint64
	ProvenanceDigest string
}

type EvidenceStore interface {
	LoadHead(context.Context, StreamRef) (Record, bool, error)
	Recover(context.Context, StreamRef, string) (Record, bool, error)
	Append(context.Context, ExpectedHead, string, string, Record) (Record, bool, error)
}

type AuditEvent struct {
	SchemaVersion    string    `json:"schema_version"`
	ContractVersion  string    `json:"contract_version"`
	EventDigest      string    `json:"event_digest"`
	TransitionID     string    `json:"transition_id"`
	RecordDigest     string    `json:"record_digest"`
	ProvenanceDigest string    `json:"provenance_digest"`
	Stream           StreamRef `json:"stream"`
	Revision         uint64    `json:"revision"`
	Event            string    `json:"event"`
	Outcome          string    `json:"outcome"`
	OccurredAt       string    `json:"occurred_at"`
}

type Auditor interface {
	AppendQueryEvidence(context.Context, AuditEvent) error
}
type Clock interface{ Now() time.Time }

type Result struct {
	Record   Record
	Replayed bool
}
