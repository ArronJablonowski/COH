// Package contextcompact replaces large workflow context with a separately
// stored summary reference without discarding evidence semantics.
package contextcompact

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	SchemaVersion   = "coh.context-compaction/v1"
	ContractVersion = "1.0.0"
	MaximumSources  = 512
)

type TrustLabel string

const UntrustedEvidence TrustLabel = "untrusted_evidence"

type TimePrecision string

const (
	PrecisionNanosecond  TimePrecision = "nanosecond"
	PrecisionMicrosecond TimePrecision = "microsecond"
	PrecisionMillisecond TimePrecision = "millisecond"
	PrecisionSecond      TimePrecision = "second"
	PrecisionMinute      TimePrecision = "minute"
	PrecisionHour        TimePrecision = "hour"
	PrecisionDay         TimePrecision = "day"
	PrecisionUnknown     TimePrecision = "unknown"
)

type OrderConfidence string

const (
	OrderStrict  OrderConfidence = "strict"
	OrderOverlap OrderConfidence = "overlap"
	OrderUnknown OrderConfidence = "unknown"
)

type ResultState string

const (
	ResultObserved    ResultState = "observed"
	ResultNegative    ResultState = "negative"
	ResultGap         ResultState = "gap"
	ResultConflicting ResultState = "conflicting"
	ResultError       ResultState = "error"
)

type Completeness string

const (
	Complete          Completeness = "complete"
	Partial           Completeness = "partial"
	Truncated         Completeness = "truncated"
	SourceUnavailable Completeness = "unavailable"
	Unknown           Completeness = "unknown"
)

type Uncertainty string

const (
	UncertaintyNone        Uncertainty = "none"
	UncertaintyBounded     Uncertainty = "bounded"
	UncertaintyClock       Uncertainty = "clock"
	UncertaintyConflicting Uncertainty = "conflicting"
	UncertaintyUnknown     Uncertainty = "unknown"
)

// Source is a data-only description. It never embeds evidence content.
type Source struct {
	Sequence                    uint32          `json:"sequence"`
	EvidenceID                  string          `json:"evidence_id"`
	EvidenceDigest              string          `json:"evidence_digest"`
	Trust                       TrustLabel      `json:"trust"`
	SourceTime                  string          `json:"source_time"`
	NormalizedTime              string          `json:"normalized_time"`
	OriginalTimezone            string          `json:"original_timezone"`
	Precision                   TimePrecision   `json:"precision"`
	ClockUncertaintyNanoseconds uint64          `json:"clock_uncertainty_nanoseconds"`
	Order                       OrderConfidence `json:"order_confidence"`
	Result                      ResultState     `json:"result_state"`
	Completeness                Completeness    `json:"completeness"`
	Uncertainty                 Uncertainty     `json:"uncertainty"`
}

type Intent struct {
	SchemaVersion   string         `json:"schema_version"`
	ContractVersion string         `json:"contract_version"`
	CompactionID    string         `json:"compaction_id"`
	RunID           string         `json:"run_id"`
	TaskID          string         `json:"task_id"`
	Case            domain.CaseRef `json:"case"`
	PolicyDigest    string         `json:"policy_digest"`
	ProviderRoute   string         `json:"provider_route"`
	Sources         []Source       `json:"sources"`
	CreatedAt       time.Time      `json:"created_at"`
	Deadline        time.Time      `json:"deadline"`
}

type Request struct {
	IdempotencyKey string
	Intent         Intent
}

type Status string

const (
	StatusWriting   Status = "writing"
	StatusCompleted Status = "completed"
	StatusUncertain Status = "uncertain"
)

type State struct {
	SchemaVersion            string             `json:"schema_version"`
	ContractVersion          string             `json:"contract_version"`
	CompactionID             string             `json:"compaction_id"`
	RunID                    string             `json:"run_id"`
	TaskID                   string             `json:"task_id"`
	Case                     domain.CaseRef     `json:"case"`
	PolicyDigest             string             `json:"policy_digest"`
	ProviderRoute            string             `json:"provider_route"`
	Sources                  []Source           `json:"sources"`
	SourceManifestDigest     string             `json:"source_manifest_digest"`
	IntentDigest             string             `json:"intent_digest"`
	IdempotencyDigest        string             `json:"idempotency_digest"`
	Summary                  domain.ArtifactRef `json:"summary"`
	SummaryTrust             TrustLabel         `json:"summary_trust"`
	Status                   Status             `json:"status"`
	ReasonCode               string             `json:"reason_code"`
	PreviousProvenanceDigest string             `json:"previous_provenance_digest"`
	ProvenanceDigest         string             `json:"provenance_digest"`
	CreatedAt                time.Time          `json:"created_at"`
	Deadline                 time.Time          `json:"deadline"`
	UpdatedAt                time.Time          `json:"updated_at"`
	Revision                 uint64             `json:"revision"`
}

type Result struct {
	CompactionID         string
	IntentDigest         string
	Summary              domain.ArtifactRef
	SummaryTrust         TrustLabel
	Sources              []Source
	SourceManifestDigest string
	Status               Status
	ProvenanceDigest     string
	Replayed             bool
}

// SummaryRequest is data-only. A writer may resolve the evidence references
// internally, but cannot receive policy, approval, broker, or tool authority.
type SummaryRequest struct {
	CompactionID string
	RunID        string
	TaskID       string
	Case         domain.CaseRef
	Sources      []Source
	Deadline     time.Time
}

type SummaryWriter interface {
	Write(context.Context, SummaryRequest) (domain.ArtifactRef, error)
}

type EvidenceLookup struct {
	Case           domain.CaseRef
	EvidenceID     string
	EvidenceDigest string
}

// EvidenceResolver proves that an ID resolves in the bound case to the exact
// immutable digest without returning evidence content.
type EvidenceResolver interface {
	Resolve(context.Context, EvidenceLookup) error
}

type Store interface {
	Load(context.Context, domain.CaseRef, string) (State, bool, error)
	Begin(context.Context, string, State) (State, bool, error)
	Save(context.Context, string, State, State) (State, error)
}

type Clock interface{ Now() time.Time }

type Compactor interface {
	Compact(context.Context, Request) (Result, error)
}
