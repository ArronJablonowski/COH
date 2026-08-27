package queryruntime

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/querybounds"
	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const (
	ContractVersion         = "1.0.0"
	SessionSchemaVersion    = "coh.query-runtime-session/v1"
	SlicePlanSchemaVersion  = "coh.query-slice-plan/v1"
	RateSchemaVersion       = "coh.query-rate-reservation/v1"
	MaximumCancellationWait = 5 * time.Second
	MaximumRecordWait       = 5 * time.Second
	MaximumSessionCapacity  = 10000
	MaximumSliceDescriptors = 4096
)

type Profile struct {
	Mode   string                `json:"mode"`
	Limits queryconnector.Limits `json:"limits"`
}

type Config struct {
	Interactive      Profile
	Export           Profile
	MaximumSessions  int
	CancellationWait time.Duration
	RecordWait       time.Duration
}

type Usage struct {
	RowsScanned     uint64 `json:"rows_scanned"`
	RowsReturned    uint64 `json:"rows_returned"`
	BytesReturned   uint64 `json:"bytes_returned"`
	DurationMillis  uint64 `json:"duration_millis"`
	PagesReturned   uint32 `json:"pages_returned"`
	SlicesCompleted uint32 `json:"slices_completed"`
	CostMillionths  uint64 `json:"cost_millionths"`
}

type Session struct {
	SchemaVersion             string                `json:"schema_version"`
	ContractVersion           string                `json:"contract_version"`
	SessionDigest             string                `json:"session_digest"`
	PreviousSessionDigest     string                `json:"previous_session_digest,omitempty"`
	SessionID                 string                `json:"session_id"`
	Revision                  uint64                `json:"revision"`
	QueryID                   string                `json:"query_id"`
	QueryDigest               string                `json:"query_digest"`
	BoundsDecisionDigest      string                `json:"bounds_decision_digest"`
	ExecutionDigest           string                `json:"execution_digest"`
	AttemptID                 string                `json:"attempt_id"`
	OrganizationID            string                `json:"organization_id"`
	TenantID                  string                `json:"tenant_id"`
	ActorID                   string                `json:"actor_id"`
	SourceID                  string                `json:"source_id"`
	Mode                      string                `json:"mode"`
	EffectiveLimits           queryconnector.Limits `json:"effective_limits"`
	Usage                     Usage                 `json:"usage"`
	Status                    string                `json:"status"`
	ReasonCode                string                `json:"reason_code"`
	NextPageNumber            uint32                `json:"next_page_number"`
	JobHandleDigest           string                `json:"job_handle_digest"`
	PageHandleDigest          string                `json:"page_handle_digest,omitempty"`
	LastPageDigest            string                `json:"last_page_digest,omitempty"`
	LastRateReservationDigest string                `json:"last_rate_reservation_digest,omitempty"`
	CancellationIntentDigest  string                `json:"cancellation_intent_digest,omitempty"`
	VendorProvenanceDigest    string                `json:"vendor_provenance_digest"`
	StartedAt                 string                `json:"started_at"`
	UpdatedAt                 string                `json:"updated_at"`
	Deadline                  string                `json:"deadline"`
}

type SessionRef struct {
	SessionID     string
	SessionDigest string
}

type StartRequest struct {
	Mode      string
	Admission querybounds.Admission
	Execution queryconnector.ValidatedExecution
}

type CancelIntent struct {
	SessionID      string
	SessionDigest  string
	IdempotencyKey string
	ReasonCode     string
}

type Result struct {
	Session Session
	Page    queryconnector.ValidatedPage
	HasPage bool
}

type RateRequest struct {
	SchemaVersion    string `json:"schema_version"`
	ContractVersion  string `json:"contract_version"`
	SessionID        string `json:"session_id"`
	SessionDigest    string `json:"session_digest"`
	OrganizationID   string `json:"organization_id"`
	TenantID         string `json:"tenant_id"`
	ActorID          string `json:"actor_id"`
	SourceID         string `json:"source_id"`
	Mode             string `json:"mode"`
	Operation        string `json:"operation"`
	MaximumPerMinute uint32 `json:"maximum_per_minute"`
	RequestedAt      string `json:"requested_at"`
}

type RateReservation struct {
	SchemaVersion     string `json:"schema_version"`
	ContractVersion   string `json:"contract_version"`
	ReservationDigest string `json:"reservation_digest"`
	KeyDigest         string `json:"key_digest"`
	SessionID         string `json:"session_id"`
	Operation         string `json:"operation"`
	Sequence          uint64 `json:"sequence"`
	ReservedAt        string `json:"reserved_at"`
	ValidUntil        string `json:"valid_until"`
}

type SliceDescriptor struct {
	SliceDigest string `json:"slice_digest"`
	Index       uint32 `json:"index"`
	Count       uint32 `json:"count"`
	Start       string `json:"start"`
	End         string `json:"end"`
}

type SlicePlan struct {
	SchemaVersion        string            `json:"schema_version"`
	ContractVersion      string            `json:"contract_version"`
	PlanDigest           string            `json:"plan_digest"`
	ParentQueryID        string            `json:"parent_query_id"`
	ParentQueryDigest    string            `json:"parent_query_digest"`
	BoundsDecisionDigest string            `json:"bounds_decision_digest"`
	Slices               []SliceDescriptor `json:"slices"`
}

type Adapter interface {
	Poll(context.Context, queryconnector.PollRequest) (queryconnector.ValidatedPoll, error)
	NextPage(context.Context, queryconnector.PageRequest) (queryconnector.ValidatedPage, error)
	Cancel(context.Context, queryconnector.CancelRequest) (queryconnector.ValidatedCancellation, error)
}

// RateGate is the atomic rate authority for tenant/source/actor/profile keys.
// Production callers must not substitute process-local counters for this port.
type RateGate interface {
	Reserve(context.Context, RateRequest) (RateReservation, error)
}

// Recorder durably accepts a redacted session transition before a page or
// terminal success becomes caller-visible. COH-E12-05 owns its persistence.
type Recorder interface {
	RecordQuerySession(context.Context, Session) error
}

type Clock interface {
	Now() time.Time
}
