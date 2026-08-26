// Package runbudget enforces durable run and task resource budgets before work
// can be scheduled by the agent workflow.
package runbudget

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	SchemaVersion   = "coh.run-budget/v1"
	ContractVersion = "1.0.0"
	MaximumRecords  = 4096
)

// Vector uses integer base units only. CostMicros is one millionth of the
// configured account currency and WallTimeNanoseconds is an elapsed duration.
type Vector struct {
	Tokens              uint64 `json:"tokens"`
	CostMicros          uint64 `json:"cost_micros"`
	WallTimeNanoseconds uint64 `json:"wall_time_nanoseconds"`
	ToolCalls           uint64 `json:"tool_calls"`
	QueryRows           uint64 `json:"query_rows"`
	EvidenceBytes       uint64 `json:"evidence_bytes"`
	DelegationDepth     uint32 `json:"delegation_depth"`
	Fanout              uint32 `json:"fanout"`
	Concurrency         uint32 `json:"concurrency"`
}

type Plan struct {
	SchemaVersion   string         `json:"schema_version"`
	ContractVersion string         `json:"contract_version"`
	RunID           string         `json:"run_id"`
	Case            domain.CaseRef `json:"case"`
	PolicyDigest    string         `json:"policy_digest"`
	ProviderRoute   string         `json:"provider_route"`
	Limits          Vector         `json:"limits"`
	CreatedAt       time.Time      `json:"created_at"`
	ExpiresAt       time.Time      `json:"expires_at"`
}

type ReservationRequest struct {
	IdempotencyKey string
	RunID          string
	TaskID         string
	ParentTaskID   string
	Case           domain.CaseRef
	Activity       string
	PolicyDigest   string
	ProviderRoute  string
	Deadline       time.Time
	Plan           *Plan
	TaskLimits     Vector
	Claim          Vector
}

type Reservation struct {
	ReservationDigest string
	PlanDigest        string
	ClaimDigest       string
	LedgerDigest      string
	Replayed          bool
}

type SettlementRequest struct {
	IdempotencyKey    string
	RunID             string
	TaskID            string
	Case              domain.CaseRef
	ReservationDigest string
	Actual            *Vector
	Outcome           string
}

type Settlement struct {
	ReservationDigest string
	SettlementDigest  string
	LedgerDigest      string
	Replayed          bool
}

type ReservationStatus string

const (
	ReservationActive  ReservationStatus = "active"
	ReservationSettled ReservationStatus = "settled"
)

type ReservationRecord struct {
	ReservationDigest           string            `json:"reservation_digest"`
	ClaimDigest                 string            `json:"claim_digest"`
	SettlementDigest            string            `json:"settlement_digest"`
	SettlementIdempotencyDigest string            `json:"settlement_idempotency_digest"`
	IdempotencyDigest           string            `json:"idempotency_digest"`
	TaskID                      string            `json:"task_id"`
	ParentTaskID                string            `json:"parent_task_id"`
	Activity                    string            `json:"activity"`
	PolicyDigest                string            `json:"policy_digest"`
	ProviderRoute               string            `json:"provider_route"`
	Deadline                    time.Time         `json:"deadline"`
	TaskLimits                  Vector            `json:"task_limits"`
	Claim                       Vector            `json:"claim"`
	Actual                      Vector            `json:"actual"`
	Outcome                     string            `json:"outcome"`
	Status                      ReservationStatus `json:"status"`
	CreatedAt                   time.Time         `json:"created_at"`
	SettledAt                   time.Time         `json:"settled_at"`
}

type Ledger struct {
	SchemaVersion            string              `json:"schema_version"`
	ContractVersion          string              `json:"contract_version"`
	RunID                    string              `json:"run_id"`
	Case                     domain.CaseRef      `json:"case"`
	PlanDigest               string              `json:"plan_digest"`
	PolicyDigest             string              `json:"policy_digest"`
	ProviderRoute            string              `json:"provider_route"`
	Limits                   Vector              `json:"limits"`
	Charged                  Vector              `json:"charged"`
	ActiveConcurrency        uint32              `json:"active_concurrency"`
	Reservations             []ReservationRecord `json:"reservations"`
	ReasonCode               string              `json:"reason_code"`
	PreviousProvenanceDigest string              `json:"previous_provenance_digest"`
	ProvenanceDigest         string              `json:"provenance_digest"`
	CreatedAt                time.Time           `json:"created_at"`
	ExpiresAt                time.Time           `json:"expires_at"`
	UpdatedAt                time.Time           `json:"updated_at"`
	Revision                 uint64              `json:"revision"`
}

// Store must implement begin-if-absent and optimistic compare-and-save. Those
// operations are the durable serialization boundary for budget decisions.
type Store interface {
	Load(context.Context, domain.CaseRef, string) (Ledger, bool, error)
	Begin(context.Context, string, Ledger) (Ledger, bool, error)
	Save(context.Context, string, Ledger, Ledger) (Ledger, error)
}

type Clock interface{ Now() time.Time }

// Authority is the only scheduling-budget capability used by the agent loop.
type Authority interface {
	Reserve(context.Context, ReservationRequest) (Reservation, error)
	Settle(context.Context, SettlementRequest) (Settlement, error)
}
