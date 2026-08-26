// Package agentphase coordinates typed plan, act, observe, and review phases
// over the durable agent loop.
package agentphase

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/agentloop"
)

const ContractVersion = "coh.agent-phase/v1"

type Phase string

const (
	PlanPhase    Phase = "plan"
	ActPhase     Phase = "act"
	ObservePhase Phase = "observe"
	ReviewPhase  Phase = "review"
)

type Completeness string

const (
	Complete  Completeness = "complete"
	Partial   Completeness = "partial"
	Empty     Completeness = "empty"
	Uncertain Completeness = "uncertain"
)

type ReviewDisposition string

const (
	ReviewAccepted ReviewDisposition = "accepted"
	ReviewRevise   ReviewDisposition = "revise"
)

type RetryPolicy struct {
	MaximumPhaseAttempts uint32 `json:"maximum_phase_attempts"`
	MaximumReviewCycles  uint32 `json:"maximum_review_cycles"`
}

type PhaseInput struct {
	ContractVersion   string      `json:"contract_version"`
	Phase             Phase       `json:"phase"`
	TraceID           string      `json:"trace_id"`
	Cycle             uint32      `json:"cycle"`
	InputRefs         []string    `json:"input_refs"`
	InputSetDigest    string      `json:"input_set_digest"`
	PriorOutputDigest string      `json:"prior_output_digest"`
	RetryPolicy       RetryPolicy `json:"retry_policy"`
	Deadline          string      `json:"deadline"`
}

type Claim struct {
	ClaimID                    string   `json:"claim_id"`
	StatementDigest            string   `json:"statement_digest"`
	EvidenceRefs               []string `json:"evidence_refs"`
	CounterevidenceRefs        []string `json:"counterevidence_refs"`
	ConfidenceBasisPoints      uint16   `json:"confidence_basis_points"`
	UnknownDigests             []string `json:"unknown_digests"`
	RecommendedNextStepDigests []string `json:"recommended_next_step_digests"`
}

type Finding struct {
	FindingID                  string   `json:"finding_id"`
	SummaryDigest              string   `json:"summary_digest"`
	Status                     string   `json:"status"`
	Severity                   string   `json:"severity"`
	EvidenceRefs               []string `json:"evidence_refs"`
	CounterevidenceRefs        []string `json:"counterevidence_refs"`
	ConfidenceBasisPoints      uint16   `json:"confidence_basis_points"`
	UnknownDigests             []string `json:"unknown_digests"`
	RecommendedNextStepDigests []string `json:"recommended_next_step_digests"`
}

type PhaseOutput struct {
	ContractVersion   string            `json:"contract_version"`
	Phase             Phase             `json:"phase"`
	TraceID           string            `json:"trace_id"`
	Cycle             uint32            `json:"cycle"`
	InputSetDigest    string            `json:"input_set_digest"`
	ArtifactDigest    string            `json:"artifact_digest"`
	IntentDigest      string            `json:"intent_digest"`
	ReceiptDigest     string            `json:"receipt_digest"`
	EvidenceRefs      []string          `json:"evidence_refs"`
	Completeness      Completeness      `json:"completeness"`
	NegativeResult    bool              `json:"negative_result"`
	Claims            []Claim           `json:"claims"`
	Findings          []Finding         `json:"findings"`
	ReviewDisposition ReviewDisposition `json:"review_disposition"`
}

type StartRequest struct {
	IdempotencyKey string
	RunID          string
	TraceID        string
	Case           domain.CaseRef
	ActorID        string
	PolicyDigest   string
	ProviderRoute  string
	InputRefs      []string
	RetryPolicy    RetryPolicy
	Deadline       time.Time
}

type Session struct {
	TraceID       string
	Cycle         uint32
	Phase         Phase
	RetryPolicy   RetryPolicy
	ControlDigest string
	Snapshot      agentloop.Snapshot
}

type AdvanceRequest struct {
	IdempotencyKey string
	Session        Session
	Intent         *domain.ToolIntent
}

type AdvanceResult struct {
	Session Session
	Output  PhaseOutput
}

type TransitionRequest struct {
	IdempotencyKey string
	Session        Session
	Output         PhaseOutput
}

type ResultResolver interface {
	Resolve(context.Context, string, Phase) (PhaseOutput, error)
}

type Dependencies struct {
	Store   agentloop.StateStore
	Models  workflowbase.ModelProvider
	Actions workflowbase.ActionAuthority
	Results ResultResolver
	Clock   agentloop.Clock
}
