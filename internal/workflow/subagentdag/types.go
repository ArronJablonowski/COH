// Package subagentdag coordinates bounded, durable analytical child tasks.
package subagentdag

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/runbudget"
)

const (
	SchemaVersion         = "coh.subagent-dag/v1"
	DecisionSchemaVersion = "coh.subagent-dag-decision/v1"
	ContractVersion       = "1.0.0"
	MaximumTasks          = 512
	MaximumParents        = 16
	MaximumReferences     = 512
	MaximumResults        = 256
)

type Role string

const (
	CoordinatorRole         Role = "coordinator"
	AlertTriageRole         Role = "alert_triage"
	SIEMQueryRole           Role = "siem_query"
	TimelineCorrelationRole Role = "timeline_correlation"
	HuntingRole             Role = "hunting"
	CTIAttackRole           Role = "cti_attack"
	DetectionRole           Role = "detection"
	VulnerabilityRole       Role = "vulnerability"
	ValidationRole          Role = "validation"
	IRPlannerRole           Role = "ir_planner"
	ReviewerRole            Role = "reviewer"
	ReportWriterRole        Role = "report_writer"
)

type Operation string

const (
	CreateGraph Operation = "create_graph"
	Delegate    Operation = "delegate"
	Execute     Operation = "execute"
	Cancel      Operation = "cancel"
	Recover     Operation = "recover"
)

type TaskStatus string

const (
	TaskPending     TaskStatus = "pending"
	TaskDispatching TaskStatus = "dispatching"
	TaskSucceeded   TaskStatus = "succeeded"
	TaskFailed      TaskStatus = "failed"
	TaskDenied      TaskStatus = "denied"
	TaskCanceled    TaskStatus = "canceled"
	TaskTimedOut    TaskStatus = "timeout"
	TaskUncertain   TaskStatus = "uncertain"
)

type Completeness string

const (
	Complete  Completeness = "complete"
	Partial   Completeness = "partial"
	Empty     Completeness = "empty"
	Uncertain Completeness = "uncertain"
)

type Limits struct {
	MaximumDepth       uint32 `json:"maximum_depth"`
	MaximumFanout      uint32 `json:"maximum_fanout"`
	MaximumConcurrency uint32 `json:"maximum_concurrency"`
	MaximumTasks       uint32 `json:"maximum_tasks"`
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

type StructuredResult struct {
	TaskID         string             `json:"task_id"`
	Role           Role               `json:"role"`
	Artifact       domain.ArtifactRef `json:"artifact"`
	Claims         []Claim            `json:"claims"`
	Findings       []Finding          `json:"findings"`
	Completeness   Completeness       `json:"completeness"`
	NegativeResult bool               `json:"negative_result"`
	RuntimeDigest  string             `json:"runtime_digest"`
	ResultDigest   string             `json:"result_digest"`
}

type Edge struct {
	ParentTaskID string `json:"parent_task_id"`
	ChildTaskID  string `json:"child_task_id"`
}

type CancellationAck struct {
	TaskID           string `json:"task_id"`
	Outcome          string `json:"outcome"`
	EvidenceDigest   string `json:"evidence_digest"`
	ProvenanceDigest string `json:"provenance_digest"`
}

type CancellationStatus string

const (
	CancellationActive    CancellationStatus = "active"
	CancellationCompleted CancellationStatus = "completed"
	CancellationUncertain CancellationStatus = "uncertain"
)

type CancellationRecord struct {
	CancellationID    string             `json:"cancellation_id"`
	RootTaskID        string             `json:"root_task_id"`
	ReasonDigest      string             `json:"reason_digest"`
	TargetTaskIDs     []string           `json:"target_task_ids"`
	Acknowledgments   []CancellationAck  `json:"acknowledgments"`
	Status            CancellationStatus `json:"status"`
	IntentDigest      string             `json:"intent_digest"`
	IdempotencyDigest string             `json:"idempotency_digest"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
	Revision          uint64             `json:"revision"`
}

type Task struct {
	TaskID                   string            `json:"task_id"`
	ParentTaskIDs            []string          `json:"parent_task_ids"`
	Role                     Role              `json:"role"`
	Status                   TaskStatus        `json:"status"`
	Depth                    uint32            `json:"depth"`
	InputRefs                []string          `json:"input_refs"`
	AssignmentDigest         string            `json:"assignment_digest"`
	BudgetReservationDigest  string            `json:"budget_reservation_digest"`
	BudgetSettlementDigest   string            `json:"budget_settlement_digest"`
	Result                   *StructuredResult `json:"result"`
	Cancellation             *CancellationAck  `json:"cancellation"`
	PreviousProvenanceDigest string            `json:"previous_provenance_digest"`
	ProvenanceDigest         string            `json:"provenance_digest"`
	CreatedAt                time.Time         `json:"created_at"`
	Deadline                 time.Time         `json:"deadline"`
	UpdatedAt                time.Time         `json:"updated_at"`
	Revision                 uint64            `json:"revision"`
}

type Receipt struct {
	Operation         Operation `json:"operation"`
	IdempotencyDigest string    `json:"idempotency_digest"`
	IntentDigest      string    `json:"intent_digest"`
	TaskID            string    `json:"task_id"`
	Revision          uint64    `json:"revision"`
}

type Graph struct {
	SchemaVersion            string               `json:"schema_version"`
	ContractVersion          string               `json:"contract_version"`
	GraphID                  string               `json:"graph_id"`
	RunID                    string               `json:"run_id"`
	Case                     domain.CaseRef       `json:"case"`
	ActorID                  string               `json:"actor_id"`
	ActorRevision            uint64               `json:"actor_revision"`
	PolicyDigest             string               `json:"policy_digest"`
	ProviderRoute            string               `json:"provider_route"`
	Limits                   Limits               `json:"limits"`
	BudgetPlanDigest         string               `json:"budget_plan_digest"`
	Tasks                    []Task               `json:"tasks"`
	Edges                    []Edge               `json:"edges"`
	Receipts                 []Receipt            `json:"receipts"`
	Cancellations            []CancellationRecord `json:"cancellations"`
	PreviousProvenanceDigest string               `json:"previous_provenance_digest"`
	ProvenanceDigest         string               `json:"provenance_digest"`
	CreatedAt                time.Time            `json:"created_at"`
	Deadline                 time.Time            `json:"deadline"`
	UpdatedAt                time.Time            `json:"updated_at"`
	Revision                 uint64               `json:"revision"`
}

type Decision struct {
	SchemaVersion    string         `json:"schema_version"`
	ContractVersion  string         `json:"contract_version"`
	DecisionID       string         `json:"decision_id"`
	DecisionDigest   string         `json:"decision_digest"`
	IntentDigest     string         `json:"intent_digest"`
	Operation        Operation      `json:"operation"`
	GraphID          string         `json:"graph_id"`
	TaskID           string         `json:"task_id"`
	Case             domain.CaseRef `json:"case"`
	ActorID          string         `json:"actor_id"`
	ActorRevision    uint64         `json:"actor_revision"`
	PolicyDigest     string         `json:"policy_digest"`
	RevocationDigest string         `json:"revocation_digest"`
	Outcome          string         `json:"outcome"`
	ReasonCode       string         `json:"reason_code"`
	IssuedAt         time.Time      `json:"issued_at"`
	ExpiresAt        time.Time      `json:"expires_at"`
	Revision         uint64         `json:"revision"`
}

type CreateRequest struct {
	RequestID      string
	IdempotencyKey string
	GraphID        string
	RunID          string
	RootTaskID     string
	Case           domain.CaseRef
	ActorID        string
	ActorRevision  uint64
	PolicyDigest   string
	ProviderRoute  string
	Limits         Limits
	InputRefs      []string
	Deadline       time.Time
	BudgetPlan     runbudget.Plan
	TaskBudget     runbudget.Vector
	BudgetClaim    runbudget.Vector
}

type DelegateRequest struct {
	RequestID      string
	IdempotencyKey string
	GraphID        string
	TaskID         string
	ParentTaskIDs  []string
	Case           domain.CaseRef
	ActorID        string
	ActorRevision  uint64
	Role           Role
	InputRefs      []string
	PolicyDigest   string
	Deadline       time.Time
	TaskBudget     runbudget.Vector
	BudgetClaim    runbudget.Vector
}

type ExecuteRequest struct {
	RequestID      string
	IdempotencyKey string
	GraphID        string
	TaskID         string
	Case           domain.CaseRef
	ActorID        string
	ActorRevision  uint64
	PolicyDigest   string
}

type CancelRequest struct {
	RequestID      string
	IdempotencyKey string
	GraphID        string
	TaskID         string
	Case           domain.CaseRef
	ActorID        string
	ActorRevision  uint64
	PolicyDigest   string
	ReasonDigest   string
}

type RecoverRequest struct {
	RequestID      string
	IdempotencyKey string
	GraphID        string
	TaskID         string
	Case           domain.CaseRef
	ActorID        string
	ActorRevision  uint64
	PolicyDigest   string
}

type AuthorizationRequest struct {
	IntentDigest  string
	Operation     Operation
	GraphID       string
	TaskID        string
	Case          domain.CaseRef
	ActorID       string
	ActorRevision uint64
	Role          Role
	ParentTaskIDs []string
	PolicyDigest  string
	Deadline      time.Time
}

// ExecutionRequest is data-only. It contains no actor, policy, approval,
// credential, connector, broker, tool, or executor authority.
type ExecutionRequest struct {
	GraphID          string
	TaskID           string
	Role             Role
	InputRefs        []string
	AssignmentDigest string
	Deadline         time.Time
}

type Result struct {
	Graph    Graph
	Task     Task
	Replayed bool
}

type Authority interface {
	AuthorizeDelegation(context.Context, AuthorizationRequest) (Decision, error)
}

type Runtime interface {
	RunChild(context.Context, ExecutionRequest) (StructuredResult, error)
}

type Canceler interface {
	CancelChild(context.Context, ExecutionRequest, string) (CancellationAck, error)
}

type Store interface {
	Load(context.Context, domain.CaseRef, string) (Graph, bool, error)
	Begin(context.Context, string, Graph) (Graph, bool, error)
	Save(context.Context, string, Graph, Graph) (Graph, bool, error)
}

type Clock interface{ Now() time.Time }
