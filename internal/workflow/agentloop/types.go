package agentloop

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	ContractVersion    = "coh.agent-loop/v1"
	WorkflowDefinition = "coh.agent-loop.v1"
	WorkflowVersion    = "1.0.0"
	RecordSchema       = "coh.domain/v1"
)

type RunStatus string

const (
	RunRunning   RunStatus = "running"
	RunWaiting   RunStatus = "waiting"
	RunSucceeded RunStatus = "succeeded"
	RunFailed    RunStatus = "failed"
	RunDenied    RunStatus = "denied"
	RunCanceled  RunStatus = "canceled"
	RunTimeout   RunStatus = "timeout"
	RunUncertain RunStatus = "uncertain"
)

type StepStatus string

const (
	StepPending     StepStatus = "pending"
	StepRunning     StepStatus = "running"
	StepDispatching StepStatus = "dispatching"
	StepSucceeded   StepStatus = "succeeded"
	StepFailed      StepStatus = "failed"
	StepDenied      StepStatus = "denied"
	StepCanceled    StepStatus = "canceled"
	StepTimeout     StepStatus = "timeout"
	StepUncertain   StepStatus = "uncertain"
)

type ActivityKind string

const (
	PlanningActivity         ActivityKind = "planning"
	AuthorizedActionActivity ActivityKind = "authorized_action"
)

type Run struct {
	ContractVersion  string
	RunID            string
	Case             domain.CaseRef
	ActorID          string
	WorkflowVersion  string
	PolicyDigest     string
	ProviderRoute    string
	Status           RunStatus
	CurrentStepID    string
	Sequence         uint64
	InputRefs        []string
	OutputRefs       []string
	ProvenanceDigest string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	Revision         uint64
}

type Step struct {
	ContractVersion  string
	StepID           string
	RunID            string
	Case             domain.CaseRef
	Kind             ActivityKind
	Status           StepStatus
	Attempt          uint32
	Deadline         time.Time
	InputRefs        []string
	OutputRefs       []string
	IntentDigest     string
	ReceiptDigest    string
	ProvenanceDigest string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	Revision         uint64
}

type Snapshot struct {
	Run      Run
	Step     Step
	Replayed bool
}

type StartRequest struct {
	IdempotencyKey string
	RunID          string
	StepID         string
	Case           domain.CaseRef
	ActorID        string
	PolicyDigest   string
	ProviderRoute  string
	Activity       ActivityKind
	InputRefs      []string
	IntentDigest   string
	Deadline       time.Time
}

type ExecuteRequest struct {
	IdempotencyKey string
	Case           domain.CaseRef
	RunID          string
	StepID         string
	Intent         *domain.ToolIntent
}

type ScheduleRequest struct {
	IdempotencyKey string
	Case           domain.CaseRef
	RunID          string
	StepID         string
	Activity       ActivityKind
	InputRefs      []string
	IntentDigest   string
	Deadline       time.Time
}

type CompleteRequest struct {
	IdempotencyKey string
	Case           domain.CaseRef
	RunID          string
}

type ResumeRequest struct {
	IdempotencyKey string
	Case           domain.CaseRef
	RunID          string
	Intent         *domain.ToolIntent
}

type TerminalOutcome string

const (
	TerminalFailed    TerminalOutcome = "failed"
	TerminalDenied    TerminalOutcome = "denied"
	TerminalCanceled  TerminalOutcome = "canceled"
	TerminalTimeout   TerminalOutcome = "timeout"
	TerminalUncertain TerminalOutcome = "uncertain"
)

type TerminateRequest struct {
	IdempotencyKey string
	Case           domain.CaseRef
	RunID          string
	StepID         string
	Outcome        TerminalOutcome
	ReasonDigest   string
}

type StateStore interface {
	Create(context.Context, string, Snapshot) (Snapshot, error)
	Load(context.Context, domain.CaseRef, string) (Snapshot, error)
	Save(context.Context, string, Snapshot, Snapshot) (Snapshot, error)
}

type Clock interface{ Now() time.Time }
