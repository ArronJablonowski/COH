package workflow

import "github.com/ArronJablonowski/COH/internal/domain"

const (
	WorkflowContractVersion = "coh.workflow/v1"
	OperationWorkflowV1     = "coh.operation.v1"
	AgentLoopWorkflowV1     = "coh.agent-loop.v1"
)

type WorkflowState string

const (
	WorkflowRunning   WorkflowState = "running"
	WorkflowCompleted WorkflowState = "completed"
	WorkflowDenied    WorkflowState = "denied"
)

type WorkflowStart struct {
	ContractVersion string
	IdempotencyKey  string
	Operation       domain.Operation
	InputDigest     string
}

type WorkflowTarget struct {
	Case       domain.CaseRef
	WorkflowID string
	RunID      string
}

type WorkflowHandle struct {
	Target     WorkflowTarget
	Definition string
	Version    string
	Replayed   bool
}

type WorkflowSignal struct {
	ContractVersion string
	IdempotencyKey  string
	Target          WorkflowTarget
	Kind            string
	PayloadDigest   string
}

type WorkflowQuery struct {
	ContractVersion string
	Target          WorkflowTarget
	Kind            string
}

type WorkflowSnapshot struct {
	Target           WorkflowTarget
	Definition       string
	Version          string
	State            WorkflowState
	Sequence         uint64
	StartDigest      string
	LastSignalDigest string
}

type WorkflowCancel struct {
	ContractVersion string
	IdempotencyKey  string
	Target          WorkflowTarget
	ReasonDigest    string
}

type WorkflowReplay struct {
	ContractVersion string
	FixtureID       string
}

type WorkflowReplayResult struct {
	FixtureID     string
	Definition    string
	Version       string
	HistoryDigest string
	Replayed      bool
}
