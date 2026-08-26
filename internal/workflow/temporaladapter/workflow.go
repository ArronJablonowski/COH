package temporaladapter

import (
	"go.temporal.io/sdk/temporal"
	temporalworkflow "go.temporal.io/sdk/workflow"

	core "github.com/ArronJablonowski/COH/internal/workflow"
)

// OperationWorkflow is retained under the explicit coh.operation.v1
// registration name. Future incompatible logic must register a new name and
// keep this function replayable while v1 histories remain retained.
func OperationWorkflow(ctx temporalworkflow.Context, input operationInput) (core.WorkflowSnapshot, error) {
	return lifecycleWorkflow(ctx, input, core.OperationWorkflowV1)
}

// AgentLoopWorkflow retains the agent loop under its own immutable workflow
// definition while sharing only the already replay-stable lifecycle kernel.
// Agent-loop state and side effects remain in typed activities and durable SQL
// records; Temporal history carries only bounded identifiers and digests.
func AgentLoopWorkflow(ctx temporalworkflow.Context, input operationInput) (core.WorkflowSnapshot, error) {
	return lifecycleWorkflow(ctx, input, core.AgentLoopWorkflowV1)
}

func lifecycleWorkflow(ctx temporalworkflow.Context, input operationInput, definition string) (core.WorkflowSnapshot, error) {
	if input.Version != definition {
		return core.WorkflowSnapshot{}, temporal.NewNonRetryableApplicationError("workflow definition mismatch", "coh.contract", nil)
	}
	info := temporalworkflow.GetInfo(ctx)
	snapshot := core.WorkflowSnapshot{
		Target: core.WorkflowTarget{
			Case: input.Case, WorkflowID: info.WorkflowExecution.ID, RunID: info.WorkflowExecution.RunID,
		},
		Definition:  definition,
		Version:     workflowVersion,
		State:       core.WorkflowRunning,
		StartDigest: input.StartDigest,
	}
	if err := temporalworkflow.SetQueryHandler(ctx, querySnapshot, func() (core.WorkflowSnapshot, error) {
		return snapshot, nil
	}); err != nil {
		return core.WorkflowSnapshot{}, temporal.NewNonRetryableApplicationError("query registration failed", "coh.contract", nil)
	}

	seen := make(map[string]string)
	signals := temporalworkflow.GetSignalChannel(ctx, signalLifecycle)
	for {
		var signal lifecycleSignal
		canceled := false
		selector := temporalworkflow.NewSelector(ctx)
		selector.AddReceive(signals, func(channel temporalworkflow.ReceiveChannel, more bool) {
			if more {
				channel.Receive(ctx, &signal)
			}
		})
		selector.AddReceive(ctx.Done(), func(temporalworkflow.ReceiveChannel, bool) { canceled = true })
		selector.Select(ctx)
		if canceled {
			return snapshot, temporal.NewCanceledError()
		}
		if prior, exists := seen[signal.IdempotencyDigest]; exists {
			if prior != signal.RequestDigest {
				snapshot.State = core.WorkflowDenied
			}
			continue
		}
		seen[signal.IdempotencyDigest] = signal.RequestDigest
		if snapshot.State == core.WorkflowDenied {
			continue
		}
		snapshot.Sequence++
		snapshot.LastSignalDigest = signal.PayloadDigest
		switch signal.Kind {
		case "advance":
		case "complete":
			snapshot.State = core.WorkflowCompleted
			return snapshot, nil
		case "cancel":
			return snapshot, temporal.NewCanceledError()
		default:
			snapshot.State = core.WorkflowDenied
		}
	}
}
