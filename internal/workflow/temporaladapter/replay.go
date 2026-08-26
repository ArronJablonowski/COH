package temporaladapter

import (
	"bytes"
	"context"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	core "github.com/ArronJablonowski/COH/internal/workflow"
)

func (adapter *Adapter) Replay(ctx context.Context, request core.WorkflowReplay) (core.WorkflowReplayResult, error) {
	if err := core.ValidateWorkflowReplay(request); err != nil {
		return core.WorkflowReplayResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return core.WorkflowReplayResult{}, normalizeError("replay", "context", err)
	}
	adapter.mu.Lock()
	history, exists := adapter.histories[request.FixtureID]
	adapter.mu.Unlock()
	if !exists {
		return core.WorkflowReplayResult{}, engineError(core.EngineNotFound, "replay", "fixture_id", "retained history is not registered")
	}
	if digestBytes(history.JSON) != history.Digest {
		return core.WorkflowReplayResult{}, engineError(core.EngineDenied, "replay", "history_digest", "retained history failed verification")
	}
	parsed, err := client.HistoryFromJSON(bytes.NewReader(history.JSON), client.HistoryJSONOptions{})
	if err != nil {
		return core.WorkflowReplayResult{}, engineError(core.EngineDenied, "replay", "history", "retained history is invalid")
	}
	replayer := worker.NewWorkflowReplayer()
	if history.Definition == core.AgentLoopWorkflowV1 {
		replayer.RegisterWorkflowWithOptions(AgentLoopWorkflow, workflow.RegisterOptions{Name: core.AgentLoopWorkflowV1})
	} else {
		replayer.RegisterWorkflowWithOptions(OperationWorkflow, workflow.RegisterOptions{Name: core.OperationWorkflowV1})
	}
	if err := replayer.ReplayWorkflowHistory(nil, parsed); err != nil {
		return core.WorkflowReplayResult{}, engineError(core.EngineConflict, "replay", "history", "workflow history is not replay-compatible")
	}
	return core.WorkflowReplayResult{FixtureID: request.FixtureID, Definition: history.Definition, Version: history.Version, HistoryDigest: history.Digest, Replayed: true}, nil
}
