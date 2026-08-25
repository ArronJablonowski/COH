package temporaladapter

import (
	"context"
	"errors"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/client"

	core "github.com/ArronJablonowski/COH/internal/workflow"
)

func (adapter *Adapter) Start(ctx context.Context, request core.WorkflowStart) (core.WorkflowHandle, error) {
	if err := core.ValidateWorkflowStart(request); err != nil {
		return core.WorkflowHandle{}, err
	}
	startDigest, err := digestValue(request)
	if err != nil {
		return core.WorkflowHandle{}, engineError(core.EngineInvalidInput, "start", "request", "request cannot be encoded")
	}
	options := client.StartWorkflowOptions{
		ID:                                       request.Operation.ID,
		TaskQueue:                                adapter.taskQueue,
		WorkflowExecutionTimeout:                 adapter.executionTimeout,
		WorkflowTaskTimeout:                      10 * time.Second,
		WorkflowIDConflictPolicy:                 enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL,
		WorkflowIDReusePolicy:                    enumspb.WORKFLOW_ID_REUSE_POLICY_REJECT_DUPLICATE,
		WorkflowExecutionErrorWhenAlreadyStarted: true,
	}
	run, err := adapter.client.ExecuteWorkflow(ctx, options, core.OperationWorkflowV1, inputFromStart(request, startDigest))
	if err == nil {
		return core.WorkflowHandle{Target: core.WorkflowTarget{Case: request.Operation.Case, WorkflowID: run.GetID(), RunID: run.GetRunID()}, Definition: core.OperationWorkflowV1, Version: workflowVersion}, nil
	}
	var duplicate *serviceerror.WorkflowExecutionAlreadyStarted
	if !errors.As(err, &duplicate) {
		return core.WorkflowHandle{}, normalizeError("start", "execution", err)
	}
	snapshot, queryErr := adapter.querySnapshot(ctx, request.Operation.ID, "")
	if queryErr != nil {
		return core.WorkflowHandle{}, queryErr
	}
	if snapshot.Target.Case != request.Operation.Case || snapshot.StartDigest != startDigest {
		return core.WorkflowHandle{}, engineError(core.EngineConflict, "start", "idempotency_key", "workflow identity was used for different inputs")
	}
	return core.WorkflowHandle{Target: snapshot.Target, Definition: snapshot.Definition, Version: snapshot.Version, Replayed: true}, nil
}

func (adapter *Adapter) Signal(ctx context.Context, request core.WorkflowSignal) error {
	if err := core.ValidateWorkflowSignal(request); err != nil {
		return err
	}
	idempotencyDigest := digestBytes([]byte(request.IdempotencyKey))
	requestDigest, err := digestValue(request)
	if err != nil {
		return engineError(core.EngineInvalidInput, "signal", "request", "request cannot be encoded")
	}
	payload := lifecycleSignal{IdempotencyDigest: idempotencyDigest, RequestDigest: requestDigest, Kind: request.Kind, PayloadDigest: request.PayloadDigest}
	return normalizeError("signal", "execution", adapter.client.SignalWorkflow(ctx, request.Target.WorkflowID, request.Target.RunID, signalLifecycle, payload))
}

func (adapter *Adapter) Query(ctx context.Context, request core.WorkflowQuery) (core.WorkflowSnapshot, error) {
	if err := core.ValidateWorkflowQuery(request); err != nil {
		return core.WorkflowSnapshot{}, err
	}
	snapshot, err := adapter.querySnapshot(ctx, request.Target.WorkflowID, request.Target.RunID)
	if err != nil {
		return core.WorkflowSnapshot{}, err
	}
	if snapshot.Target.Case != request.Target.Case {
		return core.WorkflowSnapshot{}, engineError(core.EngineDenied, "query", "scope", "workflow scope differs from request")
	}
	return snapshot, nil
}

func (adapter *Adapter) querySnapshot(ctx context.Context, workflowID, runID string) (core.WorkflowSnapshot, error) {
	value, err := adapter.client.QueryWorkflow(ctx, workflowID, runID, querySnapshot)
	if err != nil {
		return core.WorkflowSnapshot{}, normalizeError("query", "execution", err)
	}
	var snapshot core.WorkflowSnapshot
	if err := value.Get(&snapshot); err != nil {
		return core.WorkflowSnapshot{}, engineError(core.EngineDenied, "query", "result", "Temporal returned an invalid snapshot")
	}
	return snapshot, nil
}

func (adapter *Adapter) Cancel(ctx context.Context, request core.WorkflowCancel) error {
	if err := core.ValidateWorkflowCancel(request); err != nil {
		return err
	}
	idempotencyDigest := digestBytes([]byte(request.IdempotencyKey))
	requestDigest, err := digestValue(request)
	if err != nil {
		return engineError(core.EngineInvalidInput, "cancel", "request", "request cannot be encoded")
	}
	payload := lifecycleSignal{IdempotencyDigest: idempotencyDigest, RequestDigest: requestDigest, Kind: "cancel", PayloadDigest: request.ReasonDigest}
	if err := adapter.client.SignalWorkflow(ctx, request.Target.WorkflowID, request.Target.RunID, signalLifecycle, payload); err != nil {
		return normalizeError("cancel", "reason", err)
	}
	return normalizeError("cancel", "execution", adapter.client.CancelWorkflow(ctx, request.Target.WorkflowID, request.Target.RunID))
}
