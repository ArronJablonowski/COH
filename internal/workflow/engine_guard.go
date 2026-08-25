package workflow

import (
	"context"
	"errors"
	"reflect"
)

type guardedEngine struct{ driver EngineDriver }

func GuardEngine(driver EngineDriver) (Engine, error) {
	if driver == nil || isNilEngineDriver(driver) {
		return nil, engineInvalid("guard", "driver", "driver is required")
	}
	return &guardedEngine{driver: driver}, nil
}

func isNilEngineDriver(driver EngineDriver) bool {
	value := reflect.ValueOf(driver)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (engine *guardedEngine) Start(ctx context.Context, request WorkflowStart) (WorkflowHandle, error) {
	if err := validateEngineContext(ctx, "start"); err != nil {
		return WorkflowHandle{}, err
	}
	if err := ValidateWorkflowStart(request); err != nil {
		return WorkflowHandle{}, err
	}
	handle, err := engine.driver.Start(ctx, request)
	if err = finishEngineCall(ctx, "start", err); err != nil {
		return WorkflowHandle{}, err
	}
	if handle.Target.Case != request.Operation.Case || handle.Target.WorkflowID != request.Operation.ID ||
		handle.Definition != OperationWorkflowV1 || handle.Version != "v1" || validateWorkflowTarget("start", handle.Target) != nil {
		return WorkflowHandle{}, NewEngineError(EngineDenied, "start", "result", "driver returned an invalid workflow handle", nil)
	}
	return handle, nil
}

func (engine *guardedEngine) Signal(ctx context.Context, request WorkflowSignal) error {
	if err := validateEngineContext(ctx, "signal"); err != nil {
		return err
	}
	if err := ValidateWorkflowSignal(request); err != nil {
		return err
	}
	return finishEngineCall(ctx, "signal", engine.driver.Signal(ctx, request))
}

func (engine *guardedEngine) Query(ctx context.Context, request WorkflowQuery) (WorkflowSnapshot, error) {
	if err := validateEngineContext(ctx, "query"); err != nil {
		return WorkflowSnapshot{}, err
	}
	if err := ValidateWorkflowQuery(request); err != nil {
		return WorkflowSnapshot{}, err
	}
	snapshot, err := engine.driver.Query(ctx, request)
	if err = finishEngineCall(ctx, "query", err); err != nil {
		return WorkflowSnapshot{}, err
	}
	if snapshot.Target != request.Target || snapshot.Definition != OperationWorkflowV1 || snapshot.Version != "v1" ||
		!digestPattern.MatchString(snapshot.StartDigest) ||
		(snapshot.LastSignalDigest != "" && !digestPattern.MatchString(snapshot.LastSignalDigest)) ||
		(snapshot.State != WorkflowRunning && snapshot.State != WorkflowCompleted && snapshot.State != WorkflowDenied) {
		return WorkflowSnapshot{}, NewEngineError(EngineDenied, "query", "result", "driver returned an invalid workflow snapshot", nil)
	}
	return snapshot, nil
}

func (engine *guardedEngine) Cancel(ctx context.Context, request WorkflowCancel) error {
	if err := validateEngineContext(ctx, "cancel"); err != nil {
		return err
	}
	if err := ValidateWorkflowCancel(request); err != nil {
		return err
	}
	return finishEngineCall(ctx, "cancel", engine.driver.Cancel(ctx, request))
}

func (engine *guardedEngine) Replay(ctx context.Context, request WorkflowReplay) (WorkflowReplayResult, error) {
	if err := validateEngineContext(ctx, "replay"); err != nil {
		return WorkflowReplayResult{}, err
	}
	if err := ValidateWorkflowReplay(request); err != nil {
		return WorkflowReplayResult{}, err
	}
	result, err := engine.driver.Replay(ctx, request)
	if err = finishEngineCall(ctx, "replay", err); err != nil {
		return WorkflowReplayResult{}, err
	}
	if result.FixtureID != request.FixtureID || result.Definition != OperationWorkflowV1 || result.Version != "v1" ||
		!digestPattern.MatchString(result.HistoryDigest) || !result.Replayed {
		return WorkflowReplayResult{}, NewEngineError(EngineDenied, "replay", "result", "driver returned an invalid replay result", nil)
	}
	return result, nil
}

func finishEngineCall(ctx context.Context, operation string, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		return validateEngineContext(ctx, operation)
	}
	if err == nil {
		return nil
	}
	var engineErr *EngineError
	if errors.As(err, &engineErr) {
		return err
	}
	return NewEngineError(EngineUnavailable, operation, "driver", "workflow driver failed", nil)
}
