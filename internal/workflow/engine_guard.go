package workflow

import (
	"context"
	"errors"
	"reflect"
	"sync"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

type StopGuard interface {
	Allow(context.Context, string, string, string) error
}

type WorkflowIndex interface {
	Add(context.Context, WorkflowTarget) error
	Remove(context.Context, WorkflowTarget) error
	List(context.Context, stopcontract.Scope) ([]WorkflowTarget, error)
}

type GuardedEngine struct {
	driver EngineDriver
	stop   StopGuard
	index  WorkflowIndex
	mu     sync.Mutex
	runs   map[string]*workflowStopRun
}

func GuardEngine(driver EngineDriver, stop StopGuard, index WorkflowIndex) (*GuardedEngine, error) {
	if driver == nil || isNilEngineDriver(driver) || stop == nil || index == nil {
		return nil, engineInvalid("guard", "driver", "driver is required")
	}
	return &GuardedEngine{driver: driver, stop: stop, index: index, runs: make(map[string]*workflowStopRun)}, nil
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

func (engine *GuardedEngine) Start(ctx context.Context, request WorkflowStart) (WorkflowHandle, error) {
	if err := validateEngineContext(ctx, "start"); err != nil {
		return WorkflowHandle{}, err
	}
	if err := ValidateWorkflowStart(request); err != nil {
		return WorkflowHandle{}, err
	}
	if err := engine.allow(ctx, request.Operation.Case); err != nil {
		return WorkflowHandle{}, err
	}
	handle, err := engine.driver.Start(ctx, request)
	if err = finishEngineCall(ctx, "start", err); err != nil {
		return WorkflowHandle{}, err
	}
	if handle.Target.Case != request.Operation.Case || handle.Target.WorkflowID != request.Operation.ID ||
		handle.Definition != request.Operation.Version || !registeredWorkflowDefinition(handle.Definition) ||
		handle.Version != "v1" || validateWorkflowTarget("start", handle.Target) != nil {
		return WorkflowHandle{}, NewEngineError(EngineDenied, "start", "result", "driver returned an invalid workflow handle", nil)
	}
	if err := engine.index.Add(ctx, handle.Target); err != nil {
		_ = engine.driver.Cancel(context.WithoutCancel(ctx), WorkflowCancel{ContractVersion: WorkflowContractVersion,
			IdempotencyKey: "index-add-failed", Target: handle.Target, ReasonDigest: workflowStopDigest(handle.Target.Case, 0)})
		return WorkflowHandle{}, NewEngineError(EngineUnavailable, "start", "index", "workflow index unavailable", nil)
	}
	if err := engine.allow(ctx, handle.Target.Case); err != nil {
		cancelCtx := context.WithoutCancel(ctx)
		_ = engine.driver.Cancel(cancelCtx, WorkflowCancel{ContractVersion: WorkflowContractVersion,
			IdempotencyKey: "estop-start-race", Target: handle.Target, ReasonDigest: workflowStopDigest(handle.Target.Case, 0)})
		_ = engine.index.Remove(cancelCtx, handle.Target)
		return WorkflowHandle{}, err
	}
	return handle, nil
}

func (engine *GuardedEngine) Signal(ctx context.Context, request WorkflowSignal) error {
	if err := validateEngineContext(ctx, "signal"); err != nil {
		return err
	}
	if err := ValidateWorkflowSignal(request); err != nil {
		return err
	}
	if err := engine.allow(ctx, request.Target.Case); err != nil {
		return err
	}
	err := finishEngineCall(ctx, "signal", engine.driver.Signal(ctx, request))
	if err == nil && request.Kind == "complete" {
		if indexErr := engine.index.Remove(ctx, request.Target); indexErr != nil {
			return NewEngineError(EngineUnavailable, "signal", "index", "workflow index unavailable", nil)
		}
	}
	return err
}

func (engine *GuardedEngine) Query(ctx context.Context, request WorkflowQuery) (WorkflowSnapshot, error) {
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
	if snapshot.Target != request.Target || !registeredWorkflowDefinition(snapshot.Definition) || snapshot.Version != "v1" ||
		!digestPattern.MatchString(snapshot.StartDigest) ||
		(snapshot.LastSignalDigest != "" && !digestPattern.MatchString(snapshot.LastSignalDigest)) ||
		(snapshot.State != WorkflowRunning && snapshot.State != WorkflowCompleted && snapshot.State != WorkflowDenied) {
		return WorkflowSnapshot{}, NewEngineError(EngineDenied, "query", "result", "driver returned an invalid workflow snapshot", nil)
	}
	if snapshot.State != WorkflowRunning {
		if indexErr := engine.index.Remove(ctx, snapshot.Target); indexErr != nil {
			return WorkflowSnapshot{}, NewEngineError(EngineUnavailable, "query", "index", "workflow index unavailable", nil)
		}
	}
	return snapshot, nil
}

func (engine *GuardedEngine) Cancel(ctx context.Context, request WorkflowCancel) error {
	if err := validateEngineContext(ctx, "cancel"); err != nil {
		return err
	}
	if err := ValidateWorkflowCancel(request); err != nil {
		return err
	}
	err := finishEngineCall(ctx, "cancel", engine.driver.Cancel(ctx, request))
	if err == nil {
		if indexErr := engine.index.Remove(ctx, request.Target); indexErr != nil {
			return NewEngineError(EngineUnavailable, "cancel", "index", "workflow index unavailable", nil)
		}
	}
	return err
}

func (engine *GuardedEngine) Replay(ctx context.Context, request WorkflowReplay) (WorkflowReplayResult, error) {
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
	if result.FixtureID != request.FixtureID || !registeredWorkflowDefinition(result.Definition) || result.Version != "v1" ||
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
