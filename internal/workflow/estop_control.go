package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"

	"github.com/ArronJablonowski/COH/internal/domain"
	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

const workflowStopControlID = "durable-workflows"

type workflowStopRun struct {
	done     chan struct{}
	evidence string
	err      error
}

func (*GuardedEngine) ID() string   { return workflowStopControlID }
func (*GuardedEngine) Kind() string { return "workflow" }

func (engine *GuardedEngine) Apply(ctx context.Context, request stopcontract.ControlRequest) (string, error) {
	if engine == nil || engine.driver == nil || request.Epoch == 0 || stopcontract.ValidateScope(request.Scope) != nil {
		return "", NewEngineError(EngineInvalidInput, "estop", "request", "invalid containment request", nil)
	}
	key := workflowStopRunKey(request)
	engine.mu.Lock()
	if existing := engine.runs[key]; existing != nil {
		engine.mu.Unlock()
		select {
		case <-existing.done:
			return existing.evidence, existing.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	run := &workflowStopRun{done: make(chan struct{})}
	engine.runs[key] = run
	engine.mu.Unlock()
	run.evidence, run.err = engine.applyStop(ctx, request)
	close(run.done)
	return run.evidence, run.err
}

func (engine *GuardedEngine) applyStop(ctx context.Context, request stopcontract.ControlRequest) (string, error) {
	targets, err := engine.index.List(ctx, request.Scope)
	if err != nil {
		return "", NewEngineError(EngineUnavailable, "estop", "index", "workflow index unavailable", nil)
	}
	sort.Slice(targets, func(i, j int) bool { return workflowTargetKey(targets[i]) < workflowTargetKey(targets[j]) })
	reasonDigest := workflowStopDigest(domain.CaseRef{OrganizationID: request.Scope.OrganizationID,
		TenantID: request.Scope.TenantID, CaseID: request.Scope.CaseID}, request.Epoch)
	type result struct {
		target WorkflowTarget
		err    error
	}
	results := make(chan result, len(targets))
	for _, target := range targets {
		go func(target WorkflowTarget) {
			signalErr := engine.driver.Signal(ctx, WorkflowSignal{ContractVersion: WorkflowContractVersion,
				IdempotencyKey: "estop-" + strconv.FormatUint(request.Epoch, 10) + "-signal", Target: target,
				Kind: "emergency_stop", PayloadDigest: reasonDigest})
			cancelErr := engine.driver.Cancel(ctx, WorkflowCancel{ContractVersion: WorkflowContractVersion,
				IdempotencyKey: "estop-" + strconv.FormatUint(request.Epoch, 10) + "-cancel", Target: target,
				ReasonDigest: reasonDigest})
			if signalErr != nil {
				results <- result{target: target, err: signalErr}
				return
			}
			results <- result{target: target, err: cancelErr}
		}(target)
	}
	failed := false
	for range targets {
		select {
		case completed := <-results:
			if completed.err != nil {
				failed = true
			} else {
				if removeErr := engine.index.Remove(ctx, completed.target); removeErr != nil {
					failed = true
				}
			}
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if failed {
		return "", NewEngineError(EngineUnavailable, "estop", "workflow", "workflow containment failed", nil)
	}
	evidence, _ := json.Marshal(struct {
		Scope   stopcontract.Scope
		Epoch   uint64
		Targets []WorkflowTarget
	}{Scope: request.Scope, Epoch: request.Epoch, Targets: targets})
	return digestWorkflowBytes(evidence), nil
}

func (engine *GuardedEngine) allow(ctx context.Context, scope domain.CaseRef) error {
	if engine == nil || engine.stop == nil {
		return NewEngineError(EngineUnavailable, "estop", "guard", "stop state unavailable", nil)
	}
	err := engine.stop.Allow(ctx, scope.OrganizationID, scope.TenantID, scope.CaseID)
	if err == nil {
		return nil
	}
	switch stopcontract.Code(err) {
	case stopcontract.Denied:
		return NewEngineError(EngineDenied, "estop", "state", "emergency stop active", nil)
	case stopcontract.Canceled:
		return NewEngineError(EngineCanceled, "estop", "state", "stop check canceled", err)
	case stopcontract.Timeout:
		return NewEngineError(EngineTimeout, "estop", "state", "stop check timed out", err)
	default:
		return NewEngineError(EngineUnavailable, "estop", "state", "stop state unavailable", nil)
	}
}

func workflowTargetKey(target WorkflowTarget) string {
	return target.Case.OrganizationID + "\x00" + target.Case.TenantID + "\x00" + target.Case.CaseID + "\x00" +
		target.WorkflowID + "\x00" + target.RunID
}

func workflowStopRunKey(request stopcontract.ControlRequest) string {
	scope := request.Scope
	return scope.Kind + "\x00" + scope.OrganizationID + "\x00" + scope.TenantID + "\x00" + scope.CaseID +
		"\x00" + strconv.FormatUint(request.Epoch, 10)
}

func workflowStopDigest(scope domain.CaseRef, epoch uint64) string {
	value, _ := json.Marshal(struct {
		Scope domain.CaseRef
		Epoch uint64
	}{Scope: scope, Epoch: epoch})
	return digestWorkflowBytes(value)
}

func digestWorkflowBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

var _ Engine = (*GuardedEngine)(nil)
var _ interface {
	ID() string
	Kind() string
	Apply(context.Context, stopcontract.ControlRequest) (string, error)
} = (*GuardedEngine)(nil)
