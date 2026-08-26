package workflow

import (
	"context"
	"sync"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

type MemoryWorkflowIndex struct {
	mu      sync.Mutex
	targets map[string]WorkflowTarget
}

func NewMemoryWorkflowIndex() *MemoryWorkflowIndex {
	return &MemoryWorkflowIndex{targets: make(map[string]WorkflowTarget)}
}

func (index *MemoryWorkflowIndex) Add(ctx context.Context, target WorkflowTarget) error {
	if err := workflowIndexInput(ctx, target); err != nil {
		return err
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	index.targets[workflowTargetKey(target)] = target
	return nil
}

func (index *MemoryWorkflowIndex) Remove(ctx context.Context, target WorkflowTarget) error {
	if err := workflowIndexInput(ctx, target); err != nil {
		return err
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	delete(index.targets, workflowTargetKey(target))
	return nil
}

func (index *MemoryWorkflowIndex) List(ctx context.Context, scope stopcontract.Scope) ([]WorkflowTarget, error) {
	if ctx == nil || ctx.Err() != nil || stopcontract.ValidateScope(scope) != nil {
		return nil, NewEngineError(EngineInvalidInput, "workflow_index", "scope", "valid scope and context required", nil)
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	result := make([]WorkflowTarget, 0)
	for _, target := range index.targets {
		if target.Case.OrganizationID == scope.OrganizationID && target.Case.TenantID == scope.TenantID &&
			(scope.Kind == "global" || target.Case.CaseID == scope.CaseID) {
			result = append(result, target)
		}
	}
	return result, nil
}

func workflowIndexInput(ctx context.Context, target WorkflowTarget) error {
	if ctx == nil || ctx.Err() != nil || validateWorkflowTarget("workflow_index", target) != nil {
		return NewEngineError(EngineInvalidInput, "workflow_index", "target", "valid target and context required", nil)
	}
	return nil
}

var _ WorkflowIndex = (*MemoryWorkflowIndex)(nil)
