package agentloop

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/workflow/memorynamespace"
)

const MemoryLookupActivityName = "coh.agent-loop.memory-lookup.v1"

// BoundedMemoryLookup deliberately exposes read only. The memory controller
// retains namespace, policy, retention, review, and provenance enforcement.
type BoundedMemoryLookup interface {
	Get(context.Context, memorynamespace.GetRequest) (memorynamespace.Result, error)
}

type MemoryLookupActivity struct{ memory BoundedMemoryLookup }

func NewMemoryLookupActivity(memory BoundedMemoryLookup) (*MemoryLookupActivity, error) {
	if memory == nil {
		return nil, newError(InvalidInput, "memory_lookup", "dependency_required", false, nil)
	}
	return &MemoryLookupActivity{memory: memory}, nil
}

func (activity *MemoryLookupActivity) Lookup(ctx context.Context,
	request memorynamespace.GetRequest) (memorynamespace.Result, error) {
	if activity == nil || activity.memory == nil {
		return memorynamespace.Result{}, newError(Unavailable, "memory_lookup", "activity_unavailable", true, nil)
	}
	result, err := activity.memory.Get(ctx, request)
	if err != nil {
		return memorynamespace.Result{}, mapMemoryError(err)
	}
	return result, nil
}

func mapMemoryError(err error) error {
	switch memorynamespace.CodeOf(err) {
	case memorynamespace.InvalidInput:
		return newError(InvalidInput, "memory_lookup", "request_invalid", false, err)
	case memorynamespace.Denied:
		return newError(Denied, "memory_lookup", "memory_denied", false, err)
	case memorynamespace.NotFound:
		return newError(NotFound, "memory_lookup", "memory_not_found", false, err)
	case memorynamespace.Conflict:
		return newError(Conflict, "memory_lookup", "memory_conflict", false, err)
	case memorynamespace.Canceled:
		return newError(Canceled, "memory_lookup", "memory_canceled", false, err)
	case memorynamespace.Timeout:
		return newError(Timeout, "memory_lookup", "memory_timeout", false, err)
	default:
		return newError(Unavailable, "memory_lookup", "memory_unavailable",
			memorynamespace.Retryable(err), err)
	}
}
