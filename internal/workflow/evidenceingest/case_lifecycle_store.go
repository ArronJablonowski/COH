package evidenceingest

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/caselifecycle"
)

type lifecycleLoader interface {
	Load(context.Context, domain.CaseRef) (caselifecycle.Record, bool, error)
}

// CaseLifecycleStore narrows the lifecycle repository to the immutable state
// needed for one ingestion authorization decision.
type CaseLifecycleStore struct{ lifecycle lifecycleLoader }

func NewCaseLifecycleStore(lifecycle lifecycleLoader) (*CaseLifecycleStore, error) {
	if lifecycle == nil {
		return nil, newError(InvalidInput, "case_lifecycle_required", false, nil)
	}
	return &CaseLifecycleStore{lifecycle: lifecycle}, nil
}

func (store *CaseLifecycleStore) LoadCase(ctx context.Context,
	scope domain.CaseRef) (CaseSnapshot, bool, error) {
	if err := contextError(ctx); err != nil {
		return CaseSnapshot{}, false, err
	}
	record, found, err := store.lifecycle.Load(ctx, scope)
	if err != nil {
		return CaseSnapshot{}, false, mapLifecycleError(err)
	}
	if !found {
		return CaseSnapshot{}, false, nil
	}
	return CaseSnapshot{Case: record.Case, Revision: record.Revision, State: string(record.State),
		Classification: string(record.Classification), ProvenanceDigest: record.ProvenanceDigest}, true, nil
}

func mapLifecycleError(err error) error {
	switch caselifecycle.CodeOf(err) {
	case caselifecycle.InvalidInput:
		return newError(InvalidInput, "case_lifecycle_invalid", false, err)
	case caselifecycle.Denied:
		return newError(Denied, "case_lifecycle_denied", false, err)
	case caselifecycle.NotFound:
		return newError(NotFound, "case_lifecycle_not_found", false, err)
	case caselifecycle.Conflict:
		return newError(Conflict, "case_lifecycle_conflict", false, err)
	case caselifecycle.Canceled:
		return newError(Canceled, "case_lifecycle_canceled", false, err)
	case caselifecycle.Timeout:
		return newError(Timeout, "case_lifecycle_timeout", false, err)
	default:
		return newError(Unavailable, "case_lifecycle_unavailable", true, err)
	}
}

var _ CaseStore = (*CaseLifecycleStore)(nil)
