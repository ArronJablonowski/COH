package agentloop

import "github.com/ArronJablonowski/COH/internal/workflow/runbudget"

func mapBudgetError(operation string, err error) error {
	switch runbudget.ErrorCode(err) {
	case runbudget.InvalidInput:
		return newError(InvalidInput, operation, runbudget.ErrorReason(err), false, nil)
	case runbudget.Denied:
		return newError(Denied, operation, runbudget.ErrorReason(err), false, nil)
	case runbudget.Conflict:
		return newError(Conflict, operation, runbudget.ErrorReason(err), runbudget.Retryable(err), nil)
	case runbudget.Canceled:
		return newError(Canceled, operation, runbudget.ErrorReason(err), false, err)
	case runbudget.Timeout:
		return newError(Timeout, operation, runbudget.ErrorReason(err), false, err)
	case runbudget.Internal:
		return newError(Internal, operation, runbudget.ErrorReason(err), false, nil)
	default:
		return newError(Unavailable, operation, runbudget.ErrorReason(err), runbudget.Retryable(err), nil)
	}
}
