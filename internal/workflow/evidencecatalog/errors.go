package evidencecatalog

import (
	"context"
	"errors"

	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func lifecycleError(code evidencelifecycle.ErrorCode, reason string, retryable bool) error {
	return &evidencelifecycle.Error{Code: code, Reason: reason, Retryable: retryable}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return lifecycleError(evidencelifecycle.InvalidInput, "catalog_context_invalid", false)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return lifecycleError(evidencelifecycle.Canceled, "catalog_canceled", false)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return lifecycleError(evidencelifecycle.Timeout, "catalog_timeout", true)
	}
	return nil
}

func ingestionError(err error, reason string) error {
	switch evidenceingest.CodeOf(err) {
	case evidenceingest.InvalidInput:
		return lifecycleError(evidencelifecycle.InvalidInput, reason+"_invalid", false)
	case evidenceingest.Denied:
		return lifecycleError(evidencelifecycle.Denied, reason+"_denied", false)
	case evidenceingest.NotFound:
		return lifecycleError(evidencelifecycle.NotFound, reason+"_not_found", false)
	case evidenceingest.Conflict:
		return lifecycleError(evidencelifecycle.Conflict, reason+"_conflict", true)
	case evidenceingest.Canceled:
		return lifecycleError(evidencelifecycle.Canceled, reason+"_canceled", false)
	case evidenceingest.Timeout:
		return lifecycleError(evidencelifecycle.Timeout, reason+"_timeout", true)
	default:
		return lifecycleError(evidencelifecycle.Unavailable, reason+"_unavailable", true)
	}
}

func storageError(err error, reason string) error {
	switch workflowbase.StorageCode(err) {
	case workflowbase.StorageInvalidInput:
		return lifecycleError(evidencelifecycle.InvalidInput, reason+"_invalid", false)
	case workflowbase.StorageDenied:
		return lifecycleError(evidencelifecycle.Denied, reason+"_denied", false)
	case workflowbase.StorageNotFound:
		return lifecycleError(evidencelifecycle.NotFound, reason+"_not_found", false)
	case workflowbase.StorageConflict:
		return lifecycleError(evidencelifecycle.Conflict, reason+"_conflict", true)
	case workflowbase.StorageCanceled:
		return lifecycleError(evidencelifecycle.Canceled, reason+"_canceled", false)
	case workflowbase.StorageTimeout:
		return lifecycleError(evidencelifecycle.Timeout, reason+"_timeout", true)
	default:
		return lifecycleError(evidencelifecycle.Unavailable, reason+"_unavailable", true)
	}
}
