package broker

import (
	"context"
	"errors"
	"time"

	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

const auditTimeout = 5 * time.Second

func contextError(ctx context.Context) error {
	if ctx == nil {
		return lifecycle.NewError(lifecycle.InvalidInput, "context_required")
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return lifecycle.NewError(lifecycle.Timeout, "request_timeout")
		}
		return lifecycle.NewError(lifecycle.Canceled, "request_canceled")
	}
	return nil
}

func mapStorageError(err error) error {
	switch workflow.StorageCode(err) {
	case workflow.StorageInvalidInput:
		return lifecycle.NewError(lifecycle.InvalidInput, "storage_input")
	case workflow.StorageDenied:
		return lifecycle.NewError(lifecycle.Denied, "storage_denied")
	case workflow.StorageNotFound:
		return lifecycle.NewError(lifecycle.NotFound, "approval_not_found")
	case workflow.StorageConflict:
		return lifecycle.NewError(lifecycle.Conflict, "optimistic_conflict")
	case workflow.StorageCanceled:
		return lifecycle.NewError(lifecycle.Canceled, "request_canceled")
	case workflow.StorageTimeout:
		return lifecycle.NewError(lifecycle.Timeout, "request_timeout")
	default:
		return lifecycle.NewError(lifecycle.Unavailable, "storage_unavailable")
	}
}

func auditContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
}
