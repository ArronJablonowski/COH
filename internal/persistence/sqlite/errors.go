package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/ArronJablonowski/COH/internal/workflow"
)

func storageError(code workflow.StorageErrorCode, operation, field, detail string) error {
	return workflow.NewStorageError(code, operation, field, detail, nil)
}

func contextError(ctx context.Context, operation string) error {
	if ctx == nil {
		return storageError(workflow.StorageInvalidInput, operation, "context", "context is required")
	}
	if err := ctx.Err(); err != nil {
		return normalizeError(operation, "context", err)
	}
	return nil
}

func normalizeError(operation, field string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return workflow.NewStorageError(workflow.StorageCanceled, operation, field, "operation canceled", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return workflow.NewStorageError(workflow.StorageTimeout, operation, field, "operation timed out", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return storageError(workflow.StorageNotFound, operation, field, "record not found")
	}
	return storageError(workflow.StorageUnavailable, operation, field, "SQLite operation failed")
}
