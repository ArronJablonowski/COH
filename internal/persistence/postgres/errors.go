package postgres

import (
	"context"
	"errors"

	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func storageError(code workflow.StorageErrorCode, operation, field, detail string) error {
	return workflow.NewStorageError(code, operation, field, detail, nil)
}

func contextError(ctx context.Context, operation string) error {
	if ctx == nil {
		return storageError(workflow.StorageInvalidInput, operation, "context", "context is required")
	}
	return normalizeError(operation, "context", ctx.Err())
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
	if errors.Is(err, pgx.ErrNoRows) {
		return storageError(workflow.StorageNotFound, operation, field, "record not found")
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505", "40001", "40P01", "55P03":
			return storageError(workflow.StorageConflict, operation, field, "PostgreSQL concurrency conflict")
		case "42501":
			return storageError(workflow.StorageDenied, operation, field, "PostgreSQL policy denied the operation")
		case "57014":
			return storageError(workflow.StorageTimeout, operation, field, "PostgreSQL canceled the operation")
		}
	}
	return storageError(workflow.StorageUnavailable, operation, field, "PostgreSQL operation failed")
}
