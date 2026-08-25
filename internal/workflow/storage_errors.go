package workflow

import (
	"context"
	"errors"
	"fmt"
)

type StorageErrorCode string

const (
	StorageInvalidInput StorageErrorCode = "invalid_input"
	StorageDenied       StorageErrorCode = "denied"
	StorageNotFound     StorageErrorCode = "not_found"
	StorageConflict     StorageErrorCode = "conflict"
	StorageCanceled     StorageErrorCode = "canceled"
	StorageTimeout      StorageErrorCode = "timeout"
	StorageUnavailable  StorageErrorCode = "unavailable"
)

// StorageError is safe to return across workflow boundaries. Error omits Cause
// so a database message, query, credential, or record value cannot leak.
type StorageError struct {
	Code      StorageErrorCode
	Operation string
	Field     string
	Detail    string
	Cause     error
}

func (err *StorageError) Error() string {
	if err.Field == "" {
		return fmt.Sprintf("storage %s: %s", err.Code, err.Detail)
	}
	return fmt.Sprintf("storage %s: %s: %s", err.Code, err.Field, err.Detail)
}

func (err *StorageError) Unwrap() error { return err.Cause }

func NewStorageError(code StorageErrorCode, operation, field, detail string, cause error) error {
	return &StorageError{Code: code, Operation: operation, Field: field, Detail: detail, Cause: cause}
}

func StorageCode(err error) StorageErrorCode {
	var storageErr *StorageError
	if errors.As(err, &storageErr) {
		return storageErr.Code
	}
	if errors.Is(err, context.Canceled) {
		return StorageCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return StorageTimeout
	}
	return StorageUnavailable
}

func storageContextError(operation string, err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return NewStorageError(StorageTimeout, operation, "context", "operation timed out", err)
	}
	return NewStorageError(StorageCanceled, operation, "context", "operation canceled", err)
}

func normalizeStorageError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return storageContextError(operation, err)
	}
	var storageErr *StorageError
	if errors.As(err, &storageErr) {
		return err
	}
	return NewStorageError(StorageUnavailable, operation, "driver", "storage driver failed", nil)
}
