package workflow

import (
	"context"
	"errors"
	"fmt"
)

type EngineErrorCode string

const (
	EngineInvalidInput EngineErrorCode = "invalid_input"
	EngineDenied       EngineErrorCode = "denied"
	EngineNotFound     EngineErrorCode = "not_found"
	EngineConflict     EngineErrorCode = "conflict"
	EngineCanceled     EngineErrorCode = "canceled"
	EngineTimeout      EngineErrorCode = "timeout"
	EngineUnavailable  EngineErrorCode = "unavailable"
)

type EngineError struct {
	Code      EngineErrorCode
	Operation string
	Field     string
	Detail    string
	Cause     error
}

func (err *EngineError) Error() string {
	if err.Field == "" {
		return fmt.Sprintf("workflow engine %s: %s", err.Code, err.Detail)
	}
	return fmt.Sprintf("workflow engine %s: %s: %s", err.Code, err.Field, err.Detail)
}

func (err *EngineError) Unwrap() error { return err.Cause }

func NewEngineError(code EngineErrorCode, operation, field, detail string, cause error) error {
	return &EngineError{Code: code, Operation: operation, Field: field, Detail: detail, Cause: cause}
}

func EngineCode(err error) EngineErrorCode {
	var engineErr *EngineError
	if errors.As(err, &engineErr) {
		return engineErr.Code
	}
	if errors.Is(err, context.Canceled) {
		return EngineCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return EngineTimeout
	}
	return EngineUnavailable
}
