// Package filesize enforces the versioned COH physical-line policy.
package filesize

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

type ErrorCode string

const (
	CodeToolFailure  ErrorCode = "tool_failure"
	CodeDenied       ErrorCode = "denied"
	CodeInvalidInput ErrorCode = "invalid_input"
	CodeTimeout      ErrorCode = "timeout"
	CodeCanceled     ErrorCode = "canceled"
)

type ContractError struct {
	Code   ErrorCode
	Field  string
	Detail string
	Cause  error
}

func (err *ContractError) Error() string {
	if err.Field == "" {
		return fmt.Sprintf("%s: %s", err.Code, err.Detail)
	}
	field := err.Field
	if len(field) > 256 {
		field = field[:256] + "..."
	}
	return fmt.Sprintf("%s: %s: %s", err.Code, strconv.Quote(field), err.Detail)
}

func (err *ContractError) Unwrap() error { return err.Cause }

func contractError(code ErrorCode, field, detail string, cause error) error {
	return &ContractError{Code: code, Field: field, Detail: detail, Cause: cause}
}

func CodeOf(err error) ErrorCode {
	var contractErr *ContractError
	if errors.As(err, &contractErr) {
		return contractErr.Code
	}
	if errors.Is(err, context.Canceled) {
		return CodeCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return CodeTimeout
	}
	return CodeToolFailure
}

func contextError(err error, field string) error {
	switch {
	case errors.Is(err, context.Canceled):
		return contractError(CodeCanceled, field, "operation canceled", err)
	case errors.Is(err, context.DeadlineExceeded):
		return contractError(CodeTimeout, field, "deadline exceeded", err)
	default:
		return contractError(CodeToolFailure, field, "context failed", err)
	}
}
