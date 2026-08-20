package supplychain

import (
	"context"
	"errors"
	"fmt"
)

type ErrorCode string

const (
	CodeInvalidInput ErrorCode = "invalid_input"
	CodeDenied       ErrorCode = "denied"
	CodeToolFailure  ErrorCode = "tool_failure"
	CodeCanceled     ErrorCode = "canceled"
	CodeTimeout      ErrorCode = "timeout"
)

type Error struct {
	Code   ErrorCode
	Field  string
	Detail string
	Cause  error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("supplychain: %s: %s: %s", e.Code, e.Field, e.Detail)
}

func (e *Error) Unwrap() error { return e.Cause }

func errorf(code ErrorCode, field, detail string, cause error) error {
	return &Error{Code: code, Field: field, Detail: detail, Cause: cause}
}

func contextError(err error, field string) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return errorf(CodeTimeout, field, "operation timed out", err)
	}
	return errorf(CodeCanceled, field, "operation canceled", err)
}

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
	}
	return CodeToolFailure
}
