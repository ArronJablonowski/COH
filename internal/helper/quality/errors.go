package quality

import (
	"errors"
	"fmt"
)

// ErrorCode is a stable machine-readable quality-gate failure class.
type ErrorCode string

const (
	CodeInvalidInput ErrorCode = "invalid_input"
	CodeDenied       ErrorCode = "denied"
	CodeTimeout      ErrorCode = "timeout"
	CodeCanceled     ErrorCode = "canceled"
	CodeToolFailure  ErrorCode = "tool_failure"
)

// Error preserves a safe code and field without exposing command output.
type Error struct {
	Code   ErrorCode
	Field  string
	Detail string
	Cause  error
}

func (e *Error) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Detail)
	}
	return fmt.Sprintf("%s: %s: %s", e.Code, e.Field, e.Detail)
}

func (e *Error) Unwrap() error { return e.Cause }

func qualityError(code ErrorCode, field, detail string, cause error) error {
	return &Error{Code: code, Field: field, Detail: detail, Cause: cause}
}

// CodeOf maps unknown errors to tool_failure and preserves typed causes.
func CodeOf(err error) ErrorCode {
	var qualityErr *Error
	if errors.As(err, &qualityErr) {
		return qualityErr.Code
	}
	return CodeToolFailure
}
