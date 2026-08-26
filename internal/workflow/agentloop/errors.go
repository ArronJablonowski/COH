package agentloop

import (
	"context"
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	NotFound     ErrorCode = "not_found"
	Conflict     ErrorCode = "conflict"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
	Unavailable  ErrorCode = "unavailable"
	Internal     ErrorCode = "internal"
)

type Error struct {
	Code      ErrorCode
	Operation string
	Reason    string
	Retryable bool
	Cause     error
}

func (value *Error) Error() string {
	return fmt.Sprintf("agent loop %s: %s", value.Code, value.Reason)
}

func (value *Error) Unwrap() error { return value.Cause }

func newError(code ErrorCode, operation, reason string, retryable bool, cause error) error {
	return &Error{Code: code, Operation: operation, Reason: reason, Retryable: retryable, Cause: cause}
}

func Code(err error) ErrorCode {
	var loopError *Error
	if errors.As(err, &loopError) {
		return loopError.Code
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	return Unavailable
}

func Reason(err error) string {
	var loopError *Error
	if errors.As(err, &loopError) {
		return loopError.Reason
	}
	return "activity_unavailable"
}

func Retryable(err error) bool {
	var loopError *Error
	return errors.As(err, &loopError) && loopError.Retryable
}
