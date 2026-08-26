package agentphase

import (
	"context"
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
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
	return fmt.Sprintf("agent phase %s: %s", value.Code, value.Reason)
}
func (value *Error) Unwrap() error           { return value.Cause }
func (value *Error) ActivityOutcome() string { return string(value.Code) }

func newError(code ErrorCode, operation, reason string, retryable bool, cause error) error {
	return &Error{Code: code, Operation: operation, Reason: reason, Retryable: retryable, Cause: cause}
}

func Code(err error) ErrorCode {
	var phaseError *Error
	if errors.As(err, &phaseError) {
		return phaseError.Code
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
	var phaseError *Error
	if errors.As(err, &phaseError) {
		return phaseError.Reason
	}
	return "dependency_unavailable"
}
