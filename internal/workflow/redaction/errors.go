package redaction

import (
	"context"
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInput    ErrorCode = "invalid_input"
	Denied          ErrorCode = "denied"
	NotFound        ErrorCode = "not_found"
	Conflict        ErrorCode = "conflict"
	Canceled        ErrorCode = "canceled"
	Timeout         ErrorCode = "timeout"
	Unavailable     ErrorCode = "unavailable"
	InternalFailure ErrorCode = "internal_failure"
)

type Error struct {
	Code      ErrorCode
	Reason    string
	Retryable bool
	cause     error
}

func (err *Error) Error() string {
	return fmt.Sprintf("redaction %s: %s", err.Code, err.Reason)
}

func (err *Error) Unwrap() error { return err.cause }

func newError(code ErrorCode, reason string, retryable bool, cause error) error {
	return &Error{Code: code, Reason: reason, Retryable: retryable, cause: cause}
}

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Code
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
	var typed *Error
	if errors.As(err, &typed) {
		return typed.Reason
	}
	return "dependency_unavailable"
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_required", false, nil)
	}
	if err := ctx.Err(); errors.Is(err, context.DeadlineExceeded) {
		return newError(Timeout, "context_timeout", true, nil)
	} else if err != nil {
		return newError(Canceled, "context_canceled", false, nil)
	}
	return nil
}
