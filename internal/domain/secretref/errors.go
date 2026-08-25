package secretref

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
)

type Error struct {
	Code   ErrorCode
	Reason string
	Cause  error
}

func (err *Error) Error() string { return fmt.Sprintf("secret reference %s: %s", err.Code, err.Reason) }
func (err *Error) Unwrap() error { return err.Cause }

func Code(err error) ErrorCode {
	var secretErr *Error
	if errors.As(err, &secretErr) {
		return secretErr.Code
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	return Unavailable
}

func secretError(code ErrorCode, reason string, cause error) error {
	return &Error{Code: code, Reason: reason, Cause: cause}
}

func errorReason(err error) string {
	var secretErr *Error
	if errors.As(err, &secretErr) {
		return secretErr.Reason
	}
	return "secret_reference_unavailable"
}
