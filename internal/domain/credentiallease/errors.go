package credentiallease

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

func (err *Error) Error() string { return fmt.Sprintf("credential lease %s: %s", err.Code, err.Reason) }
func (err *Error) Unwrap() error { return err.Cause }

func Code(err error) ErrorCode {
	var leaseErr *Error
	if errors.As(err, &leaseErr) {
		return leaseErr.Code
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	return Unavailable
}

func leaseError(code ErrorCode, reason string, cause error) error {
	return &Error{Code: code, Reason: reason, Cause: cause}
}

func errorReason(err error) string {
	var leaseErr *Error
	if errors.As(err, &leaseErr) {
		return leaseErr.Reason
	}
	return "credential_lease_unavailable"
}
