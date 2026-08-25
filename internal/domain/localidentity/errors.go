package localidentity

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

type IdentityError struct {
	Code   ErrorCode
	Reason string
	Cause  error
}

func (err *IdentityError) Error() string {
	return fmt.Sprintf("local identity %s: %s", err.Code, err.Reason)
}

func (err *IdentityError) Unwrap() error { return err.Cause }

func Code(err error) ErrorCode {
	var identityErr *IdentityError
	if errors.As(err, &identityErr) {
		return identityErr.Code
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	return Unavailable
}

func identityError(code ErrorCode, reason string, cause error) error {
	return &IdentityError{Code: code, Reason: reason, Cause: cause}
}
