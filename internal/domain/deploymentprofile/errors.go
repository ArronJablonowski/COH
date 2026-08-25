package deploymentprofile

import (
	"context"
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
	Unavailable  ErrorCode = "unavailable"
)

type ValidationError struct {
	Code   ErrorCode
	Reason string
	Cause  error
}

func (err *ValidationError) Error() string {
	return fmt.Sprintf("deployment profile %s: %s", err.Code, err.Reason)
}

func (err *ValidationError) Unwrap() error { return err.Cause }

func Code(err error) ErrorCode {
	var validationErr *ValidationError
	if errors.As(err, &validationErr) {
		return validationErr.Code
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	return InvalidInput
}

func validationError(code ErrorCode, reason string, cause error) error {
	return &ValidationError{Code: code, Reason: reason, Cause: cause}
}
