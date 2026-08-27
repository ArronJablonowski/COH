package temporaltime

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInput  ErrorCode = "invalid_input"
	Canceled      ErrorCode = "canceled"
	Timeout       ErrorCode = "timeout"
	Unavailable   ErrorCode = "unavailable"
	DeniedError   ErrorCode = "denied"
	ConflictError ErrorCode = "conflict"
)

type DomainError struct {
	code   ErrorCode
	reason Reason
	cause  error
}

func (err *DomainError) Error() string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("temporal time %s: %s", err.code, err.reason)
}

func (err *DomainError) Unwrap() error { return err.cause }

func newError(code ErrorCode, reason Reason, cause error) error {
	return &DomainError{code: code, reason: reason, cause: cause}
}

func Code(err error) ErrorCode {
	var target *DomainError
	if errors.As(err, &target) {
		return target.code
	}
	return ""
}

func ErrorReason(err error) Reason {
	var target *DomainError
	if errors.As(err, &target) {
		return target.reason
	}
	return ""
}
