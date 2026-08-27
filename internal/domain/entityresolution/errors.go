package entityresolution

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInputError ErrorCode = "invalid_input"
	CanceledError     ErrorCode = "canceled"
	TimeoutError      ErrorCode = "timeout"
	DeniedError       ErrorCode = "denied"
	ConflictError     ErrorCode = "conflict"
	UnavailableError  ErrorCode = "unavailable"
)

type ResolutionError struct {
	code   ErrorCode
	reason Reason
	cause  error
}

func (err *ResolutionError) Error() string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("entity resolution %s: %s", err.code, err.reason)
}

func (err *ResolutionError) Unwrap() error { return err.cause }

func newError(code ErrorCode, reason Reason, cause error) error {
	return &ResolutionError{code: code, reason: reason, cause: cause}
}

func Code(err error) ErrorCode {
	var target *ResolutionError
	if errors.As(err, &target) {
		return target.code
	}
	return ""
}

func ErrorReason(err error) Reason {
	var target *ResolutionError
	if errors.As(err, &target) {
		return target.reason
	}
	return ""
}
