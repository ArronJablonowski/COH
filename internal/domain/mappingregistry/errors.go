package mappingregistry

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInput     ErrorCode = "invalid_input"
	CanceledError    ErrorCode = "canceled"
	TimeoutError     ErrorCode = "timeout"
	DeniedError      ErrorCode = "denied"
	ConflictError    ErrorCode = "conflict"
	UnavailableError ErrorCode = "unavailable"
)

type RegistryError struct {
	code   ErrorCode
	reason Reason
	cause  error
}

func (err *RegistryError) Error() string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("mapping registry %s: %s", err.code, err.reason)
}
func (err *RegistryError) Unwrap() error { return err.cause }

func newError(code ErrorCode, reason Reason, cause error) error {
	return &RegistryError{code: code, reason: reason, cause: cause}
}

func Code(err error) ErrorCode {
	var target *RegistryError
	if errors.As(err, &target) {
		return target.code
	}
	return ""
}
func ErrorReason(err error) Reason {
	var target *RegistryError
	if errors.As(err, &target) {
		return target.reason
	}
	return ""
}
