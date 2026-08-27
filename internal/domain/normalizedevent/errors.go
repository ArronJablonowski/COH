package normalizedevent

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
	Unavailable  ErrorCode = "unavailable"
	Conflict     ErrorCode = "conflict"
)

type ContractError struct {
	code   ErrorCode
	reason string
	cause  error
}

func (err *ContractError) Error() string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("normalized event %s: %s", err.code, err.reason)
}

func (err *ContractError) Unwrap() error { return err.cause }

func newError(code ErrorCode, reason string, cause error) error {
	return &ContractError{code: code, reason: reason, cause: cause}
}

func Code(err error) ErrorCode {
	var target *ContractError
	if errors.As(err, &target) {
		return target.code
	}
	return ""
}

func Reason(err error) string {
	var target *ContractError
	if errors.As(err, &target) {
		return target.reason
	}
	return ""
}
