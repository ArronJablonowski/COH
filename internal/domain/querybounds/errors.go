package querybounds

import (
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
	Conflict     ErrorCode = "conflict"
)

type Error struct {
	Code   ErrorCode
	Reason string
	cause  error
}

func (err *Error) Error() string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("query bounds %s: %s", err.Code, err.Reason)
}

func (err *Error) Unwrap() error { return err.cause }

func newError(code ErrorCode, reason string, cause error) error {
	return &Error{Code: code, Reason: reason, cause: cause}
}

func Code(err error) ErrorCode {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return ""
}

func Reason(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.Reason
	}
	return ""
}
