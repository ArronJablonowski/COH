package subagentdag

import (
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	NotFound     ErrorCode = "not_found"
	Conflict     ErrorCode = "conflict"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
	Unavailable  ErrorCode = "unavailable"
	Internal     ErrorCode = "internal"
)

type Error struct {
	code      ErrorCode
	reason    string
	retryable bool
	cause     error
}

func (err *Error) Error() string {
	if err.cause == nil {
		return fmt.Sprintf("subagent DAG %s: %s", err.code, err.reason)
	}
	return fmt.Sprintf("subagent DAG %s: %s: %v", err.code, err.reason, err.cause)
}
func (err *Error) Unwrap() error { return err.cause }

func newError(code ErrorCode, reason string, retryable bool, cause error) error {
	return &Error{code: code, reason: reason, retryable: retryable, cause: cause}
}
func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return Unavailable
}
func Reason(err error) string {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.reason
	}
	return "dependency_unavailable"
}
func Retryable(err error) bool {
	var typed *Error
	return errors.As(err, &typed) && typed.retryable
}
