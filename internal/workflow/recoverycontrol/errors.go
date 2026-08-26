package recoverycontrol

import (
	"context"
	"errors"
)

type Code string

const (
	InvalidInput Code = "invalid_input"
	DeniedCode   Code = "denied"
	Conflict     Code = "conflict"
	CanceledCode Code = "canceled"
	Timeout      Code = "timeout"
	Unavailable  Code = "unavailable"
	Internal     Code = "internal"
)

type Error struct {
	code          Code
	reason        string
	retryable     bool
	indeterminate bool
	cause         error
}

func (value *Error) Error() string {
	return "recovery control " + string(value.code) + ": " + value.reason
}
func (value *Error) Unwrap() error       { return value.cause }
func (value *Error) Indeterminate() bool { return value.indeterminate }

func newError(code Code, reason string, retryable, indeterminate bool, cause error) error {
	return &Error{code: code, reason: reason, retryable: retryable, indeterminate: indeterminate, cause: cause}
}

// NewDependencyError lets narrow adapters report a typed, redacted outcome.
// The reason must be a bounded token; raw dependency errors are never stored.
func NewDependencyError(code Code, reason string, retryable, indeterminate bool) error {
	if !tokenPattern.MatchString(reason) || code != DeniedCode && code != Conflict && code != CanceledCode && code != Timeout &&
		code != Unavailable && code != Internal {
		return newError(Internal, "dependency_error_invalid", false, true, nil)
	}
	return newError(code, reason, retryable, indeterminate, nil)
}

func ErrorCode(err error) Code {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	if errors.Is(err, context.Canceled) {
		return CanceledCode
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	return Unavailable
}

func ErrorReason(err error) string {
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

func Indeterminate(err error) bool {
	var classified interface{ Indeterminate() bool }
	return !errors.As(err, &classified) || classified.Indeterminate()
}

func mapContext(err error) error {
	if errors.Is(err, context.Canceled) {
		return newError(CanceledCode, "request_canceled", false, false, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", false, false, context.DeadlineExceeded)
	}
	return newError(Unavailable, "dependency_unavailable", true, true, nil)
}
