package encryptedcas

import (
	"context"
	"errors"
)

type Code string

const (
	InvalidInput Code = "invalid_input"
	Denied       Code = "denied"
	Conflict     Code = "conflict"
	Canceled     Code = "canceled"
	Timeout      Code = "timeout"
	Unavailable  Code = "unavailable"
)

type Error struct {
	code   Code
	reason string
	cause  error
}

func (value *Error) Error() string {
	return "encrypted CAS " + string(value.code) + ": " + value.reason
}
func (value *Error) Unwrap() error     { return value.cause }
func (value *Error) ErrorCode() string { return string(value.code) }

func newError(code Code, reason string, cause error) error {
	return &Error{code: code, reason: reason, cause: cause}
}

func CodeOf(err error) Code {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
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

func contextError(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_required", nil)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return newError(Canceled, "request_canceled", context.Canceled)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", context.DeadlineExceeded)
	}
	return nil
}
