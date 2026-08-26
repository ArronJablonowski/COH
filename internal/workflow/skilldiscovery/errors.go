package skilldiscovery

import (
	"context"
	"errors"
)

type Code string

const (
	InvalidInput Code = "invalid_input"
	Denied       Code = "denied"
	NotFound     Code = "not_found"
	Conflict     Code = "conflict"
	Canceled     Code = "canceled"
	Timeout      Code = "timeout"
	Unavailable  Code = "unavailable"
	Internal     Code = "internal"
)

type Error struct {
	code      Code
	reason    string
	retryable bool
	cause     error
}

func (value *Error) Error() string {
	return "skill discovery " + string(value.code) + ": " + value.reason
}
func (value *Error) Unwrap() error { return value.cause }

func newError(code Code, reason string, retryable bool, cause error) error {
	return &Error{code: code, reason: reason, retryable: retryable, cause: cause}
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

func Retryable(err error) bool {
	var typed *Error
	return errors.As(err, &typed) && typed.retryable
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_required", false, nil)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return newError(Canceled, "request_canceled", false, context.Canceled)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", false, context.DeadlineExceeded)
	}
	return nil
}
