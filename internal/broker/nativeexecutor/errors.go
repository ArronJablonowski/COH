package nativeexecutor

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	Conflict     ErrorCode = "conflict"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
	Unavailable  ErrorCode = "unavailable"
	Failed       ErrorCode = "failed"
)

type Error struct {
	Code   ErrorCode
	Reason string
}

func (err *Error) Error() string { return fmt.Sprintf("native executor %s: %s", err.Code, err.Reason) }

func NewError(code ErrorCode, reason string) error { return &Error{Code: code, Reason: reason} }

func Code(err error) ErrorCode {
	var nativeErr *Error
	if errors.As(err, &nativeErr) {
		return nativeErr.Code
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
	var nativeErr *Error
	if errors.As(err, &nativeErr) {
		return nativeErr.Reason
	}
	return "native_executor_unavailable"
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return NewError(InvalidInput, "context_required")
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return NewError(Timeout, "request_timeout")
		}
		return NewError(Canceled, "request_canceled")
	}
	return nil
}

func mapRegistryError(err error) error {
	switch toolregistry.Code(err) {
	case toolregistry.InvalidInput:
		return NewError(InvalidInput, "registry_"+toolregistry.Reason(err))
	case toolregistry.Canceled:
		return NewError(Canceled, "request_canceled")
	case toolregistry.Timeout:
		return NewError(Timeout, "request_timeout")
	case toolregistry.Unavailable:
		return NewError(Unavailable, "registry_"+toolregistry.Reason(err))
	default:
		return NewError(Denied, "registry_"+toolregistry.Reason(err))
	}
}

func mapAuthorizationError(err error) error {
	if contextErr := contextErrorFromCause(err); contextErr != nil {
		return contextErr
	}
	var nativeErr *Error
	if errors.As(err, &nativeErr) {
		return err
	}
	return NewError(Unavailable, "authorization_unavailable")
}

func contextErrorFromCause(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return NewError(Timeout, "request_timeout")
	}
	if errors.Is(err, context.Canceled) {
		return NewError(Canceled, "request_canceled")
	}
	return nil
}
