package toolregistry

import (
	"context"
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
)

type Error struct {
	Code   ErrorCode
	Reason string
}

func (err *Error) Error() string { return fmt.Sprintf("tool registry %s: %s", err.Code, err.Reason) }

func NewError(code ErrorCode, reason string) error { return &Error{Code: code, Reason: reason} }

func Code(err error) ErrorCode {
	var registryErr *Error
	if errors.As(err, &registryErr) {
		return registryErr.Code
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
	var registryErr *Error
	if errors.As(err, &registryErr) {
		return registryErr.Reason
	}
	return "registry_unavailable"
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
