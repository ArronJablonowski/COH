package schemacache

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
	Unavailable  ErrorCode = "unavailable"
	Conflict     ErrorCode = "conflict"
	Internal     ErrorCode = "internal"
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
	return fmt.Sprintf("schema cache %s: %s", err.Code, err.Reason)
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
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	return Unavailable
}

func Reason(err error) string {
	var target *Error
	if errors.As(err, &target) {
		return target.Reason
	}
	return "schema_cache_unavailable"
}

func mapLoaderError(err error) error {
	if err == nil {
		return nil
	}
	switch queryconnector.Code(err) {
	case queryconnector.InvalidInput:
		return newError(InvalidInput, "loader_invalid", err)
	case queryconnector.Denied, queryconnector.Unsupported:
		return newError(Denied, "loader_denied", err)
	case queryconnector.Canceled:
		return newError(Canceled, "loader_canceled", err)
	case queryconnector.Timeout:
		return newError(Timeout, "loader_timeout", err)
	case queryconnector.Conflict:
		return newError(Conflict, "loader_conflict", err)
	case queryconnector.Internal:
		return newError(Internal, "loader_internal", err)
	default:
		return newError(Unavailable, "loader_unavailable", err)
	}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_required", nil)
	}
	if err := ctx.Err(); errors.Is(err, context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", err)
	} else if err != nil {
		return newError(Canceled, "request_canceled", err)
	}
	return nil
}
