package queryevidence

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
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
	return fmt.Sprintf("query evidence %s: %s", err.Code, err.Reason)
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
	return "query_evidence_unavailable"
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_required", nil)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", ctx.Err())
	}
	if ctx.Err() != nil {
		return newError(Canceled, "request_canceled", ctx.Err())
	}
	return nil
}

func dependencyError(ctx context.Context, reason string, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newError(Timeout, reason, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return newError(Canceled, reason, err)
	}
	return newError(Unavailable, reason, err)
}

func ingestError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	switch evidenceingest.CodeOf(err) {
	case evidenceingest.InvalidInput:
		return newError(InvalidInput, "native_query_ingest_invalid", err)
	case evidenceingest.Denied, evidenceingest.NotFound:
		return newError(Denied, "native_query_ingest_denied", err)
	case evidenceingest.Conflict:
		return newError(Conflict, "native_query_ingest_conflict", err)
	case evidenceingest.Canceled:
		return newError(Canceled, "native_query_ingest_canceled", err)
	case evidenceingest.Timeout:
		return newError(Timeout, "native_query_ingest_timeout", err)
	case evidenceingest.InternalFailure:
		return newError(Internal, "native_query_ingest_internal", err)
	default:
		return dependencyError(ctx, "native_query_ingest_unavailable", err)
	}
}
