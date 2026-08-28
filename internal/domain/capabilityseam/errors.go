package capabilityseam

import (
	"context"
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	Unsupported  ErrorCode = "unsupported"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
)

type Error struct {
	Code   ErrorCode
	Reason string
}

func (err *Error) Error() string {
	return fmt.Sprintf("capability seam %s: %s", err.Code, err.Reason)
}

func newError(code ErrorCode, reason string) error {
	return &Error{Code: code, Reason: reason}
}

func Code(err error) ErrorCode {
	var contractErr *Error
	if errors.As(err, &contractErr) {
		return contractErr.Code
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	return Denied
}

func Reason(err error) string {
	var contractErr *Error
	if errors.As(err, &contractErr) {
		return contractErr.Reason
	}
	return "capability_seam_denied"
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_required")
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return newError(Timeout, "context_deadline")
		}
		return newError(Canceled, "context_canceled")
	}
	return nil
}
