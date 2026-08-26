package providercontract

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
	Unavailable  ErrorCode = "unavailable"
	Conflict     ErrorCode = "conflict"
	Internal     ErrorCode = "internal"
)

type Error struct {
	Code   ErrorCode
	Reason string
}

func (err *Error) Error() string {
	return fmt.Sprintf("provider contract %s: %s", err.Code, err.Reason)
}

func NewError(code ErrorCode, reason string) error { return &Error{Code: code, Reason: reason} }

func Code(err error) ErrorCode {
	var contractErr *Error
	if errors.As(err, &contractErr) {
		return contractErr.Code
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
	var contractErr *Error
	if errors.As(err, &contractErr) {
		return contractErr.Reason
	}
	return "provider_contract_unavailable"
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
