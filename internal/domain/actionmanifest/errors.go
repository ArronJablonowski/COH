package actionmanifest

import (
	"context"
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
)

type ContractError struct {
	Code   ErrorCode
	Reason string
}

func (err *ContractError) Error() string {
	return fmt.Sprintf("action manifest %s: %s", err.Code, err.Reason)
}

func Code(err error) ErrorCode {
	var contractErr *ContractError
	if errors.As(err, &contractErr) {
		return contractErr.Code
	}
	if errors.Is(err, context.Canceled) {
		return Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	return InvalidInput
}

func Reason(err error) string {
	var contractErr *ContractError
	if errors.As(err, &contractErr) {
		return contractErr.Reason
	}
	return "manifest_invalid"
}

func contractError(code ErrorCode, reason string) error {
	return &ContractError{Code: code, Reason: reason}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return contractError(InvalidInput, "context_required")
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return contractError(Timeout, "request_timeout")
		}
		return contractError(Canceled, "request_canceled")
	}
	return nil
}
