package approvallifecycle

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
	Cause  error
}

func (err *Error) Error() string {
	return fmt.Sprintf("approval lifecycle %s: %s", err.Code, err.Reason)
}
func (err *Error) Unwrap() error { return err.Cause }

func NewError(code ErrorCode, reason string) error { return &Error{Code: code, Reason: reason} }

func Code(err error) ErrorCode {
	var lifecycleErr *Error
	if errors.As(err, &lifecycleErr) {
		return lifecycleErr.Code
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
	var lifecycleErr *Error
	if errors.As(err, &lifecycleErr) {
		return lifecycleErr.Reason
	}
	return "approval_lifecycle_unavailable"
}
