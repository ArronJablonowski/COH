package policy

import (
	"context"
	"errors"
	"fmt"
)

type ErrorCode string

const (
	InvalidInput ErrorCode = "invalid_input"
	Denied       ErrorCode = "denied"
	Unavailable  ErrorCode = "unavailable"
	Canceled     ErrorCode = "canceled"
	Timeout      ErrorCode = "timeout"
)

type Error struct {
	Code   ErrorCode
	Reason string
}

func (err *Error) Error() string { return fmt.Sprintf("policy %s: %s", err.Code, err.Reason) }

func Code(err error) ErrorCode {
	var policyErr *Error
	if errors.As(err, &policyErr) {
		return policyErr.Code
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
	var policyErr *Error
	if errors.As(err, &policyErr) {
		return policyErr.Reason
	}
	return "policy_unavailable"
}

func NewError(code ErrorCode, reason string) error { return &Error{Code: code, Reason: reason} }
