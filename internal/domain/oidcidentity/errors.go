package oidcidentity

import (
	"context"
	"errors"
	"fmt"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

type Error struct {
	Code   localidentity.ErrorCode
	Reason string
	Cause  error
}

func (err *Error) Error() string { return fmt.Sprintf("server oidc %s: %s", err.Code, err.Reason) }
func (err *Error) Unwrap() error { return err.Cause }

func Code(err error) localidentity.ErrorCode {
	var oidcErr *Error
	if errors.As(err, &oidcErr) {
		return oidcErr.Code
	}
	if errors.Is(err, context.Canceled) {
		return localidentity.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return localidentity.Timeout
	}
	return localidentity.Unavailable
}

func oidcError(code localidentity.ErrorCode, reason string, cause error) error {
	return &Error{Code: code, Reason: reason, Cause: cause}
}

func errorReason(err error) string {
	var oidcErr *Error
	if errors.As(err, &oidcErr) {
		return oidcErr.Reason
	}
	return "server_oidc_unavailable"
}
