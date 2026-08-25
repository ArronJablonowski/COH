package oidcauth

import (
	"context"
	"errors"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

var (
	ErrNotFound = errors.New("server oidc record not found")
	ErrConflict = errors.New("server oidc record conflict")
)

func authError(code localidentity.ErrorCode, reason string) error {
	return &localidentity.IdentityError{Code: code, Reason: reason}
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		reason := "request_timeout"
		if errors.Is(err, context.Canceled) {
			reason = "request_canceled"
		}
		return authError(localidentity.Code(err), reason)
	}
	return nil
}

func reason(err error) string {
	var identityErr *localidentity.IdentityError
	if errors.As(err, &identityErr) {
		return identityErr.Reason
	}
	return "server_oidc_unavailable"
}
