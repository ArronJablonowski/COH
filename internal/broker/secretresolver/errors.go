package secretresolver

import (
	"context"
	"errors"

	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

var ErrNotFound = errors.New("secret backend entry not found")

func resolverError(code secretref.ErrorCode, reason string) error {
	return &secretref.Error{Code: code, Reason: reason}
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		reason := "request_timeout"
		if errors.Is(err, context.Canceled) {
			reason = "request_canceled"
		}
		return resolverError(secretref.Code(err), reason)
	}
	return nil
}

func reason(err error) string {
	var secretErr *secretref.Error
	if errors.As(err, &secretErr) {
		return secretErr.Reason
	}
	return "secret_resolution_unavailable"
}
