package localauth

import (
	"context"
	"errors"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

var (
	ErrNotFound = errors.New("local auth record not found")
	ErrConflict = errors.New("local auth record conflict")
)

func authError(code localidentity.ErrorCode, reason string) error {
	return &localidentity.IdentityError{Code: code, Reason: reason}
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return authError(localidentity.Code(err), contextReason(err))
	}
	return nil
}

func contextReason(err error) string {
	if errors.Is(err, context.Canceled) {
		return "request_canceled"
	}
	return "request_timeout"
}

func reason(err error) string {
	var identityErr *localidentity.IdentityError
	if errors.As(err, &identityErr) {
		return identityErr.Reason
	}
	return "authentication_unavailable"
}
