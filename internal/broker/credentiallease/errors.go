package credentiallease

import (
	"context"
	"errors"
	"time"

	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
)

const auditAppendTimeout = 5 * time.Second

func brokerError(code leasecontract.ErrorCode, reason string) error {
	return &leasecontract.Error{Code: code, Reason: reason}
}

func contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		reason := "request_timeout"
		if errors.Is(err, context.Canceled) {
			reason = "request_canceled"
		}
		return &leasecontract.Error{Code: leasecontract.Code(err), Reason: reason}
	}
	return nil
}

func reason(err error) string {
	var leaseErr *leasecontract.Error
	if errors.As(err, &leaseErr) {
		return leaseErr.Reason
	}
	return "credential_lease_unavailable"
}

func auditContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), auditAppendTimeout)
}
