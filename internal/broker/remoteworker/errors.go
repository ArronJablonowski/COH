package remoteworker

import (
	"context"
	"errors"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

func brokerError(code workercontract.ErrorCode, reason string) error {
	return workercontract.NewError(code, reason)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return brokerError(workercontract.InvalidInput, "context_required")
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return brokerError(workercontract.Timeout, "request_timeout")
		}
		return brokerError(workercontract.Canceled, "request_canceled")
	}
	return nil
}

func auditContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.Background()
	if ctx != nil {
		base = context.WithoutCancel(ctx)
	}
	return context.WithTimeout(base, 5*time.Second)
}

func outcome(err error, allowedReason string) (string, string) {
	if err == nil {
		return "allowed", allowedReason
	}
	switch workercontract.Code(err) {
	case workercontract.InvalidInput:
		return "invalid", workercontract.Reason(err)
	case workercontract.Denied, workercontract.NotFound, workercontract.Conflict:
		return "denied", workercontract.Reason(err)
	case workercontract.Canceled:
		return "canceled", workercontract.Reason(err)
	case workercontract.Timeout:
		return "timeout", workercontract.Reason(err)
	default:
		return "unavailable", workercontract.Reason(err)
	}
}
