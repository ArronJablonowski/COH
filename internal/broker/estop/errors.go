package estop

import (
	"context"
	"errors"
	"time"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
)

func brokerError(code stopcontract.ErrorCode, reason string) error {
	return stopcontract.NewError(code, reason)
}

func normalizeContext(ctx context.Context) error {
	if err := stopcontract.ContextError(ctx); err != nil {
		return err
	}
	return nil
}

func normalizeStoreError(ctx context.Context, err error) error {
	if contextErr := normalizeContext(ctx); contextErr != nil {
		return contextErr
	}
	switch stopcontract.Code(err) {
	case stopcontract.Denied, stopcontract.NotFound, stopcontract.Conflict:
		return err
	default:
		return brokerError(stopcontract.Unavailable, "estop_store_unavailable")
	}
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
	switch stopcontract.Code(err) {
	case stopcontract.InvalidInput:
		return "invalid", stopcontract.Reason(err)
	case stopcontract.Denied, stopcontract.NotFound, stopcontract.Conflict:
		return "denied", stopcontract.Reason(err)
	case stopcontract.Canceled:
		return "canceled", stopcontract.Reason(err)
	case stopcontract.Timeout:
		return "timeout", stopcontract.Reason(err)
	default:
		return "unavailable", stopcontract.Reason(err)
	}
}

func controlError(err error, ctx context.Context) (string, string) {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return "timeout", "control_timeout"
	}
	return "failed", "control_failed"
}
