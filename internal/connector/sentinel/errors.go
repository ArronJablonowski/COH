package sentinel

import (
	"context"
	"errors"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func invalidInput(reason string) error {
	return queryconnector.NewError(queryconnector.InvalidInput, reason, nil)
}

func deniedCall(reason string) error {
	return queryconnector.NewError(queryconnector.Denied, reason, nil)
}

func conflictCall(reason string) error {
	return queryconnector.NewError(queryconnector.Conflict, reason, nil)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return invalidInput("sentinel_context_required")
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return queryconnector.NewError(queryconnector.Timeout, "sentinel_request_timeout", err)
		}
		return queryconnector.NewError(queryconnector.Canceled, "sentinel_request_canceled", err)
	}
	return nil
}

func mapTransportError(ctx context.Context, err error) error {
	if contextual := contextError(ctx); contextual != nil {
		return contextual
	}
	if queryconnector.Reason(err) != "query_connector_unavailable" {
		return err
	}
	return queryconnector.NewError(queryconnector.Unavailable, "sentinel_transport_failed", nil)
}
