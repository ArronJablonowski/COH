package securityonion

import (
	"context"
	"errors"
	"net"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func invalid(reason string) error {
	return queryconnector.NewError(queryconnector.InvalidInput, reason, nil)
}

func denied(reason string) error {
	return queryconnector.NewError(queryconnector.Denied, reason, nil)
}

func conflict(reason string) error {
	return queryconnector.NewError(queryconnector.Conflict, reason, nil)
}

func mapHTTPError(err error) error {
	if err == nil {
		return nil
	}
	var connectorError *queryconnector.Error
	if errors.As(err, &connectorError) {
		return err
	}
	if errors.Is(err, context.Canceled) {
		return queryconnector.NewError(queryconnector.Canceled, "securityonion_request_canceled", nil)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return queryconnector.NewError(queryconnector.Timeout, "securityonion_request_timeout", nil)
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return queryconnector.NewError(queryconnector.Unavailable, "securityonion_transport_failed", nil)
	}
	return queryconnector.NewError(queryconnector.Unavailable, "securityonion_request_failed", nil)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return invalid("securityonion_context_required")
	}
	return mapHTTPError(ctx.Err())
}
