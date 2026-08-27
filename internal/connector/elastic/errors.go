package elastic

import (
	"context"
	"errors"

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

func unsupported(reason string) error {
	return queryconnector.NewError(queryconnector.Unsupported, reason, nil)
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return invalid("context_required")
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return queryconnector.NewError(queryconnector.Timeout, "elastic_request_timeout", err)
		}
		return queryconnector.NewError(queryconnector.Canceled, "elastic_request_canceled", err)
	}
	return nil
}
