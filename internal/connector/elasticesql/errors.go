package elasticesql

import (
	"context"
	"errors"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func contextError(ctx context.Context) error {
	if ctx == nil {
		return queryconnector.NewError(queryconnector.InvalidInput, "context_required", nil)
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return queryconnector.NewError(queryconnector.Timeout, "esql_validation_timeout", err)
		}
		return queryconnector.NewError(queryconnector.Canceled, "esql_validation_canceled", err)
	}
	return nil
}

type denial struct{ reason string }

func (value *denial) Error() string { return value.reason }

func deny(reason string) error { return &denial{reason: reason} }
