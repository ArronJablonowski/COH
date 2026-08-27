package securityonion

import (
	"context"
	"errors"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type oqlDenial struct{ reason string }

func (value *oqlDenial) Error() string { return value.reason }
func denyOQL(reason string) error      { return &oqlDenial{reason: reason} }

func oqlContextError(ctx context.Context) error {
	if ctx == nil {
		return queryconnector.NewError(queryconnector.InvalidInput, "context_required", nil)
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return queryconnector.NewError(queryconnector.Timeout, "securityonion_oql_validation_timeout", err)
		}
		return queryconnector.NewError(queryconnector.Canceled, "securityonion_oql_validation_canceled", err)
	}
	return nil
}
