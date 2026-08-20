// Package connector contains bounded external-system adapters. Only broker
// implementations may import this boundary; it has no generic pass-through.
package connector

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
)

// Gateway dispatches one already-authorized, digest-bound intent. Policy and
// credential enforcement remain broker responsibilities.
type Gateway interface {
	Dispatch(context.Context, domain.ToolIntent) (domain.ActionReceipt, error)
}
