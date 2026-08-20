// Package policy owns authorization decisions and policy-domain behavior.
// It is independent of transports and concrete adapters.
package policy

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
)

// Decision is an immutable result from evaluating one operation.
type Decision struct {
	Allowed        bool
	PolicyRevision string
	ReasonCode     string
}

// Evaluator is the narrow policy port consumed only by the broker boundary.
// Workflows and transports cannot import or receive it.
type Evaluator interface {
	Evaluate(context.Context, domain.Operation) (Decision, error)
}
