package broker

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain/extensionlifecycle"
)

// ExtensionLifecycleControl is the broker-owned runtime boundary used by the
// command root. Registration effects cannot be invoked through model, agent,
// workflow, provider, or connector surfaces, and E-stop is observed through
// the same trusted control boundary immediately before execution.
type ExtensionLifecycleControl interface {
	extensionlifecycle.EffectPort
	ObserveExtensionEStop(context.Context, extensionlifecycle.ExactScope) (extensionlifecycle.EStopObservation, error)
}
