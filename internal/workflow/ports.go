// Package workflow owns application use cases and inward-facing ports.
// Workflows submit typed intents to ActionAuthority and can never receive a
// connector, policy engine, runner, or other action-capable implementation.
package workflow

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
)

// ModelProvider is the bounded model inference port.
type ModelProvider interface {
	Invoke(context.Context, domain.Operation) (domain.ArtifactRef, error)
}

// ActionAuthority is the sole side-effect route available to workflows. Its
// broker implementation rechecks policy and owns connector dispatch.
type ActionAuthority interface {
	Submit(context.Context, domain.ToolIntent) (domain.ActionReceipt, error)
}

// Engine is the guarded durable application boundary exposed to transports.
type Engine interface {
	Start(context.Context, WorkflowStart) (WorkflowHandle, error)
	Signal(context.Context, WorkflowSignal) error
	Query(context.Context, WorkflowQuery) (WorkflowSnapshot, error)
	Cancel(context.Context, WorkflowCancel) error
	Replay(context.Context, WorkflowReplay) (WorkflowReplayResult, error)
}

// EngineDriver is implemented by durable workflow adapters. GuardEngine must
// wrap a driver before it is exposed to a transport or command.
type EngineDriver interface {
	Engine
}

// Dependencies are explicit, testable application ports.
type Dependencies struct {
	Models  ModelProvider
	Actions ActionAuthority
	Store   Repository
}
