// Package command is the native composition root. Commands parse operator
// intent and wire dependencies; business and authorization logic live inward.
package command

import (
	"github.com/ArronJablonowski/COH/internal/broker"
	"github.com/ArronJablonowski/COH/internal/persistence"
	"github.com/ArronJablonowski/COH/internal/provider"
	"github.com/ArronJablonowski/COH/internal/transport"
	"github.com/ArronJablonowski/COH/internal/ui"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

// Components makes composition dependencies visible to architecture checks.
// It is not a service locator and must not be passed into domain code.
type Components struct {
	Broker      broker.Authority
	Provider    provider.Gateway
	Persistence persistence.Repository
	Workflow    workflow.Engine
	Transport   transport.Service
	UI          ui.Bundle
}
