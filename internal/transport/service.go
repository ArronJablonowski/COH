// Package transport owns protocol translation. It calls workflow ports and
// cannot import concrete provider, connector, or persistence adapters.
package transport

import (
	"github.com/ArronJablonowski/COH/internal/ui"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

// Service contains only application-facing ports and immutable UI assets.
type Service struct {
	Workflows workflow.Engine
	UI        ui.Bundle
}
