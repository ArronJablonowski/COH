// Package provider contains model-provider adapters. Adapters depend inward
// on workflow ports and cannot import transports, commands, or other adapters.
package provider

import "github.com/ArronJablonowski/COH/internal/workflow"

// Gateway marks a model-provider implementation of the workflow port.
type Gateway interface {
	workflow.ModelProvider
}
