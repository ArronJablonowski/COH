// Package provider contains model-provider adapters. Adapters depend inward
// on workflow ports and cannot import transports, commands, or other adapters.
package provider

import (
	"context"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

// Gateway marks a model-provider implementation of the workflow port.
type Gateway interface {
	workflow.ModelProvider
}

// QualifiedAdapter is the provider-contract boundary implemented by vendor
// adapters before workflow integration. It cannot execute returned tool calls.
type QualifiedAdapter interface {
	Capability() providercontract.ValidatedCapability
	Invoke(context.Context, providercontract.ValidatedRequest) (providercontract.ValidatedResponse, error)
}
