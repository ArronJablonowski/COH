// Package provider contains model-provider adapters. Adapters depend inward
// on workflow ports and cannot import transports, commands, or other adapters.
package provider

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain/modelsurface"
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

// SurfaceGateway is the production dispatch boundary. It accepts only an
// inference admitted and sealed by the model-surface domain.
type SurfaceGateway struct{ adapter QualifiedAdapter }

func NewSurfaceGateway(adapter QualifiedAdapter) (*SurfaceGateway, error) {
	if adapter == nil {
		return nil, providercontract.NewError(providercontract.InvalidInput, "surface_gateway_adapter")
	}
	return &SurfaceGateway{adapter: adapter}, nil
}

func (gateway *SurfaceGateway) Invoke(ctx context.Context, admitted modelsurface.AdmittedInference) (providercontract.ValidatedResponse, error) {
	if gateway == nil || gateway.adapter == nil || len(admitted.Request().CanonicalBytes()) == 0 {
		return providercontract.ValidatedResponse{}, providercontract.NewError(providercontract.InvalidInput, "surface_admission")
	}
	return gateway.adapter.Invoke(ctx, admitted.Request())
}
