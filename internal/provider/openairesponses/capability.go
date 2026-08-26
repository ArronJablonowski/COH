package openairesponses

import (
	"context"
	"encoding/json"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type CapabilityDefinition struct {
	SnapshotID string
	ObservedAt time.Time
	ValidUntil time.Time
	Provider   providercontract.ProviderIdentity
	Limits     providercontract.Limits
}

// DiscoverCapability publishes the configured, bounded support claim for one
// exact qualified endpoint/model tuple. It does not infer support from endpoint
// reachability or a model-name match.
func DiscoverCapability(ctx context.Context, definition CapabilityDefinition) (providercontract.ValidatedCapability, error) {
	provider := definition.Provider
	if provider.ProviderKind != "openai_responses" || provider.AdapterVersion != AdapterVersion ||
		provider.EndpointIdentityDigest != EndpointIdentityDigest(ResponsesEndpoint) || provider.DataRoute != "approved_external" ||
		provider.StateMode != "stateless" {
		return providercontract.ValidatedCapability{}, newError(providercontract.Denied, "capability_provider_identity", false)
	}
	snapshot := providercontract.CapabilitySnapshot{SchemaVersion: providercontract.CapabilitySchemaVersion,
		ContractVersion: providercontract.ContractVersion, SnapshotID: definition.SnapshotID,
		ObservedAt: formatTimestamp(definition.ObservedAt), ValidUntil: formatTimestamp(definition.ValidUntil), Provider: provider,
		Features: providercontract.Features{MessageRoles: []string{"assistant", "developer", "system", "tool", "user"},
			ContentKinds: []string{"input_json", "output_json", "reasoning_ref", "text", "tool_call", "tool_result"},
			ToolCalls:    true, StructuredOutput: true, Streaming: true, Cancellation: true, Usage: true,
			StateModes: []string{"stateless"}}, Limits: definition.Limits}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return providercontract.ValidatedCapability{}, newError(providercontract.Internal, "capability_encoding", false)
	}
	validated, err := providercontract.DecodeCapability(ctx, encoded)
	if err != nil {
		return providercontract.ValidatedCapability{}, newError(providercontract.Code(err), providercontract.Reason(err), false)
	}
	return validated, nil
}
