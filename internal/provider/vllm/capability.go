package vllm

import (
	"context"
	"encoding/json"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const (
	toolParserDomain      = "COH-VLLM-TOOL-PARSER-V1\x00"
	reasoningParserDomain = "COH-VLLM-REASONING-PARSER-V1\x00"
	samplingProfileDomain = "COH-VLLM-SAMPLING-PROFILE-V1\x00"
)

type CapabilityDefinition struct {
	SnapshotID string
	ObservedAt time.Time
	ValidUntil time.Time
	Provider   providercontract.ProviderIdentity
	Limits     providercontract.Limits
}

func ToolParserDigest() string { return digest(toolParserDomain, []byte(VendorSurfaceVersion)) }

func ReasoningParserDigest() string {
	return digest(reasoningParserDomain, []byte(VendorSurfaceVersion))
}

func SamplingProfileDigest() string {
	return digest(samplingProfileDomain,
		[]byte("max_completion_tokens,temperature,top_p,seed,n=1,logprobs=false,include_reasoning=true,parallel_tool_calls=true,strict_tools=true"))
}

func DiscoverCapability(ctx context.Context, definition CapabilityDefinition) (providercontract.ValidatedCapability, error) {
	provider := definition.Provider
	if provider.ProviderKind != "vllm" || provider.AdapterVersion != AdapterVersion ||
		provider.EndpointIdentityDigest != EndpointIdentityDigest(VLLMEndpoint) || provider.DataRoute != "local" ||
		provider.StateMode != "stateless" || provider.ToolParserDigest != ToolParserDigest() ||
		provider.ReasoningParserDigest != ReasoningParserDigest() || provider.SamplingProfileDigest != SamplingProfileDigest() {
		return providercontract.ValidatedCapability{}, newError(providercontract.Denied, "capability_provider_identity", false)
	}
	snapshot := providercontract.CapabilitySnapshot{SchemaVersion: providercontract.CapabilitySchemaVersion,
		ContractVersion: providercontract.ContractVersion, SnapshotID: definition.SnapshotID,
		ObservedAt: formatTimestamp(definition.ObservedAt), ValidUntil: formatTimestamp(definition.ValidUntil), Provider: provider,
		Features: providercontract.Features{MessageRoles: []string{"assistant", "system", "tool", "user"},
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

func formatTimestamp(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
