package codexruntime

import (
	"context"
	"encoding/json"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const (
	toolParserDomain      = "COH-CODEX-RUNTIME-TOOL-PARSER-V1\x00"
	reasoningParserDomain = "COH-CODEX-RUNTIME-REASONING-PARSER-V1\x00"
	samplingProfileDomain = "COH-CODEX-RUNTIME-SAMPLING-PROFILE-V1\x00"
)

type CapabilityDefinition struct {
	SnapshotID             string
	ObservedAt, ValidUntil time.Time
	Provider               providercontract.ProviderIdentity
	Limits                 providercontract.Limits
}

func ToolParserDigest() string {
	return digest(toolParserDomain, []byte(ProtocolVersion+"\x00dynamicTools+item/tool/call"))
}
func ReasoningParserDigest() string {
	return digest(reasoningParserDomain, []byte(ProtocolVersion+"\x00reasoning-events"))
}
func SamplingProfileDigest() string {
	return digest(samplingProfileDomain, []byte("model=pinned,temperature_milli=0,top_p_millionths=1000000,seed=0,effort=medium,summary=concise,sandbox=read-only,approval=untrusted"))
}

func DiscoverCapability(ctx context.Context, definition CapabilityDefinition) (providercontract.ValidatedCapability, error) {
	p := definition.Provider
	if p.ProviderKind != "codex_runtime" || p.AdapterVersion != AdapterVersion || p.DataRoute != "approved_external" ||
		p.StateMode != "stateless" || p.RequestedModel != p.ActualModel || p.RuntimeVersion != RuntimeVersion || p.RuntimeDigest != RuntimeDigest ||
		p.ToolParserDigest != ToolParserDigest() || p.ReasoningParserDigest != ReasoningParserDigest() || p.SamplingProfileDigest != SamplingProfileDigest() {
		return providercontract.ValidatedCapability{}, newError(providercontract.Denied, "capability_provider_identity", false)
	}
	snapshot := providercontract.CapabilitySnapshot{SchemaVersion: providercontract.CapabilitySchemaVersion, ContractVersion: providercontract.ContractVersion,
		SnapshotID: definition.SnapshotID, ObservedAt: formatTimestamp(definition.ObservedAt), ValidUntil: formatTimestamp(definition.ValidUntil), Provider: p,
		Features: providercontract.Features{MessageRoles: []string{"assistant", "system", "tool", "user"}, ContentKinds: []string{"input_json", "output_json", "reasoning_ref", "text", "tool_call", "tool_result"}, ToolCalls: true, StructuredOutput: true, Streaming: true, Cancellation: true, Usage: true, StateModes: []string{"stateless"}}, Limits: definition.Limits}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return providercontract.ValidatedCapability{}, newError(providercontract.Internal, "capability_encoding", false)
	}
	value, err := providercontract.DecodeCapability(ctx, encoded)
	if err != nil {
		return providercontract.ValidatedCapability{}, newError(providercontract.Code(err), providercontract.Reason(err), false)
	}
	return value, nil
}
func formatTimestamp(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
