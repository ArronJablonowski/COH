package codexruntime

import (
	"context"
	"reflect"
	"strings"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type Adapter struct{ config Config }

func New(config Config) (*Adapter, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	return &Adapter{config: config}, nil
}
func (a *Adapter) Capability() providercontract.ValidatedCapability {
	if a == nil {
		return providercontract.ValidatedCapability{}
	}
	return a.config.Capability
}

func validateConfig(c Config) error {
	if c.Capability.Digest() == "" || c.Qualifications == nil || c.Schemas == nil || c.Tools == nil || c.Reasoning == nil || c.Factory == nil || c.Batch == nil || c.Clock == nil || !validWorkspace(c.Workspace) {
		return newError(providercontract.InvalidInput, "adapter_configuration", false)
	}
	p := c.Capability.Value().Provider
	if p.ProviderKind != "codex_runtime" || p.AdapterVersion != AdapterVersion || p.EndpointIdentityDigest != EndpointIdentityDigest(p.RuntimeName, c.Workspace) || p.DataRoute != "approved_external" || p.StateMode != "stateless" || p.RequestedModel != p.ActualModel || p.RuntimeVersion != RuntimeVersion || p.RuntimeDigest != RuntimeDigest || p.ToolParserDigest != ToolParserDigest() || p.ReasoningParserDigest != ReasoningParserDigest() || p.SamplingProfileDigest != SamplingProfileDigest() {
		return newError(providercontract.Denied, "provider_identity_not_supported", false)
	}
	if p.RuntimeName != "codex-app-server" && p.RuntimeName != "codex-exec" {
		return newError(providercontract.Unsupported, "runtime_mode", false)
	}
	return nil
}

func (a *Adapter) validateDispatch(ctx context.Context, request providercontract.ValidatedRequest) (providercontract.InferenceRequest, time.Duration, error) {
	if a == nil || ctx == nil || request.Digest() == "" {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.InvalidInput, "dispatch_input", false)
	}
	if err := ctx.Err(); err != nil {
		return providercontract.InferenceRequest{}, 0, contextAdapterError(err)
	}
	now := a.config.Clock().UTC()
	if now.IsZero() {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.Internal, "clock_unavailable", false)
	}
	v, c := request.Value(), a.config.Capability.Value()
	if v.CapabilityDigest != a.config.Capability.Digest() || !reflect.DeepEqual(v.Provider, c.Provider) || v.State.Mode != "stateless" || uint64(len(v.Messages)) > uint64(c.Limits.MaximumMessages) || uint64(len(v.Tools)) > uint64(c.Limits.MaximumTools) || v.MaximumOutputTokens > c.Limits.MaximumOutputTokens {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.Denied, "dispatch_binding", false)
	}
	if v.Sampling.TemperatureMilli != 0 || v.Sampling.TopPMillionths != 1000000 || v.Sampling.Seed != 0 {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.Unsupported, "sampling_profile", false)
	}
	deadline, err := time.Parse("2006-01-02T15:04:05.000000000Z", v.Deadline)
	if err != nil || !now.Before(deadline) {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.Timeout, "dispatch_deadline", false)
	}
	if _, err := a.config.Qualifications.Resolve(ctx, v.QualificationID, a.config.Capability, now); err != nil {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.Code(err), providercontract.Reason(err), false)
	}
	window := deadline.Sub(now)
	ceiling := time.Duration(c.Limits.MaximumStreamSeconds) * time.Second
	if ceiling < window {
		window = ceiling
	}
	return v, window, nil
}
func contextAdapterError(err error) error {
	if err == context.DeadlineExceeded {
		return newError(providercontract.Timeout, "request_timeout", false)
	}
	return newError(providercontract.Canceled, "request_canceled", false)
}
func validWorkspace(value string) bool {
	return strings.HasPrefix(value, "/") && len(value) <= 4096 && !strings.ContainsAny(value, "\x00\r\n")
}

func (a *Adapter) verifyObservation(value providercontract.InferenceRequest, o LaunchObservation, mode string) error {
	p := value.Provider
	expectedSurface := "dynamicTools-only"
	if mode == "exec-jsonl" {
		expectedSurface = "tools-disabled"
	}
	if o.RuntimeVersion != p.RuntimeVersion || o.RuntimeDigest != p.RuntimeDigest || o.ProtocolDigest != ProtocolDigest || o.Model != p.ActualModel || o.ModelRevision != p.ModelRevision || o.Workspace != a.config.Workspace || o.Transport != mode || o.Sandbox != "read-only" || o.ApprovalPolicy != "untrusted" || o.NetworkMode != "connected" || o.ConfigDigest != p.ChatTemplateDigest || o.EnvironmentDigest != p.HardwareProfileDigest || o.CredentialMode != "invocation-scoped" || o.ExperimentalSurface != expectedSurface || !validWorkspace(o.CodexHome) || o.ConfigMode != "managed-isolated" || o.RulesMode != "disabled" || o.HooksMode != "disabled" || o.MCPMode != map[bool]string{true: "disabled", false: "broker-only"}[mode == "exec-jsonl"] || o.WebSearchMode != "disabled" || o.MutationMode != "disabled" || o.EnvironmentMode != "allowlist" {
		return newError(providercontract.Denied, "runtime_attestation_failed", false)
	}
	return nil
}

func (a *Adapter) validateUsage(request providercontract.InferenceRequest, usage providercontract.Usage) error {
	limits := a.config.Capability.Value().Limits
	if usage.InputTokens > limits.MaximumInputTokens || usage.OutputTokens > request.MaximumOutputTokens || usage.OutputTokens > limits.MaximumOutputTokens || usage.TotalTokens > request.Provider.ContextLimit {
		return newError(providercontract.Denied, "usage_limit_exceeded", false)
	}
	return nil
}
