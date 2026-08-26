package openairesponses

import (
	"context"
	"reflect"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type Adapter struct {
	config Config
}

func New(config Config) (*Adapter, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	return &Adapter{config: config}, nil
}

func (adapter *Adapter) Capability() providercontract.ValidatedCapability {
	if adapter == nil {
		return providercontract.ValidatedCapability{}
	}
	return adapter.config.Capability
}

func (adapter *Adapter) validateDispatch(ctx context.Context, request providercontract.ValidatedRequest) (providercontract.InferenceRequest, time.Duration, error) {
	if adapter == nil || ctx == nil || request.Digest() == "" {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.InvalidInput, "dispatch_input", false)
	}
	if err := ctx.Err(); err != nil {
		return providercontract.InferenceRequest{}, 0, contextAdapterError(err)
	}
	now := adapter.config.Clock().UTC()
	if now.IsZero() {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.Internal, "clock_unavailable", false)
	}
	value := request.Value()
	capability := adapter.config.Capability.Value()
	if value.CapabilityDigest != adapter.config.Capability.Digest() || !reflect.DeepEqual(value.Provider, capability.Provider) ||
		uint64(len(value.Messages)) > uint64(capability.Limits.MaximumMessages) ||
		uint64(len(value.Tools)) > uint64(capability.Limits.MaximumTools) || value.MaximumOutputTokens > capability.Limits.MaximumOutputTokens {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.Denied, "dispatch_binding", false)
	}
	deadline, err := time.Parse("2006-01-02T15:04:05.000000000Z", value.Deadline)
	if err != nil || !now.Before(deadline) {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.Timeout, "dispatch_deadline", false)
	}
	if _, err := adapter.config.Qualifications.Resolve(ctx, value.QualificationID, adapter.config.Capability, now); err != nil {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.Code(err), providercontract.Reason(err), false)
	}
	inputTokens, err := adapter.config.Tokens.Count(ctx, request)
	if err != nil {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.Unavailable, "token_count_unavailable", true)
	}
	if inputTokens == 0 || inputTokens > capability.Limits.MaximumInputTokens ||
		inputTokens+value.MaximumOutputTokens > capability.Provider.ContextLimit {
		return providercontract.InferenceRequest{}, 0, newError(providercontract.Denied, "context_limit", false)
	}
	window := deadline.Sub(now)
	streamCeiling := time.Duration(capability.Limits.MaximumStreamSeconds) * time.Second
	if streamCeiling < window {
		window = streamCeiling
	}
	return value, window, nil
}

func contextAdapterError(err error) error {
	if err == context.DeadlineExceeded {
		return newError(providercontract.Timeout, "request_timeout", false)
	}
	return newError(providercontract.Canceled, "request_canceled", false)
}
