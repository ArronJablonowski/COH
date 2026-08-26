package recoverycontrol

import (
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func approvedRouteBinding(value ApprovedRoute, request InvokeRequest, now time.Time) (RouteBinding, error) {
	primary, err := capabilityProfile(value.PrimaryCapability, value.PrimaryQualification, now)
	if err != nil {
		return RouteBinding{}, err
	}
	fallback, err := capabilityProfile(value.FallbackCapability, value.FallbackQualification, now)
	if err != nil {
		return RouteBinding{}, err
	}
	binding := RouteBinding{DecisionID: value.DecisionID, PolicyDigest: value.PolicyDigest,
		RequestedRoute: value.RequestedRoute, PrimaryRoute: value.PrimaryRoute,
		FallbackRoute: value.FallbackRoute, ApprovalDigest: value.ApprovalDigest,
		Primary: primary, Fallback: fallback, IssuedAt: value.IssuedAt.UTC(), ExpiresAt: value.ExpiresAt.UTC()}
	if value.PolicyDigest != request.PolicyDigest || value.RequestedRoute != request.RequestedRoute ||
		!validRouteBinding(binding, request.PolicyDigest, now) {
		return RouteBinding{}, newError(DeniedCode, "route_approval_invalid", false, false, nil)
	}
	if err := equivalentCapabilities(primary, fallback); err != nil {
		return RouteBinding{}, err
	}
	return binding, nil
}

func capabilityProfile(value providercontract.ValidatedCapability,
	qualification providercontract.ValidatedQualification, now time.Time) (CapabilityProfile, error) {
	snapshot := value.Value()
	if value.Digest() == "" || providercontract.ValidateCapability(snapshot) != nil || qualification.Digest() == "" ||
		providercontract.AdmitQualification(value, qualification, now) != nil {
		return CapabilityProfile{}, newError(DeniedCode, "capability_snapshot_invalid", false, false, nil)
	}
	return CapabilityProfile{CapabilityDigest: value.Digest(), QualificationDigest: qualification.Digest(),
		DataRoute: snapshot.Provider.DataRoute, StateMode: snapshot.Provider.StateMode,
		MessageRoles: slices.Clone(snapshot.Features.MessageRoles),
		ContentKinds: slices.Clone(snapshot.Features.ContentKinds), StateModes: slices.Clone(snapshot.Features.StateModes),
		ToolCalls: snapshot.Features.ToolCalls, StructuredOutput: snapshot.Features.StructuredOutput,
		Streaming: snapshot.Features.Streaming, Cancellation: snapshot.Features.Cancellation, Usage: snapshot.Features.Usage,
		MaximumInputTokens:  snapshot.Limits.MaximumInputTokens,
		MaximumOutputTokens: snapshot.Limits.MaximumOutputTokens, MaximumMessages: snapshot.Limits.MaximumMessages,
		MaximumTools:             snapshot.Limits.MaximumTools,
		MaximumParallelToolCalls: snapshot.Limits.MaximumParallelToolCalls,
		MaximumStreamSeconds:     snapshot.Limits.MaximumStreamSeconds, ContextLimit: snapshot.Provider.ContextLimit}, nil
}

func equivalentCapabilities(primary, fallback CapabilityProfile) error {
	if exposureRank(fallback.DataRoute) > exposureRank(primary.DataRoute) {
		return newError(DeniedCode, "fallback_data_exposure_broader", false, false, nil)
	}
	if primary.StateMode == "provider_managed" || !fallback.Cancellation ||
		primary.ToolCalls && !fallback.ToolCalls || primary.StructuredOutput && !fallback.StructuredOutput ||
		primary.Streaming && !fallback.Streaming || primary.Cancellation && !fallback.Cancellation ||
		primary.Usage && !fallback.Usage || !containsAll(fallback.MessageRoles, primary.MessageRoles) ||
		!containsAll(fallback.ContentKinds, primary.ContentKinds) || !slices.Contains(fallback.StateModes, primary.StateMode) ||
		fallback.MaximumInputTokens < primary.MaximumInputTokens ||
		fallback.MaximumOutputTokens < primary.MaximumOutputTokens ||
		fallback.MaximumMessages < primary.MaximumMessages || fallback.MaximumTools < primary.MaximumTools ||
		fallback.MaximumParallelToolCalls < primary.MaximumParallelToolCalls ||
		fallback.MaximumStreamSeconds < primary.MaximumStreamSeconds || fallback.ContextLimit < primary.ContextLimit {
		return newError(DeniedCode, "fallback_capability_not_equivalent", false, false, nil)
	}
	return nil
}

func containsAll(have, required []string) bool {
	for _, value := range required {
		if !slices.Contains(have, value) {
			return false
		}
	}
	return true
}

func exposureRank(value string) int {
	switch value {
	case "air_gapped":
		return 0
	case "local":
		return 1
	case "approved_external":
		return 2
	default:
		return 100
	}
}
