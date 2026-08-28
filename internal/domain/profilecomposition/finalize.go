package profilecomposition

import (
	"context"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

// Finalize binds a graph digest produced by the command composition root to
// the prepared profile. It performs no capability resolution or activation.
func (candidate Candidate) Finalize(ctx context.Context, capabilityGraphDigest string) (ValidatedResolvedProfile, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedResolvedProfile{}, err
	}
	if candidate.state == nil {
		return ValidatedResolvedProfile{}, newError(InvalidInput, "candidate_required")
	}
	if !validDigest(capabilityGraphDigest) {
		return ValidatedResolvedProfile{}, newError(InvalidInput, "capability_graph_digest")
	}
	state := cloneCandidateState(*candidate.state)
	profile := ResolvedProfile{SchemaVersion: ResolvedProfileSchemaVersion, ContractVersion: ContractVersion,
		ProfileID: state.request.ProfileID, Revision: state.request.Revision, Target: state.request.Target,
		OrderedLayers: state.bindings, DeploymentProfile: state.deployment,
		CapabilityBundles: state.capabilities, PolicyBundles: state.policies,
		EndpointReferences: state.endpoints, Permissions: state.permissions, Limits: state.limits,
		Features: state.features, OfflineBundleDigest: state.offlineBundleDigest,
		ProfileBindingDigest: state.profileBindingDigest, CapabilityGraphDigest: capabilityGraphDigest}
	digest, err := resolvedProfileDigest(profile)
	if err != nil {
		return ValidatedResolvedProfile{}, err
	}
	profile.CompositionDigest = digest
	encoded, err := json.Marshal(profile)
	if err != nil {
		return ValidatedResolvedProfile{}, newError(Denied, "resolved_profile_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return ValidatedResolvedProfile{}, newError(Denied, "resolved_profile_encoding")
	}
	if err := contextError(ctx); err != nil {
		return ValidatedResolvedProfile{}, err
	}
	return ValidatedResolvedProfile{digest: digest, bytes: canonical}, nil
}

func resolvedProfileDigest(profile ResolvedProfile) (string, error) {
	profile.CompositionDigest = ""
	encoded, err := json.Marshal(profile)
	if err != nil {
		return "", newError(Denied, "resolved_profile_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newError(Denied, "resolved_profile_encoding")
	}
	return digestBytes(resolvedProfileDomain, canonical), nil
}

func cloneCandidateState(value candidateState) candidateState {
	value.ordered = append([]VerifiedLayer(nil), value.ordered...)
	value.bindings = append([]LayerBinding(nil), value.bindings...)
	value.capabilities = append([]ArtifactRef(nil), value.capabilities...)
	value.policies = append([]ArtifactRef(nil), value.policies...)
	value.endpoints = append([]string(nil), value.endpoints...)
	value.permissions = append([]string(nil), value.permissions...)
	return value
}
