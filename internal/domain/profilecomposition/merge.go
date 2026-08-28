package profilecomposition

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type profileBinding struct {
	SchemaVersion       string        `json:"schema_version"`
	ContractVersion     string        `json:"contract_version"`
	Target              ExactTarget   `json:"target"`
	DeploymentProfile   ArtifactRef   `json:"deployment_profile"`
	PolicyBundles       []ArtifactRef `json:"policy_bundles"`
	EndpointReferences  []string      `json:"endpoint_references"`
	Permissions         []string      `json:"permissions"`
	Limits              Limits        `json:"limits"`
	Features            Features      `json:"features"`
	OfflineBundleDigest string        `json:"offline_bundle_digest"`
}

func Prepare(ctx context.Context, request Request, layers []VerifiedLayer) (Candidate, error) {
	if err := contextError(ctx); err != nil {
		return Candidate{}, err
	}
	if !validUUID7(request.ProfileID) || request.Revision == 0 || !validExactTarget(request.Target) ||
		len(layers) == 0 || len(layers) > 128 {
		return Candidate{}, newError(InvalidInput, "composition_request")
	}
	ordered, err := orderLayers(ctx, request.Target, layers)
	if err != nil {
		return Candidate{}, err
	}
	state, err := mergeOrdered(ctx, request, ordered)
	if err != nil {
		return Candidate{}, err
	}
	binding := profileBinding{SchemaVersion: "coh.profile-binding/v1", ContractVersion: ContractVersion,
		Target: request.Target, DeploymentProfile: state.deployment, PolicyBundles: state.policies,
		EndpointReferences: state.endpoints, Permissions: state.permissions, Limits: state.limits,
		Features: state.features, OfflineBundleDigest: state.offlineBundleDigest}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return Candidate{}, newError(Denied, "profile_binding_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return Candidate{}, newError(Denied, "profile_binding_encoding")
	}
	state.profileBindingDigest = digestBytes(profileBindingDomain, canonical)
	return Candidate{state: state}, nil
}

func orderLayers(ctx context.Context, target ExactTarget, layers []VerifiedLayer) ([]VerifiedLayer, error) {
	byID := make(map[string]VerifiedLayer, len(layers))
	children := make(map[string][]string, len(layers))
	indegree := make(map[string]int, len(layers))
	baselineCount := 0
	for _, verified := range layers {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		if verified.validated.LayerDigest() == "" {
			return nil, newError(InvalidInput, "verified_layer_required")
		}
		layer := verified.Layer()
		if !targetCovered(layer.Target, target) {
			return nil, newError(Denied, "target_not_covered")
		}
		if _, exists := byID[layer.LayerID]; exists {
			return nil, newError(Denied, "layer_ambiguous")
		}
		byID[layer.LayerID] = verified
		indegree[layer.LayerID] = len(layer.Parents)
		if layer.Kind == "baseline" {
			baselineCount++
			if len(layer.Parents) != 0 || layer.Precedence != 0 {
				return nil, newError(Denied, "baseline_invalid")
			}
		}
	}
	if baselineCount != 1 {
		return nil, newError(Denied, "baseline_ambiguous")
	}
	for _, verified := range layers {
		layer := verified.Layer()
		for _, parent := range layer.Parents {
			actual, exists := byID[parent.LayerID]
			if !exists {
				return nil, newError(Denied, "parent_missing")
			}
			actualLayer := actual.Layer()
			if actualLayer.Revision != parent.Revision || actual.LayerDigest() != parent.LayerDigest {
				return nil, newError(Denied, "parent_drift")
			}
			children[parent.LayerID] = append(children[parent.LayerID], layer.LayerID)
		}
	}
	ready := make([]VerifiedLayer, 0, len(layers))
	for id, degree := range indegree {
		if degree == 0 {
			ready = append(ready, byID[id])
		}
	}
	ordered := make([]VerifiedLayer, 0, len(layers))
	for len(ready) > 0 {
		slices.SortFunc(ready, compareVerifiedLayers)
		next := ready[0]
		ready = ready[1:]
		ordered = append(ordered, next)
		for _, child := range children[next.Layer().LayerID] {
			indegree[child]--
			if indegree[child] == 0 {
				ready = append(ready, byID[child])
			}
		}
	}
	if len(ordered) != len(layers) {
		return nil, newError(Denied, "layer_cycle")
	}
	if ordered[0].Layer().Kind != "baseline" {
		return nil, newError(Denied, "baseline_order")
	}
	return ordered, nil
}

func mergeOrdered(ctx context.Context, request Request, ordered []VerifiedLayer) (*candidateState, error) {
	first := ordered[0].Layer().Contribution
	state := &candidateState{request: request, ordered: append([]VerifiedLayer(nil), ordered...),
		deployment: first.DeploymentProfile, capabilities: append([]ArtifactRef(nil), first.CapabilityBundles...),
		policies: append([]ArtifactRef(nil), first.PolicyBundles...), endpoints: append([]string(nil), first.EndpointReferences...),
		permissions: append([]string(nil), first.Permissions...), limits: first.Limits, features: first.Features,
		offlineBundleDigest: first.OfflineBundleDigest, bindings: make([]LayerBinding, 0, len(ordered))}
	for index, verified := range ordered {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		layer := verified.Layer()
		if index > 0 {
			if layer.Contribution.DeploymentProfile != state.deployment {
				return nil, newError(Denied, "deployment_profile_drift")
			}
			var err error
			state.capabilities, err = mergeArtifacts(state.capabilities, layer.Contribution.CapabilityBundles)
			if err != nil {
				return nil, err
			}
			state.policies, err = mergeArtifacts(state.policies, layer.Contribution.PolicyBundles)
			if err != nil {
				return nil, err
			}
			if !isSubset(layer.Contribution.EndpointReferences, state.endpoints) {
				return nil, newError(Denied, "endpoint_widening")
			}
			if !isSubset(layer.Contribution.Permissions, state.permissions) {
				return nil, newError(Denied, "permission_widening")
			}
			if limitsWiden(layer.Contribution.Limits, state.limits) {
				return nil, newError(Denied, "limit_widening")
			}
			if featuresWiden(layer.Contribution.Features, state.features) {
				return nil, newError(Denied, "feature_widening")
			}
			if layer.Contribution.OfflineBundleDigest != state.offlineBundleDigest {
				return nil, newError(Denied, "offline_bundle_drift")
			}
			state.endpoints = append([]string(nil), layer.Contribution.EndpointReferences...)
			state.permissions = append([]string(nil), layer.Contribution.Permissions...)
			state.limits = minimumLimits(state.limits, layer.Contribution.Limits)
			state.features = intersectFeatures(state.features, layer.Contribution.Features)
		}
		binding, err := layerBinding(verified)
		if err != nil {
			return nil, err
		}
		state.bindings = append(state.bindings, binding)
	}
	return state, nil
}

func layerBinding(verified VerifiedLayer) (LayerBinding, error) {
	envelope := verified.validated.Value()
	encoded, err := json.Marshal(envelope.Signatures)
	if err != nil {
		return LayerBinding{}, newError(Denied, "signature_set_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return LayerBinding{}, newError(Denied, "signature_set_encoding")
	}
	publisherRevision := uint64(0)
	for _, signature := range envelope.Signatures {
		if signature.Role == "publisher" {
			publisherRevision = signature.KeyRevision
		}
	}
	return LayerBinding{LayerID: envelope.Layer.LayerID, Name: envelope.Layer.Name, Kind: envelope.Layer.Kind,
		Revision: envelope.Layer.Revision, Precedence: envelope.Layer.Precedence, LayerDigest: verified.LayerDigest(),
		PredecessorDigest: envelope.Layer.PredecessorDigest, SignatureSetDigest: digestBytes(signatureSetDomain, canonical),
		PublisherKeyRevision: publisherRevision, TrustRevision: verified.TrustRevision(),
		RevocationRevision:          verified.RevocationRevision(),
		RollbackAuthorizationDigest: envelope.Layer.RollbackAuthorizationDigest}, nil
}

func mergeArtifacts(current, added []ArtifactRef) ([]ArtifactRef, error) {
	byID := make(map[string]ArtifactRef, len(current)+len(added))
	for _, ref := range current {
		byID[ref.ID] = ref
	}
	for _, ref := range added {
		if prior, exists := byID[ref.ID]; exists && prior != ref {
			return nil, newError(Denied, "artifact_conflict")
		}
		byID[ref.ID] = ref
	}
	result := make([]ArtifactRef, 0, len(byID))
	for _, ref := range byID {
		result = append(result, ref)
	}
	slices.SortFunc(result, compareArtifactRefs)
	return result, nil
}

func validExactTarget(value ExactTarget) bool {
	return oneOf(value.DeploymentKind, "compose", "native_server", "native_workstation") &&
		oneOf(value.ConnectivityMode, "air_gapped", "connected", "restricted_connected") &&
		oneOf(value.Platform, "darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64") &&
		oneOf(value.Surface, "api", "cli", "headless", "test", "web")
}
func targetCovered(value Target, target ExactTarget) bool {
	return slices.Contains(value.DeploymentKinds, target.DeploymentKind) &&
		slices.Contains(value.ConnectivityModes, target.ConnectivityMode) && slices.Contains(value.Platforms, target.Platform) &&
		slices.Contains(value.Surfaces, target.Surface)
}
func compareVerifiedLayers(left, right VerifiedLayer) int {
	a, b := left.Layer(), right.Layer()
	if a.Precedence != b.Precedence {
		return compareUint(a.Precedence, b.Precedence)
	}
	if kindRank(a.Kind) != kindRank(b.Kind) {
		return compareUint(uint64(kindRank(a.Kind)), uint64(kindRank(b.Kind)))
	}
	if a.Name != b.Name {
		return compareText(a.Name, b.Name)
	}
	if a.LayerID != b.LayerID {
		return compareText(a.LayerID, b.LayerID)
	}
	if a.Revision != b.Revision {
		return compareUint(a.Revision, b.Revision)
	}
	return compareText(left.LayerDigest(), right.LayerDigest())
}
func compareArtifactRefs(left, right ArtifactRef) int {
	if left.ID != right.ID {
		return compareText(left.ID, right.ID)
	}
	if left.Revision != right.Revision {
		return compareUint(left.Revision, right.Revision)
	}
	return compareText(left.Digest, right.Digest)
}
func kindRank(kind string) int {
	return slices.Index([]string{"baseline", "deployment", "connectivity", "surface", "site", "overlay"}, kind)
}
func compareText(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
func compareUint(left, right uint64) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
func isSubset(candidate, current []string) bool {
	for _, value := range candidate {
		if !slices.Contains(current, value) {
			return false
		}
	}
	return true
}
func limitsWiden(a, b Limits) bool {
	return a.MaxConcurrency > b.MaxConcurrency || a.MaxContextBytes > b.MaxContextBytes || a.MaxDurationMS > b.MaxDurationMS || a.MaxEvidenceBytes > b.MaxEvidenceBytes || a.MaxModelTokens > b.MaxModelTokens || a.MaxToolCalls > b.MaxToolCalls
}
func minimumLimits(a, b Limits) Limits {
	return Limits{min(a.MaxConcurrency, b.MaxConcurrency), min(a.MaxContextBytes, b.MaxContextBytes), min(a.MaxDurationMS, b.MaxDurationMS), min(a.MaxEvidenceBytes, b.MaxEvidenceBytes), min(a.MaxModelTokens, b.MaxModelTokens), min(a.MaxToolCalls, b.MaxToolCalls)}
}
func featuresWiden(a, b Features) bool {
	return a.ExternalConnectivity && !b.ExternalConnectivity || a.ExtensionLifecycle && !b.ExtensionLifecycle || a.ModelInference && !b.ModelInference || a.Retrieval && !b.Retrieval || a.ToolDispatch && !b.ToolDispatch
}
func intersectFeatures(a, b Features) Features {
	return Features{a.ExternalConnectivity && b.ExternalConnectivity, a.ExtensionLifecycle && b.ExtensionLifecycle, a.ModelInference && b.ModelInference, a.Retrieval && b.Retrieval, a.ToolDispatch && b.ToolDispatch}
}
