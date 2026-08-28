package profilecomposition

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

var (
	inspectionSemverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?$`)
	inspectionTokenPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/+@-]{0,255}$`)
)

func (candidate Candidate) ValueSourceDigests() ValueSourceDigests {
	if candidate.state == nil || len(candidate.state.ordered) == 0 {
		return ValueSourceDigests{}
	}
	first := candidate.state.ordered[0]
	result := ValueSourceDigests{}
	for index := range result.Limits {
		result.Limits[index] = first.LayerDigest()
	}
	for index := range result.Features {
		result.Features[index] = first.LayerDigest()
	}
	limits := first.Layer().Contribution.Limits
	features := first.Layer().Contribution.Features
	for _, verified := range candidate.state.ordered[1:] {
		next := verified.Layer().Contribution
		limitValues := [6]uint64{next.Limits.MaxConcurrency, next.Limits.MaxContextBytes, next.Limits.MaxDurationMS,
			next.Limits.MaxEvidenceBytes, next.Limits.MaxModelTokens, next.Limits.MaxToolCalls}
		currentLimits := [6]uint64{limits.MaxConcurrency, limits.MaxContextBytes, limits.MaxDurationMS,
			limits.MaxEvidenceBytes, limits.MaxModelTokens, limits.MaxToolCalls}
		for index := range limitValues {
			if limitValues[index] < currentLimits[index] {
				result.Limits[index] = verified.LayerDigest()
			}
		}
		featureValues := [5]bool{next.Features.ExternalConnectivity, next.Features.ExtensionLifecycle,
			next.Features.ModelInference, next.Features.Retrieval, next.Features.ToolDispatch}
		currentFeatures := [5]bool{features.ExternalConnectivity, features.ExtensionLifecycle,
			features.ModelInference, features.Retrieval, features.ToolDispatch}
		for index := range featureValues {
			if currentFeatures[index] && !featureValues[index] {
				result.Features[index] = verified.LayerDigest()
			}
		}
		limits = minimumLimits(limits, next.Limits)
		features = intersectFeatures(features, next.Features)
	}
	return result
}

// PublishInspection validates and canonically seals the only operator-safe
// projection. The command composition root must construct the projection.
func PublishInspection(ctx context.Context, value Inspection) (ValidatedInspection, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedInspection{}, err
	}
	if err := validateInspection(value); err != nil {
		return ValidatedInspection{}, err
	}
	value.InspectionDigest = ""
	encoded, err := json.Marshal(value)
	if err != nil {
		return ValidatedInspection{}, newError(Denied, "inspection_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return ValidatedInspection{}, newError(Denied, "inspection_encoding")
	}
	digest := digestBytes(inspectionDigestDomain, canonical)
	value.InspectionDigest = digest
	encoded, err = json.Marshal(value)
	if err != nil {
		return ValidatedInspection{}, newError(Denied, "inspection_encoding")
	}
	canonical, err = domaincontract.Canonicalize(encoded)
	if err != nil {
		return ValidatedInspection{}, newError(Denied, "inspection_encoding")
	}
	return ValidatedInspection{digest: digest, bytes: canonical}, nil
}

func validateInspection(value Inspection) error {
	if value.SchemaVersion != InspectionSchemaVersion || value.ContractVersion != ContractVersion {
		return newError(Unsupported, "unsupported_contract")
	}
	if !validUUID7(value.ProfileID) || value.ProfileRevision == 0 || value.ProfileRevision > MaximumRevision ||
		!validExactTarget(value.Target) || !validDigest(value.ProfileBindingDigest) ||
		!validDigest(value.CompositionDigest) || !validDigest(value.CapabilityGraphDigest) ||
		value.InspectionDigest != "" || len(value.Lineage) == 0 || len(value.Lineage) > 128 ||
		len(value.Definitions) == 0 || len(value.Definitions) > 1024 || len(value.Providers) == 0 ||
		len(value.Providers) > 1024 || len(value.Consumers) == 0 || len(value.Consumers) > 4096 ||
		len(value.DependencyEdges) > 8192 || len(value.ConsumerEdges) == 0 || len(value.ConsumerEdges) > 8192 {
		return newError(InvalidInput, "inspection_identity")
	}
	for index, item := range value.Lineage {
		if item.Position != uint64(index) || !validUUID7(item.LayerID) || !validToken(item.Name) ||
			!oneOf(item.Kind, "baseline", "connectivity", "deployment", "overlay", "site", "surface") ||
			item.Revision == 0 || item.Revision > MaximumRevision || !validDigest(item.LayerDigest) ||
			!validDigest(item.SignatureSetDigest) || item.QualificationState != "qualified" ||
			item.TrustRevision == 0 || item.TrustRevision > MaximumRevision || item.RevocationRevision > MaximumRevision {
			return newError(InvalidInput, "inspection_lineage")
		}
	}
	if !validInspectionGraph(value) || !validInspectionStates(value) {
		return newError(InvalidInput, "inspection_shape")
	}
	return nil
}

func validInspectionGraph(value Inspection) bool {
	definitionIDs := make([]string, len(value.Definitions))
	for index, item := range value.Definitions {
		if !validInspectionToken(item.NodeID) || !inspectionSemverPattern.MatchString(item.CapabilityVersion) ||
			!validInspectionToken(item.OwnerModule) || !validDigest(item.DeclarationDigest) ||
			!oneOf(item.AccessPolicy, "broker_intent_only", "read_only_service") ||
			!oneOf(item.Lifecycle, "restart_bound", "static", "transactional") {
			return false
		}
		definitionIDs[index] = item.NodeID
	}
	providerIDs := make([]string, len(value.Providers))
	for index, item := range value.Providers {
		if !validInspectionToken(item.NodeID) || !slices.Contains(definitionIDs, item.CapabilityNodeID) ||
			!inspectionSemverPattern.MatchString(item.ProviderVersion) || !validDigest(item.ArtifactDigest) ||
			!validDigest(item.QualificationDigest) || item.QualificationState != "qualified" ||
			!validDigest(item.ScopeDigest) || !validDigest(item.PermissionDigest) {
			return false
		}
		providerIDs[index] = item.NodeID
	}
	consumerIDs := make([]string, len(value.Consumers))
	for index, item := range value.Consumers {
		if !validInspectionToken(item.NodeID) || !validDigest(item.DeclarationDigest) ||
			!validDigest(item.ScopeDigest) || !validDigest(item.PermissionDigest) {
			return false
		}
		consumerIDs[index] = item.NodeID
	}
	if !sortedUnique(definitionIDs) || !sortedUnique(providerIDs) || !sortedUnique(consumerIDs) {
		return false
	}
	dependencyIDs := make([]string, len(value.DependencyEdges))
	for index, edge := range value.DependencyEdges {
		if !slices.Contains(definitionIDs, edge.From) || !slices.Contains(definitionIDs, edge.To) ||
			!oneOf(edge.Kind, "optional", "required") {
			return false
		}
		dependencyIDs[index] = edge.From + "\x00" + edge.To + "\x00" + edge.Kind
	}
	consumerEdgeIDs := make([]string, len(value.ConsumerEdges))
	for index, edge := range value.ConsumerEdges {
		if !slices.Contains(consumerIDs, edge.Consumer) || !slices.Contains(definitionIDs, edge.Capability) ||
			!slices.Contains(providerIDs, edge.Provider) || !oneOf(edge.AccessMode, "broker_intent", "read_only_service") {
			return false
		}
		consumerEdgeIDs[index] = edge.Consumer + "\x00" + edge.Capability + "\x00" + edge.Provider
	}
	return sortedUnique(dependencyIDs) && sortedUnique(consumerEdgeIDs)
}

func validInspectionStates(value Inspection) bool {
	limitNames := []string{"max_concurrency", "max_context_bytes", "max_duration_ms", "max_evidence_bytes", "max_model_tokens", "max_tool_calls"}
	featureNames := []string{"external_connectivity", "extension_lifecycle", "model_inference", "retrieval", "tool_dispatch"}
	if len(value.Limits) != len(limitNames) || len(value.FeatureStates) != len(featureNames) {
		return false
	}
	lineageDigests := make([]string, len(value.Lineage))
	for index, item := range value.Lineage {
		lineageDigests[index] = item.LayerDigest
	}
	for index, item := range value.Limits {
		if item.Name != limitNames[index] || item.Value > 1073741824 ||
			!validDigest(item.SourceLayerDigest) || !slices.Contains(lineageDigests, item.SourceLayerDigest) {
			return false
		}
	}
	for index, item := range value.FeatureStates {
		if item.Name != featureNames[index] || !validDigest(item.SourceLayerDigest) ||
			!slices.Contains(lineageDigests, item.SourceLayerDigest) {
			return false
		}
	}
	return true
}

func validInspectionToken(value string) bool {
	return inspectionTokenPattern.MatchString(value)
}
