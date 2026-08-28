package command

import (
	"context"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/capabilityseam"
	"github.com/ArronJablonowski/COH/internal/domain/profilecomposition"
)

// Inspect produces the single canonical, redacted projection consumed by all
// operator surfaces. It never exposes source declarations or runtime objects.
func (prepared PreparedProfileCapabilities) Inspect(ctx context.Context,
	resolved profilecomposition.ValidatedResolvedProfile, graph capabilityseam.ValidatedGraph,
) (profilecomposition.ValidatedInspection, error) {
	if err := profileCompositionContextError(ctx); err != nil {
		return profilecomposition.ValidatedInspection{}, err
	}
	profile := resolved.Value()
	graphValue := graph.Value()
	bundle := prepared.bundle.Value()
	if prepared.bundle.Digest() == "" || prepared.candidate.ProfileBindingDigest() == "" || resolved.Digest() == "" ||
		graph.Digest() == "" || profile.CompositionDigest != resolved.Digest() ||
		profile.ProfileBindingDigest != prepared.candidate.ProfileBindingDigest() ||
		profile.CapabilityGraphDigest != graph.Digest() || graphValue.GraphDigest != graph.Digest() ||
		graphValue.BundleDigest != prepared.bundle.Digest() || graphValue.ProfileDigest != profile.ProfileBindingDigest ||
		bundle.ProfileDigest != profile.ProfileBindingDigest || bundle.Revision != profile.Revision {
		return profilecomposition.ValidatedInspection{}, profilecomposition.NewError(profilecomposition.Denied, "inspection_binding")
	}
	expectedResolved, err := prepared.candidate.Finalize(ctx, graph.Digest())
	if err != nil || expectedResolved.Digest() != resolved.Digest() ||
		!slices.Equal(expectedResolved.CanonicalBytes(), resolved.CanonicalBytes()) {
		return profilecomposition.ValidatedInspection{}, profilecomposition.NewError(profilecomposition.Denied, "inspection_profile_binding")
	}
	inspection := profilecomposition.Inspection{SchemaVersion: profilecomposition.InspectionSchemaVersion,
		ContractVersion: profilecomposition.ContractVersion, ProfileID: profile.ProfileID, ProfileRevision: profile.Revision,
		Target: profile.Target, ProfileBindingDigest: profile.ProfileBindingDigest, CompositionDigest: profile.CompositionDigest,
		CapabilityGraphDigest: profile.CapabilityGraphDigest}
	for position, binding := range profile.OrderedLayers {
		inspection.Lineage = append(inspection.Lineage, profilecomposition.InspectionLineage{Position: uint64(position),
			LayerID: binding.LayerID, Name: binding.Name, Kind: binding.Kind, Revision: binding.Revision,
			LayerDigest: binding.LayerDigest, SignatureSetDigest: binding.SignatureSetDigest,
			QualificationState: "qualified", TrustRevision: binding.TrustRevision,
			RevocationRevision: binding.RevocationRevision})
	}
	definitions := make(map[string]capabilityseam.Definition, len(bundle.Definitions))
	for _, definition := range bundle.Definitions {
		definitions[capabilityNodeID(definition.Capability)] = definition
	}
	providers := make(map[string]capabilityseam.Provider, len(bundle.Providers))
	for _, provider := range bundle.Providers {
		providers[providerNodeID(provider)] = provider
	}
	consumers := make(map[string]struct{}, len(bundle.Consumers))
	for _, consumer := range bundle.Consumers {
		consumers["consumer/"+consumer.ConsumerID] = struct{}{}
	}
	for _, node := range graphValue.DefinitionNodes {
		definition, exists := definitions[node.NodeID]
		if !exists {
			return profilecomposition.ValidatedInspection{}, profilecomposition.NewError(profilecomposition.Denied, "inspection_definition_binding")
		}
		inspection.Definitions = append(inspection.Definitions, profilecomposition.InspectionDefinition{NodeID: node.NodeID,
			CapabilityVersion: definition.Capability.Version, OwnerModule: definition.Owner.Module,
			DeclarationDigest: node.DeclarationDigest, AccessPolicy: definition.AccessPolicy,
			Lifecycle: definition.Lifecycle, NonReplaceable: node.NonReplaceable})
	}
	for _, node := range graphValue.ProviderNodes {
		provider, exists := providers[node.NodeID]
		definition, definitionExists := definitions[node.CapabilityNodeID]
		if !exists || !definitionExists || provider.Capability != definition.Capability {
			return profilecomposition.ValidatedInspection{}, profilecomposition.NewError(profilecomposition.Denied, "inspection_provider_binding")
		}
		inspection.Providers = append(inspection.Providers, profilecomposition.InspectionProvider{NodeID: node.NodeID,
			CapabilityNodeID: node.CapabilityNodeID, ProviderVersion: provider.ProviderVersion,
			ArtifactDigest: provider.ArtifactDigest, QualificationDigest: node.QualificationDigest,
			QualificationState: "qualified", ScopeDigest: node.ScopeDigest, PermissionDigest: node.PermissionDigest})
	}
	for _, node := range graphValue.ConsumerNodes {
		if _, exists := consumers[node.NodeID]; !exists {
			return profilecomposition.ValidatedInspection{}, profilecomposition.NewError(profilecomposition.Denied, "inspection_consumer_binding")
		}
		inspection.Consumers = append(inspection.Consumers, profilecomposition.InspectionConsumer{NodeID: node.NodeID,
			DeclarationDigest: node.DeclarationDigest, ScopeDigest: node.ScopeDigest, PermissionDigest: node.PermissionDigest})
	}
	for _, edge := range graphValue.DependencyEdges {
		inspection.DependencyEdges = append(inspection.DependencyEdges,
			profilecomposition.InspectionDependencyEdge{From: edge.From, To: edge.To, Kind: edge.Kind})
	}
	for _, edge := range graphValue.ConsumerEdges {
		inspection.ConsumerEdges = append(inspection.ConsumerEdges, profilecomposition.InspectionConsumerEdge{
			Consumer: edge.Consumer, Capability: edge.Capability, Provider: edge.Provider, AccessMode: edge.AccessMode})
	}
	valueSources := prepared.candidate.ValueSourceDigests()
	limitNames := [6]string{"max_concurrency", "max_context_bytes", "max_duration_ms", "max_evidence_bytes", "max_model_tokens", "max_tool_calls"}
	limitValues := [6]uint64{profile.Limits.MaxConcurrency, profile.Limits.MaxContextBytes, profile.Limits.MaxDurationMS,
		profile.Limits.MaxEvidenceBytes, profile.Limits.MaxModelTokens, profile.Limits.MaxToolCalls}
	for index, name := range limitNames {
		inspection.Limits = append(inspection.Limits, profilecomposition.InspectionLimit{Name: name,
			Value: limitValues[index], SourceLayerDigest: valueSources.Limits[index]})
	}
	featureNames := [5]string{"external_connectivity", "extension_lifecycle", "model_inference", "retrieval", "tool_dispatch"}
	featureValues := [5]bool{profile.Features.ExternalConnectivity, profile.Features.ExtensionLifecycle,
		profile.Features.ModelInference, profile.Features.Retrieval, profile.Features.ToolDispatch}
	for index, name := range featureNames {
		inspection.FeatureStates = append(inspection.FeatureStates, profilecomposition.InspectionFeature{Name: name,
			Enabled: featureValues[index], SourceLayerDigest: valueSources.Features[index]})
	}
	slices.SortFunc(inspection.Definitions, func(a, b profilecomposition.InspectionDefinition) int { return compareProfileText(a.NodeID, b.NodeID) })
	slices.SortFunc(inspection.Providers, func(a, b profilecomposition.InspectionProvider) int { return compareProfileText(a.NodeID, b.NodeID) })
	slices.SortFunc(inspection.Consumers, func(a, b profilecomposition.InspectionConsumer) int { return compareProfileText(a.NodeID, b.NodeID) })
	slices.SortFunc(inspection.DependencyEdges, func(a, b profilecomposition.InspectionDependencyEdge) int {
		return compareProfileText(a.From+"\x00"+a.To+"\x00"+a.Kind, b.From+"\x00"+b.To+"\x00"+b.Kind)
	})
	slices.SortFunc(inspection.ConsumerEdges, func(a, b profilecomposition.InspectionConsumerEdge) int {
		return compareProfileText(a.Consumer+"\x00"+a.Capability+"\x00"+a.Provider,
			b.Consumer+"\x00"+b.Capability+"\x00"+b.Provider)
	})
	return profilecomposition.PublishInspection(ctx, inspection)
}

func capabilityNodeID(value capabilityseam.CapabilityRef) string {
	return "capability/" + value.Name + "@" + value.Version
}
func providerNodeID(value capabilityseam.Provider) string {
	return "provider/" + value.ProviderID + "@" + value.ProviderVersion
}
