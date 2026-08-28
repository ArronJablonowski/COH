package capabilityseam

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	definitionDigestDomain = "COH-CAPABILITY-DEFINITION-V1\x00"
	providerDigestDomain   = "COH-CAPABILITY-PROVIDER-V1\x00"
	consumerDigestDomain   = "COH-CAPABILITY-CONSUMER-V1\x00"
	scopeDigestDomain      = "COH-CAPABILITY-SCOPE-V1\x00"
	permissionDigestDomain = "COH-CAPABILITY-PERMISSIONS-V1\x00"
)

// Resolve builds one complete immutable graph under current qualification
// authority. It performs no activation and returns no executable provider
// object or action authority.
func (resolver *Resolver) Resolve(ctx context.Context, bundle ValidatedBundle,
	authority QualificationAuthoritySnapshot) (ValidatedGraph, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedGraph{}, err
	}
	if resolver == nil || resolver.clock == nil {
		return ValidatedGraph{}, newError(InvalidInput, "resolver_clock_required")
	}
	if bundle.Digest() == "" || len(bundle.CanonicalBytes()) == 0 {
		return ValidatedGraph{}, newError(InvalidInput, "validated_bundle_required")
	}
	value := bundle.Value()
	definitions := make(map[string]Definition, len(value.Definitions))
	selected := make(map[string]Provider, len(value.Providers))
	providersByCapability := make(map[string][]Provider, len(value.Providers))
	for _, definition := range value.Definitions {
		definitions[capabilityID(definition.Capability)] = definition
	}
	for _, provider := range value.Providers {
		identifier := capabilityID(provider.Capability)
		if _, exists := definitions[identifier]; !exists {
			return ValidatedGraph{}, newError(Denied, "provider_definition_missing")
		}
		providersByCapability[identifier] = append(providersByCapability[identifier], provider)
	}
	for _, definition := range value.Definitions {
		identifier := capabilityID(definition.Capability)
		providers := providersByCapability[identifier]
		if len(providers) > 1 {
			return ValidatedGraph{}, newError(Denied, "provider_ambiguous")
		}
		if len(providers) == 0 {
			if definition.Multiplicity == "exactly_one" {
				return ValidatedGraph{}, newError(Denied, "provider_missing")
			}
			continue
		}
		selected[identifier] = providers[0]
	}
	if err := validateResolutionBindings(value, definitions, selected); err != nil {
		return ValidatedGraph{}, err
	}
	if err := validateQualificationAuthority(resolver.clock.Now(), value, selected, authority); err != nil {
		return ValidatedGraph{}, err
	}

	edges, order, err := resolveDependencies(ctx, value.Definitions, definitions, selected)
	if err != nil {
		return ValidatedGraph{}, err
	}
	graph, err := buildGraph(value, bundle.Digest(), selected, edges, order)
	if err != nil {
		return ValidatedGraph{}, err
	}
	if err := contextError(ctx); err != nil {
		return ValidatedGraph{}, err
	}
	digest, err := graphDigest(graph)
	if err != nil {
		return ValidatedGraph{}, newError(Denied, "graph_encoding")
	}
	graph.GraphDigest = digest
	encoded, err := json.Marshal(graph)
	if err != nil {
		return ValidatedGraph{}, newError(Denied, "graph_encoding")
	}
	return DecodeGraph(ctx, encoded)
}

func resolveDependencies(ctx context.Context, ordered []Definition, definitions map[string]Definition,
	selected map[string]Provider) ([]DependencyEdge, []string, error) {
	edges := make([]DependencyEdge, 0)
	dependencies := make(map[string][]string, len(ordered))
	for _, definition := range ordered {
		if err := contextError(ctx); err != nil {
			return nil, nil, err
		}
		identifier := capabilityID(definition.Capability)
		for _, dependency := range definition.Dependencies {
			target := capabilityID(dependency.Capability)
			if _, exists := definitions[target]; !exists {
				if dependency.Kind == "required" {
					return nil, nil, newError(Denied, "dependency_missing")
				}
				continue
			}
			if _, active := selected[target]; !active {
				if dependency.Kind == "required" {
					return nil, nil, newError(Denied, "dependency_provider_missing")
				}
				continue
			}
			dependencies[identifier] = append(dependencies[identifier], target)
			edges = append(edges, DependencyEdge{From: definitionNodeID(identifier), To: definitionNodeID(target), Kind: dependency.Kind})
		}
	}
	slices.SortFunc(edges, func(left, right DependencyEdge) int {
		return compareStrings(left.From+"\x00"+left.To+"\x00"+left.Kind, right.From+"\x00"+right.To+"\x00"+right.Kind)
	})
	state := make(map[string]uint8, len(ordered))
	order := make([]string, 0, len(ordered))
	var visit func(string) error
	visit = func(identifier string) error {
		if err := contextError(ctx); err != nil {
			return err
		}
		if state[identifier] == 1 {
			return newError(Denied, "dependency_cycle")
		}
		if state[identifier] == 2 {
			return nil
		}
		state[identifier] = 1
		for _, dependency := range dependencies[identifier] {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		state[identifier] = 2
		order = append(order, definitionNodeID(identifier))
		return nil
	}
	for _, definition := range ordered {
		if err := visit(capabilityID(definition.Capability)); err != nil {
			return nil, nil, err
		}
	}
	return edges, order, nil
}

func buildGraph(bundle Bundle, bundleDigest string, selected map[string]Provider, dependencyEdges []DependencyEdge,
	order []string) (Graph, error) {
	graph := Graph{
		SchemaVersion: GraphSchemaVersion, ContractVersion: ContractVersion,
		BundleDigest: bundleDigest, ProfileDigest: bundle.ProfileDigest, Revision: bundle.Revision,
		DefinitionNodes: make([]CapabilityNode, 0, len(bundle.Definitions)),
		ProviderNodes:   make([]ProviderNode, 0, len(selected)), ConsumerNodes: make([]ConsumerNode, 0, len(bundle.Consumers)),
		DependencyEdges: dependencyEdges, ConsumerEdges: make([]ConsumerEdge, 0, len(bundle.Consumers)), ResolutionOrder: order,
	}
	for _, definition := range bundle.Definitions {
		digest, err := digestRecord(definitionDigestDomain, definition)
		if err != nil {
			return Graph{}, err
		}
		graph.DefinitionNodes = append(graph.DefinitionNodes, CapabilityNode{
			NodeID: definitionNodeID(capabilityID(definition.Capability)), DeclarationDigest: digest,
			NonReplaceable: definition.Replaceability == "non_replaceable",
		})
	}
	for identifier, provider := range selected {
		declarationDigest, err := digestRecord(providerDigestDomain, provider)
		if err != nil {
			return Graph{}, err
		}
		scopeDigest, err := digestRecord(scopeDigestDomain, provider.Scope)
		if err != nil {
			return Graph{}, err
		}
		permissionDigest, err := digestRecord(permissionDigestDomain, provider.Permissions)
		if err != nil {
			return Graph{}, err
		}
		graph.ProviderNodes = append(graph.ProviderNodes, ProviderNode{
			NodeID: providerNodeID(provider), CapabilityNodeID: definitionNodeID(identifier),
			DeclarationDigest: declarationDigest, QualificationDigest: provider.Qualification.RecordDigest,
			ScopeDigest: scopeDigest, PermissionDigest: permissionDigest,
		})
	}
	for _, consumer := range bundle.Consumers {
		identifier := capabilityID(consumer.Capability)
		provider, exists := selected[identifier]
		if !exists {
			return Graph{}, newError(Denied, "consumer_provider_missing")
		}
		declarationDigest, err := digestRecord(consumerDigestDomain, consumer)
		if err != nil {
			return Graph{}, err
		}
		scopeDigest, err := digestRecord(scopeDigestDomain, consumer.Scope)
		if err != nil {
			return Graph{}, err
		}
		permissionDigest, err := digestRecord(permissionDigestDomain, consumer.Permissions)
		if err != nil {
			return Graph{}, err
		}
		graph.ConsumerNodes = append(graph.ConsumerNodes, ConsumerNode{NodeID: consumerNodeID(consumer),
			DeclarationDigest: declarationDigest, ScopeDigest: scopeDigest, PermissionDigest: permissionDigest})
		graph.ConsumerEdges = append(graph.ConsumerEdges, ConsumerEdge{Consumer: consumerNodeID(consumer),
			Capability: definitionNodeID(identifier), Provider: providerNodeID(provider), AccessMode: consumer.AccessMode})
	}
	slices.SortFunc(graph.ProviderNodes, func(left, right ProviderNode) int { return compareStrings(left.NodeID, right.NodeID) })
	slices.SortFunc(graph.ConsumerNodes, func(left, right ConsumerNode) int { return compareStrings(left.NodeID, right.NodeID) })
	slices.SortFunc(graph.ConsumerEdges, func(left, right ConsumerEdge) int {
		return compareStrings(left.Consumer+"\x00"+left.Capability+"\x00"+left.Provider,
			right.Consumer+"\x00"+right.Capability+"\x00"+right.Provider)
	})
	return graph, nil
}

func digestRecord(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", newError(Denied, "record_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newError(Denied, "record_encoding")
	}
	return digestBytes(domain, canonical), nil
}

func definitionNodeID(identifier string) string { return "capability/" + identifier }
func providerNodeID(value Provider) string {
	return "provider/" + value.ProviderID + "@" + value.ProviderVersion
}
func consumerNodeID(value Consumer) string { return "consumer/" + value.ConsumerID }
func compareStrings(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}
