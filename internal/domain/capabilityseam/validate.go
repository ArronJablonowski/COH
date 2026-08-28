package capabilityseam

import (
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	tokenPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/+-]{0,255}$`)
	nodePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/+@-]{0,255}$`)
	semverPattern = regexp.MustCompile(`^[0-9]+[.][0-9]+[.][0-9]+(-[0-9A-Za-z.-]+)?([+][0-9A-Za-z.-]+)?$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuid7Pattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

func validateBundle(value Bundle) error {
	if value.SchemaVersion != BundleSchemaVersion || value.ContractVersion != ContractVersion {
		return newError(Unsupported, "unsupported_contract")
	}
	if !validToken(value.BundleID, 128) || value.Revision == 0 || !validDigest(value.ProfileDigest) ||
		len(value.Definitions) == 0 || len(value.Definitions) > 1024 ||
		len(value.Providers) == 0 || len(value.Providers) > 1024 ||
		len(value.Consumers) == 0 || len(value.Consumers) > 4096 {
		return newError(InvalidInput, "bundle_identity")
	}
	definitionIDs := make([]string, len(value.Definitions))
	for index, definition := range value.Definitions {
		if err := validateDefinition(definition); err != nil {
			return err
		}
		definitionIDs[index] = capabilityID(definition.Capability)
	}
	providerIDs := make([]string, len(value.Providers))
	for index, provider := range value.Providers {
		if err := validateProvider(provider, value.ProfileDigest); err != nil {
			return err
		}
		providerIDs[index] = provider.ProviderID
	}
	consumerIDs := make([]string, len(value.Consumers))
	for index, consumer := range value.Consumers {
		if err := validateConsumer(consumer); err != nil {
			return err
		}
		consumerIDs[index] = consumer.ConsumerID
	}
	if !sortedUnique(definitionIDs) || !sortedUnique(providerIDs) || !sortedUnique(consumerIDs) {
		return newError(InvalidInput, "declaration_order")
	}
	return nil
}

func validateDefinition(value Definition) error {
	if !validCapability(value.Capability) || !validOwner(value.Owner) ||
		!oneOf(value.AuthorityClass, "authority", "data_plane") ||
		!oneOf(value.Replaceability, "non_replaceable", "qualified_provider") ||
		!oneOf(value.Multiplicity, "exactly_one", "zero_or_one") ||
		!oneOf(value.Lifecycle, "static", "restart_bound", "transactional") ||
		!validPermissions(value.Permissions) || len(value.Dependencies) > 128 {
		return newError(InvalidInput, "definition")
	}
	if value.AuthorityClass == "authority" && (value.Replaceability != "non_replaceable" ||
		value.Multiplicity != "exactly_one" || value.Lifecycle != "static") {
		return newError(Denied, "authority_replaceable")
	}
	identities := make([]string, len(value.Dependencies))
	for index, dependency := range value.Dependencies {
		if !validCapability(dependency.Capability) || !oneOf(dependency.Kind, "required", "optional") {
			return newError(InvalidInput, "dependency")
		}
		identities[index] = capabilityID(dependency.Capability)
	}
	if !sortedUnique(identities) {
		return newError(InvalidInput, "dependency_order")
	}
	return nil
}

func validateProvider(value Provider, profileDigest string) error {
	if !validToken(value.ProviderID, 128) || !semverPattern.MatchString(value.ProviderVersion) ||
		!validDigest(value.ArtifactDigest) || !validOwner(value.Owner) || value.Owner.ArtifactDigest != value.ArtifactDigest ||
		!validCapability(value.Capability) ||
		!validScope(value.Scope) || !validPermissions(value.Permissions) ||
		!oneOf(value.Lifecycle, "static", "restart_bound", "transactional") ||
		!oneOf(value.BrokerRoute, "not_applicable", "typed_intent") {
		return newError(InvalidInput, "provider")
	}
	qualification := value.Qualification
	issued, issuedErr := time.Parse(time.RFC3339Nano, qualification.IssuedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, qualification.ExpiresAt)
	if !uuid7Pattern.MatchString(qualification.RecordID) || !validDigest(qualification.RecordDigest) ||
		qualification.ProviderArtifactDigest != value.ArtifactDigest || qualification.ProfileDigest != profileDigest ||
		!oneOf(qualification.Status, "qualified", "revoked") || issuedErr != nil || expiresErr != nil ||
		!expires.After(issued) || qualification.AuthorityRevision == 0 ||
		qualification.Status == "qualified" && qualification.RevocationRevision != 0 ||
		qualification.Status == "revoked" && qualification.RevocationRevision == 0 {
		return newError(InvalidInput, "qualification")
	}
	return nil
}

func validateConsumer(value Consumer) error {
	if !validToken(value.ConsumerID, 128) || !validOwner(value.Owner) || !validCapability(value.Capability) ||
		!validScope(value.Scope) || !validPermissions(value.Permissions) ||
		!oneOf(value.AccessMode, "broker_intent", "read_only_service") {
		return newError(InvalidInput, "consumer")
	}
	return nil
}

func validateGraph(value Graph) error {
	if value.SchemaVersion != GraphSchemaVersion || value.ContractVersion != ContractVersion {
		return newError(Unsupported, "unsupported_contract")
	}
	if !validDigest(value.BundleDigest) || !validDigest(value.ProfileDigest) || value.Revision == 0 ||
		!validDigest(value.GraphDigest) || len(value.DefinitionNodes) == 0 || len(value.DefinitionNodes) > 1024 ||
		len(value.ProviderNodes) == 0 || len(value.ProviderNodes) > 1024 ||
		len(value.ConsumerNodes) == 0 || len(value.ConsumerNodes) > 4096 ||
		len(value.DependencyEdges) > 131072 || len(value.ConsumerEdges) == 0 || len(value.ConsumerEdges) > 4096 {
		return newError(InvalidInput, "graph_identity")
	}
	if !validGraphNodes(value) || !validGraphEdges(value) || !validNodeSet(value.ResolutionOrder, 1024) {
		return newError(InvalidInput, "graph_shape")
	}
	return nil
}

func validGraphNodes(value Graph) bool {
	definitions := make([]string, len(value.DefinitionNodes))
	for index, node := range value.DefinitionNodes {
		if !validNodeToken(node.NodeID) || !validDigest(node.DeclarationDigest) {
			return false
		}
		definitions[index] = node.NodeID
	}
	providers := make([]string, len(value.ProviderNodes))
	for index, node := range value.ProviderNodes {
		if !validNodeToken(node.NodeID) || !validNodeToken(node.CapabilityNodeID) ||
			!validDigest(node.DeclarationDigest) || !validDigest(node.QualificationDigest) ||
			!validDigest(node.ScopeDigest) || !validDigest(node.PermissionDigest) {
			return false
		}
		providers[index] = node.NodeID
	}
	consumers := make([]string, len(value.ConsumerNodes))
	for index, node := range value.ConsumerNodes {
		if !validNodeToken(node.NodeID) || !validDigest(node.DeclarationDigest) ||
			!validDigest(node.ScopeDigest) || !validDigest(node.PermissionDigest) {
			return false
		}
		consumers[index] = node.NodeID
	}
	return sortedUnique(definitions) && sortedUnique(providers) && sortedUnique(consumers)
}

func validGraphEdges(value Graph) bool {
	dependencies := make([]string, len(value.DependencyEdges))
	for index, edge := range value.DependencyEdges {
		if !validNodeToken(edge.From) || !validNodeToken(edge.To) || !oneOf(edge.Kind, "required", "optional") {
			return false
		}
		dependencies[index] = edge.From + "\x00" + edge.To + "\x00" + edge.Kind
	}
	consumers := make([]string, len(value.ConsumerEdges))
	for index, edge := range value.ConsumerEdges {
		if !validNodeToken(edge.Consumer) || !validNodeToken(edge.Capability) ||
			!validNodeToken(edge.Provider) || !oneOf(edge.AccessMode, "broker_intent", "read_only_service") {
			return false
		}
		consumers[index] = edge.Consumer + "\x00" + edge.Capability + "\x00" + edge.Provider
	}
	return sortedUnique(dependencies) && sortedUnique(consumers)
}

func validCapability(value CapabilityRef) bool {
	return validToken(value.Name, 128) && semverPattern.MatchString(value.Version)
}

func validOwner(value Owner) bool {
	return validToken(value.Module, 128) && validDigest(value.ArtifactDigest)
}

func validScope(value Scope) bool {
	if !uuid7Pattern.MatchString(value.OrganizationID) || !uuid7Pattern.MatchString(value.TenantID) ||
		!oneOf(value.Environment, "native_workstation", "native_server", "compose", "test") {
		return false
	}
	return value.CaseID == nil || uuid7Pattern.MatchString(*value.CaseID)
}

func validPermissions(values []string) bool { return validTokenSet(values, 128) }

func validTokenSet(values []string, maximum int) bool {
	if values == nil || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validToken(value, 128) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validNodeSet(values []string, maximum int) bool {
	if values == nil || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validNodeToken(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func sortedUnique(values []string) bool {
	if values == nil || !slices.IsSorted(values) {
		return false
	}
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return false
		}
	}
	return true
}

func capabilityID(value CapabilityRef) string { return value.Name + "@" + value.Version }
func validDigest(value string) bool           { return digestPattern.MatchString(value) }
func validToken(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && tokenPattern.MatchString(value)
}
func validNodeToken(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value && nodePattern.MatchString(value)
}
func oneOf(value string, allowed ...string) bool { return slices.Contains(allowed, value) }
