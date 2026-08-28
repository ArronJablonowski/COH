// Package capabilityseam defines the closed runtime-composition records used
// by COH. Resolving a provider never grants execution authority.
package capabilityseam

const (
	BundleSchemaVersion = "coh.capability-seam-bundle/v1"
	GraphSchemaVersion  = "coh.resolved-capability-graph/v1"
	ContractVersion     = "1.0.0"
	MaximumInputBytes   = 4 << 20

	bundleDigestDomain = "COH-CAPABILITY-SEAM-BUNDLE-V1\x00"
	graphDigestDomain  = "COH-RESOLVED-CAPABILITY-GRAPH-V1\x00"
)

type CapabilityRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Owner struct {
	Module         string `json:"module"`
	ArtifactDigest string `json:"artifact_digest"`
}

type Scope struct {
	OrganizationID string  `json:"organization_id"`
	TenantID       string  `json:"tenant_id"`
	CaseID         *string `json:"case_id"`
	Environment    string  `json:"environment"`
}

type Dependency struct {
	Capability CapabilityRef `json:"capability"`
	Kind       string        `json:"kind"`
}

type Qualification struct {
	RecordID               string `json:"record_id"`
	RecordDigest           string `json:"record_digest"`
	ProviderArtifactDigest string `json:"provider_artifact_digest"`
	ProfileDigest          string `json:"profile_digest"`
	Status                 string `json:"status"`
	IssuedAt               string `json:"issued_at"`
	ExpiresAt              string `json:"expires_at"`
	AuthorityRevision      uint64 `json:"authority_revision"`
	RevocationRevision     uint64 `json:"revocation_revision"`
}

type Definition struct {
	Capability     CapabilityRef `json:"capability"`
	Owner          Owner         `json:"owner"`
	AuthorityClass string        `json:"authority_class"`
	Replaceability string        `json:"replaceability"`
	Multiplicity   string        `json:"multiplicity"`
	Lifecycle      string        `json:"lifecycle"`
	Permissions    []string      `json:"permissions"`
	Dependencies   []Dependency  `json:"dependencies"`
}

type Provider struct {
	ProviderID      string        `json:"provider_id"`
	ProviderVersion string        `json:"provider_version"`
	ArtifactDigest  string        `json:"artifact_digest"`
	Owner           Owner         `json:"owner"`
	Capability      CapabilityRef `json:"capability"`
	Scope           Scope         `json:"scope"`
	Permissions     []string      `json:"permissions"`
	Lifecycle       string        `json:"lifecycle"`
	Qualification   Qualification `json:"qualification"`
	BrokerRoute     string        `json:"broker_route"`
}

type Consumer struct {
	ConsumerID  string        `json:"consumer_id"`
	Owner       Owner         `json:"owner"`
	Capability  CapabilityRef `json:"capability"`
	Scope       Scope         `json:"scope"`
	Permissions []string      `json:"permissions"`
	AccessMode  string        `json:"access_mode"`
}

type Bundle struct {
	SchemaVersion   string       `json:"schema_version"`
	ContractVersion string       `json:"contract_version"`
	BundleID        string       `json:"bundle_id"`
	Revision        uint64       `json:"revision"`
	ProfileDigest   string       `json:"profile_digest"`
	Definitions     []Definition `json:"definitions"`
	Providers       []Provider   `json:"providers"`
	Consumers       []Consumer   `json:"consumers"`
}

type CapabilityNode struct {
	NodeID            string `json:"node_id"`
	DeclarationDigest string `json:"declaration_digest"`
	NonReplaceable    bool   `json:"non_replaceable"`
}

type ProviderNode struct {
	NodeID              string `json:"node_id"`
	CapabilityNodeID    string `json:"capability_node_id"`
	DeclarationDigest   string `json:"declaration_digest"`
	QualificationDigest string `json:"qualification_digest"`
	ScopeDigest         string `json:"scope_digest"`
	PermissionDigest    string `json:"permission_digest"`
}

type ConsumerNode struct {
	NodeID            string `json:"node_id"`
	DeclarationDigest string `json:"declaration_digest"`
	ScopeDigest       string `json:"scope_digest"`
	PermissionDigest  string `json:"permission_digest"`
}

type DependencyEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type ConsumerEdge struct {
	Consumer   string `json:"consumer"`
	Capability string `json:"capability"`
	Provider   string `json:"provider"`
	AccessMode string `json:"access_mode"`
}

type Graph struct {
	SchemaVersion   string           `json:"schema_version"`
	ContractVersion string           `json:"contract_version"`
	BundleDigest    string           `json:"bundle_digest"`
	ProfileDigest   string           `json:"profile_digest"`
	Revision        uint64           `json:"revision"`
	DefinitionNodes []CapabilityNode `json:"definition_nodes"`
	ProviderNodes   []ProviderNode   `json:"provider_nodes"`
	ConsumerNodes   []ConsumerNode   `json:"consumer_nodes"`
	DependencyEdges []DependencyEdge `json:"dependency_edges"`
	ConsumerEdges   []ConsumerEdge   `json:"consumer_edges"`
	ResolutionOrder []string         `json:"resolution_order"`
	GraphDigest     string           `json:"graph_digest,omitempty"`
}
