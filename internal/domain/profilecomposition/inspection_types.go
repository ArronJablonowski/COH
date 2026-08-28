package profilecomposition

import "encoding/json"

const (
	InspectionSchemaVersion = "coh.profile-inspection/v1"
	inspectionDigestDomain  = "COH-PROFILE-INSPECTION-V1\x00"
)

type InspectionLineage struct {
	Position           uint64 `json:"position"`
	LayerID            string `json:"layer_id"`
	Name               string `json:"name"`
	Kind               string `json:"kind"`
	Revision           uint64 `json:"revision"`
	LayerDigest        string `json:"layer_digest"`
	SignatureSetDigest string `json:"signature_set_digest"`
	QualificationState string `json:"qualification_state"`
	TrustRevision      uint64 `json:"trust_revision"`
	RevocationRevision uint64 `json:"revocation_revision"`
}

type InspectionDefinition struct {
	NodeID            string `json:"node_id"`
	CapabilityVersion string `json:"capability_version"`
	OwnerModule       string `json:"owner_module"`
	DeclarationDigest string `json:"declaration_digest"`
	AccessPolicy      string `json:"access_policy"`
	Lifecycle         string `json:"lifecycle"`
	NonReplaceable    bool   `json:"non_replaceable"`
}

type InspectionProvider struct {
	NodeID              string `json:"node_id"`
	CapabilityNodeID    string `json:"capability_node_id"`
	ProviderVersion     string `json:"provider_version"`
	ArtifactDigest      string `json:"artifact_digest"`
	QualificationDigest string `json:"qualification_digest"`
	QualificationState  string `json:"qualification_state"`
	ScopeDigest         string `json:"scope_digest"`
	PermissionDigest    string `json:"permission_digest"`
}

type InspectionConsumer struct {
	NodeID            string `json:"node_id"`
	DeclarationDigest string `json:"declaration_digest"`
	ScopeDigest       string `json:"scope_digest"`
	PermissionDigest  string `json:"permission_digest"`
}

type InspectionDependencyEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

type InspectionConsumerEdge struct {
	Consumer   string `json:"consumer"`
	Capability string `json:"capability"`
	Provider   string `json:"provider"`
	AccessMode string `json:"access_mode"`
}

type InspectionLimit struct {
	Name              string `json:"name"`
	Value             uint64 `json:"value"`
	SourceLayerDigest string `json:"source_layer_digest"`
}

type InspectionFeature struct {
	Name              string `json:"name"`
	Enabled           bool   `json:"enabled"`
	SourceLayerDigest string `json:"source_layer_digest"`
}

type Inspection struct {
	SchemaVersion         string                     `json:"schema_version"`
	ContractVersion       string                     `json:"contract_version"`
	ProfileID             string                     `json:"profile_id"`
	ProfileRevision       uint64                     `json:"profile_revision"`
	Target                ExactTarget                `json:"target"`
	ProfileBindingDigest  string                     `json:"profile_binding_digest"`
	CompositionDigest     string                     `json:"composition_digest"`
	CapabilityGraphDigest string                     `json:"capability_graph_digest"`
	Lineage               []InspectionLineage        `json:"lineage"`
	Definitions           []InspectionDefinition     `json:"definitions"`
	Providers             []InspectionProvider       `json:"providers"`
	Consumers             []InspectionConsumer       `json:"consumers"`
	DependencyEdges       []InspectionDependencyEdge `json:"dependency_edges"`
	ConsumerEdges         []InspectionConsumerEdge   `json:"consumer_edges"`
	Limits                []InspectionLimit          `json:"limits"`
	FeatureStates         []InspectionFeature        `json:"feature_states"`
	InspectionDigest      string                     `json:"inspection_digest,omitempty"`
}

type ValidatedInspection struct {
	digest string
	bytes  []byte
}

func (value ValidatedInspection) Digest() string { return value.digest }
func (value ValidatedInspection) CanonicalBytes() []byte {
	return append([]byte(nil), value.bytes...)
}
func (value ValidatedInspection) Value() Inspection {
	var inspection Inspection
	_ = json.Unmarshal(value.bytes, &inspection)
	return inspection
}

type ValueSourceDigests struct {
	Limits   [6]string
	Features [5]string
}
