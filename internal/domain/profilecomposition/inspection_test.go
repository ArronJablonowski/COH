package profilecomposition

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
)

func TestPublishInspectionSealsCanonicalOwnedProjection(t *testing.T) {
	digest := "sha256:" + repeatHex("a")
	value := validInspectionForTest(digest)
	left, err := PublishInspection(context.Background(), value)
	if err != nil {
		t.Fatal(err)
	}
	right, err := PublishInspection(context.Background(), value)
	if err != nil || left.Digest() != right.Digest() || !slices.Equal(left.CanonicalBytes(), right.CanonicalBytes()) {
		t.Fatalf("right=%s err=%v", right.Digest(), err)
	}
	copyBytes := left.CanonicalBytes()
	copyBytes[0] = 'x'
	if left.CanonicalBytes()[0] != '{' || left.Value().InspectionDigest != left.Digest() {
		t.Fatal("inspection did not retain immutable canonical bytes")
	}
	var shape map[string]any
	if err := json.Unmarshal(left.CanonicalBytes(), &shape); err != nil {
		t.Fatal(err)
	}
	if len(shape) != 17 {
		t.Fatalf("unexpected top-level shape: %v", shape)
	}
}

func TestPublishInspectionFailsClosedForMalformedProjection(t *testing.T) {
	digest := "sha256:" + repeatHex("a")
	tests := []struct {
		name   string
		mutate func(*Inspection)
	}{
		{"caller_digest", func(value *Inspection) { value.InspectionDigest = digest }},
		{"lineage_position", func(value *Inspection) { value.Lineage[0].Position = 1 }},
		{"unknown_access", func(value *Inspection) { value.ConsumerEdges[0].AccessMode = "direct" }},
		{"missing_limit", func(value *Inspection) { value.Limits = value.Limits[:5] }},
		{"secret_field_substitute", func(value *Inspection) { value.Definitions[0].OwnerModule = "/Users/private/key" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := validInspectionForTest(digest)
			test.mutate(&value)
			if _, err := PublishInspection(context.Background(), value); err == nil {
				t.Fatal("malformed inspection accepted")
			}
		})
	}
}

func validInspectionForTest(digest string) Inspection {
	lineage := InspectionLineage{LayerID: "018f0000-0000-7000-8000-000000000100", Name: "baseline.native",
		Kind: "baseline", Revision: 1, LayerDigest: digest, SignatureSetDigest: digest,
		QualificationState: "qualified", TrustRevision: 1}
	definition := InspectionDefinition{NodeID: "capability/model.inference@1.0.0",
		CapabilityVersion: "1.0.0", OwnerModule: "internal/domain/providercontract", DeclarationDigest: digest,
		AccessPolicy: "read_only_service", Lifecycle: "restart_bound"}
	provider := InspectionProvider{NodeID: "provider/ollama.local@1.0.0",
		CapabilityNodeID: definition.NodeID, ProviderVersion: "1.0.0", ArtifactDigest: digest,
		QualificationDigest: digest, QualificationState: "qualified", ScopeDigest: digest, PermissionDigest: digest}
	consumer := InspectionConsumer{NodeID: "consumer/workflow.agentloop", DeclarationDigest: digest,
		ScopeDigest: digest, PermissionDigest: digest}
	limitNames := []string{"max_concurrency", "max_context_bytes", "max_duration_ms", "max_evidence_bytes", "max_model_tokens", "max_tool_calls"}
	limits := make([]InspectionLimit, len(limitNames))
	for index, name := range limitNames {
		limits[index] = InspectionLimit{Name: name, Value: uint64(index), SourceLayerDigest: digest}
	}
	featureNames := []string{"external_connectivity", "extension_lifecycle", "model_inference", "retrieval", "tool_dispatch"}
	features := make([]InspectionFeature, len(featureNames))
	for index, name := range featureNames {
		features[index] = InspectionFeature{Name: name, Enabled: index%2 == 0, SourceLayerDigest: digest}
	}
	return Inspection{SchemaVersion: InspectionSchemaVersion, ContractVersion: ContractVersion,
		ProfileID: "018f0000-0000-7000-8000-000000000900", ProfileRevision: 1,
		Target:               ExactTarget{DeploymentKind: "native_workstation", ConnectivityMode: "connected", Platform: "darwin_arm64", Surface: "web"},
		ProfileBindingDigest: digest, CompositionDigest: digest, CapabilityGraphDigest: digest,
		Lineage: []InspectionLineage{lineage}, Definitions: []InspectionDefinition{definition},
		Providers: []InspectionProvider{provider}, Consumers: []InspectionConsumer{consumer},
		DependencyEdges: []InspectionDependencyEdge{}, ConsumerEdges: []InspectionConsumerEdge{{
			Consumer: consumer.NodeID, Capability: definition.NodeID, Provider: provider.NodeID, AccessMode: "read_only_service"}},
		Limits: limits, FeatureStates: features}
}
