package architecturecatalog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCapabilityMutationsDenyOrphansAndCycles(t *testing.T) {
	base := capabilityGraph{SchemaVersion: "coh.resolved-capability-graph/v1"}
	base.DefinitionNodes = append(base.DefinitionNodes,
		struct {
			NodeID         string `json:"node_id"`
			NonReplaceable bool   `json:"non_replaceable"`
		}{NodeID: "capability/a"},
		struct {
			NodeID         string `json:"node_id"`
			NonReplaceable bool   `json:"non_replaceable"`
		}{NodeID: "capability/b"})
	base.ProviderNodes = append(base.ProviderNodes, struct {
		NodeID           string `json:"node_id"`
		CapabilityNodeID string `json:"capability_node_id"`
	}{NodeID: "provider/a", CapabilityNodeID: "capability/a"}, struct {
		NodeID           string `json:"node_id"`
		CapabilityNodeID string `json:"capability_node_id"`
	}{NodeID: "provider/b", CapabilityNodeID: "capability/b"})
	base.ConsumerNodes = append(base.ConsumerNodes, struct {
		NodeID string `json:"node_id"`
	}{NodeID: "consumer/a"}, struct {
		NodeID string `json:"node_id"`
	}{NodeID: "consumer/b"})
	base.ConsumerEdges = append(base.ConsumerEdges, struct {
		Consumer   string `json:"consumer"`
		Capability string `json:"capability"`
		Provider   string `json:"provider"`
		AccessMode string `json:"access_mode"`
	}{Consumer: "consumer/a", Capability: "capability/a", Provider: "provider/a", AccessMode: "read_only_service"}, struct {
		Consumer   string `json:"consumer"`
		Capability string `json:"capability"`
		Provider   string `json:"provider"`
		AccessMode string `json:"access_mode"`
	}{Consumer: "consumer/b", Capability: "capability/b", Provider: "provider/b", AccessMode: "read_only_service"})

	tests := []struct {
		name   string
		mutate func(*capabilityGraph)
		want   string
	}{
		{"orphan-provider", func(graph *capabilityGraph) { graph.ProviderNodes[0].CapabilityNodeID = "capability/missing" }, "orphan provider"},
		{"orphan-consumer", func(graph *capabilityGraph) { graph.ConsumerEdges[0].Consumer = "consumer/missing" }, "orphan consumer edge"},
		{"orphan-definition", func(graph *capabilityGraph) {
			graph.DefinitionNodes = append(graph.DefinitionNodes, struct {
				NodeID         string `json:"node_id"`
				NonReplaceable bool   `json:"non_replaceable"`
			}{NodeID: "capability/orphan"})
		}, "orphan definition"},
		{"unused-provider", func(graph *capabilityGraph) {
			graph.ProviderNodes = append(graph.ProviderNodes, struct {
				NodeID           string `json:"node_id"`
				CapabilityNodeID string `json:"capability_node_id"`
			}{NodeID: "provider/orphan", CapabilityNodeID: "capability/a"})
		}, "orphan provider"},
		{"unused-consumer", func(graph *capabilityGraph) {
			graph.ConsumerNodes = append(graph.ConsumerNodes, struct {
				NodeID string `json:"node_id"`
			}{NodeID: "consumer/orphan"})
		}, "orphan consumer"},
		{"cycle", func(graph *capabilityGraph) {
			graph.DependencyEdges = append(graph.DependencyEdges,
				struct {
					From string `json:"from"`
					To   string `json:"to"`
					Kind string `json:"kind"`
				}{From: "capability/a", To: "capability/b", Kind: "required"},
				struct {
					From string `json:"from"`
					To   string `json:"to"`
					Kind string `json:"kind"`
				}{From: "capability/b", To: "capability/a", Kind: "required"})
		}, "cycle"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			value.DefinitionNodes = append([]struct {
				NodeID         string `json:"node_id"`
				NonReplaceable bool   `json:"non_replaceable"`
			}{}, base.DefinitionNodes...)
			value.ProviderNodes = append([]struct {
				NodeID           string `json:"node_id"`
				CapabilityNodeID string `json:"capability_node_id"`
			}{}, base.ProviderNodes...)
			value.ConsumerNodes = append([]struct {
				NodeID string `json:"node_id"`
			}{}, base.ConsumerNodes...)
			value.ConsumerEdges = append([]struct {
				Consumer   string `json:"consumer"`
				Capability string `json:"capability"`
				Provider   string `json:"provider"`
				AccessMode string `json:"access_mode"`
			}{}, base.ConsumerEdges...)
			value.DependencyEdges = append([]struct {
				From string `json:"from"`
				To   string `json:"to"`
				Kind string `json:"kind"`
			}{}, base.DependencyEdges...)
			test.mutate(&value)
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := capabilityRecords(data); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("mutation accepted or wrong denial: %v", err)
			}
		})
	}
}

func TestModelSurfaceMutationRequiresProjection(t *testing.T) {
	vocabulary := eventVocabulary{SchemaVersion: "coh.model-surface-event-vocabulary/v1"}
	vocabulary.Definitions = append(vocabulary.Definitions, struct {
		EventType           string   `json:"event_type"`
		EventVersion        uint16   `json:"event_version"`
		EventClass          string   `json:"event_class"`
		Persistence         string   `json:"persistence"`
		ProducerModule      string   `json:"producer_module"`
		ConsumerModules     []string `json:"consumer_modules"`
		ProjectionRule      string   `json:"projection_rule"`
		PayloadSchemaDigest string   `json:"payload_schema_digest"`
	}{EventType: "agent.message", EventVersion: 1, EventClass: "model_surface", Persistence: "durable",
		ProducerModule: "agent", ConsumerModules: []string{"projector"}, ProjectionRule: "none"})
	data, _ := json.Marshal(vocabulary)
	if _, err := eventRecords(data, true); err == nil || !strings.Contains(err.Error(), "projection rule") {
		t.Fatalf("missing projection rule accepted: %v", err)
	}
}
