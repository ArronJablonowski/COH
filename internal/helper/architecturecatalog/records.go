package architecturecatalog

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var authorityLine = regexp.MustCompile(`\{"(authority\.[a-z]+)"[^\n]+"(coh\.[a-z]+)"\},`)

type capabilityGraph struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	DefinitionNodes []struct {
		NodeID         string `json:"node_id"`
		NonReplaceable bool   `json:"non_replaceable"`
	} `json:"definition_nodes"`
	ProviderNodes []struct {
		NodeID           string `json:"node_id"`
		CapabilityNodeID string `json:"capability_node_id"`
	} `json:"provider_nodes"`
	ConsumerNodes []struct {
		NodeID string `json:"node_id"`
	} `json:"consumer_nodes"`
	DependencyEdges []struct {
		From string `json:"from"`
		To   string `json:"to"`
		Kind string `json:"kind"`
	} `json:"dependency_edges"`
	ConsumerEdges []struct {
		Consumer   string `json:"consumer"`
		Capability string `json:"capability"`
		Provider   string `json:"provider"`
		AccessMode string `json:"access_mode"`
	} `json:"consumer_edges"`
	ResolutionOrder []string `json:"resolution_order"`
	BundleDigest    string   `json:"bundle_digest"`
	ProfileDigest   string   `json:"profile_digest"`
	Revision        uint64   `json:"revision"`
	GraphDigest     string   `json:"graph_digest"`
}

func capabilityRecords(data []byte) ([]Record, error) {
	var graph capabilityGraph
	if err := json.Unmarshal(data, &graph); err != nil || graph.SchemaVersion != "coh.resolved-capability-graph/v1" {
		return nil, fmt.Errorf("invalid capability graph")
	}
	definitions := make(map[string]bool)
	providers := make(map[string]string)
	consumers := make(map[string]bool)
	providerFor := make(map[string]bool)
	providerUsed := make(map[string]bool)
	consumerUsed := make(map[string]bool)
	var records []Record
	for _, value := range graph.DefinitionNodes {
		definitions[value.NodeID] = true
		records = append(records, Record{ID: value.NodeID, Kind: "capability", Attributes: []Attribute{attr("non_replaceable", fmt.Sprint(value.NonReplaceable))}})
	}
	for _, value := range graph.ProviderNodes {
		if !definitions[value.CapabilityNodeID] {
			return nil, fmt.Errorf("orphan provider %s", value.NodeID)
		}
		providers[value.NodeID] = value.CapabilityNodeID
		providerFor[value.CapabilityNodeID] = true
		records = append(records, Record{ID: value.NodeID, Kind: "provider", Attributes: []Attribute{attr("capability", value.CapabilityNodeID)}})
	}
	for _, value := range graph.ConsumerNodes {
		consumers[value.NodeID] = true
		records = append(records, Record{ID: value.NodeID, Kind: "consumer", Attributes: []Attribute{}})
	}
	for _, edge := range graph.ConsumerEdges {
		if !consumers[edge.Consumer] || !definitions[edge.Capability] || providers[edge.Provider] != edge.Capability {
			return nil, fmt.Errorf("orphan consumer edge %s", edge.Consumer)
		}
		providerUsed[edge.Provider] = true
		consumerUsed[edge.Consumer] = true
		records = append(records, Record{ID: edge.Consumer + "->" + edge.Provider, Kind: "consumer_edge", Attributes: []Attribute{
			attr("access_mode", edge.AccessMode), attr("capability", edge.Capability)}})
	}
	adjacency := make(map[string][]string)
	for _, edge := range graph.DependencyEdges {
		if !definitions[edge.From] || !definitions[edge.To] {
			return nil, fmt.Errorf("orphan dependency edge")
		}
		adjacency[edge.From] = append(adjacency[edge.From], edge.To)
		records = append(records, Record{ID: edge.From + "->" + edge.To, Kind: "dependency_edge", Attributes: []Attribute{attr("dependency_kind", edge.Kind)}})
	}
	if cyclic(adjacency) {
		return nil, fmt.Errorf("capability dependency cycle")
	}
	for definition := range definitions {
		if !providerFor[definition] {
			return nil, fmt.Errorf("orphan definition %s", definition)
		}
	}
	for provider := range providers {
		if !providerUsed[provider] {
			return nil, fmt.Errorf("orphan provider %s", provider)
		}
	}
	for consumer := range consumers {
		if !consumerUsed[consumer] {
			return nil, fmt.Errorf("orphan consumer %s", consumer)
		}
	}
	return records, nil
}

func authorityRecords(data []byte) ([]Record, error) {
	matches := authorityLine.FindAllSubmatch(data, -1)
	records := make([]Record, 0, len(matches))
	for _, match := range matches {
		records = append(records, Record{ID: string(match[1]), Kind: "reserved_authority", Attributes: []Attribute{
			attr("access_policy", "broker_intent_only"), attr("lifecycle", "static"),
			attr("provider", string(match[2])), attr("replaceability", "non_replaceable"),
		}})
	}
	if len(records) != 10 {
		return nil, fmt.Errorf("reserved authority catalog is incomplete")
	}
	return records, nil
}

type signedLayer struct {
	SchemaVersion string `json:"schema_version"`
	Layer         struct {
		Name         string `json:"name"`
		Kind         string `json:"kind"`
		Revision     uint64 `json:"revision"`
		Precedence   int    `json:"precedence"`
		Contribution struct {
			DeploymentProfile struct {
				ID       string `json:"id"`
				Revision uint64 `json:"revision"`
				Digest   string `json:"digest"`
			} `json:"deployment_profile"`
			EndpointReferences []string          `json:"endpoint_references"`
			Permissions        []string          `json:"permissions"`
			Features           map[string]bool   `json:"features"`
			Limits             map[string]uint64 `json:"limits"`
		} `json:"contribution"`
	} `json:"layer"`
	LayerDigest string `json:"layer_digest"`
}

func configurationRecords(data []byte) ([]Record, error) {
	var layer signedLayer
	if err := json.Unmarshal(data, &layer); err != nil || layer.SchemaVersion != "coh.signed-profile-layer/v1" {
		return nil, fmt.Errorf("invalid signed profile layer")
	}
	records := []Record{{ID: layer.Layer.Name, Kind: "profile_layer", Attributes: []Attribute{
		attr("kind", layer.Layer.Kind), attr("precedence", fmt.Sprint(layer.Layer.Precedence)),
		attr("revision", fmt.Sprint(layer.Layer.Revision)), attr("layer_digest", layer.LayerDigest),
	}}}
	profile := layer.Layer.Contribution.DeploymentProfile
	records = append(records, Record{ID: profile.ID, Kind: "deployment_profile", Attributes: []Attribute{
		attr("revision", fmt.Sprint(profile.Revision)), attr("profile_digest", profile.Digest)}})
	for name, enabled := range layer.Layer.Contribution.Features {
		records = append(records, Record{ID: name, Kind: "feature", Attributes: []Attribute{attr("enabled", fmt.Sprint(enabled))}})
	}
	for name, value := range layer.Layer.Contribution.Limits {
		records = append(records, Record{ID: name, Kind: "limit", Attributes: []Attribute{attr("value", fmt.Sprint(value))}})
	}
	for _, endpoint := range layer.Layer.Contribution.EndpointReferences {
		records = append(records, Record{ID: endpoint, Kind: "endpoint_reference", Attributes: []Attribute{}})
	}
	for _, permission := range layer.Layer.Contribution.Permissions {
		records = append(records, Record{ID: permission, Kind: "permission", Attributes: []Attribute{}})
	}
	return records, nil
}

type eventVocabulary struct {
	SchemaVersion string `json:"schema_version"`
	Definitions   []struct {
		EventType           string   `json:"event_type"`
		EventVersion        uint16   `json:"event_version"`
		EventClass          string   `json:"event_class"`
		Persistence         string   `json:"persistence"`
		ProducerModule      string   `json:"producer_module"`
		ConsumerModules     []string `json:"consumer_modules"`
		ProjectionRule      string   `json:"projection_rule"`
		PayloadSchemaDigest string   `json:"payload_schema_digest"`
	} `json:"definitions"`
}

func eventRecords(data []byte, surfaceOnly bool) ([]Record, error) {
	var vocabulary eventVocabulary
	if err := json.Unmarshal(data, &vocabulary); err != nil || vocabulary.SchemaVersion != "coh.model-surface-event-vocabulary/v1" {
		return nil, fmt.Errorf("invalid event vocabulary")
	}
	var records []Record
	for _, event := range vocabulary.Definitions {
		if surfaceOnly && event.EventClass != "model_surface" {
			continue
		}
		if event.EventClass == "model_surface" && (event.Persistence != "durable" || event.ProjectionRule == "none" || event.ProjectionRule == "") {
			return nil, fmt.Errorf("model-visible event lacks durable projection rule")
		}
		identity := fmt.Sprintf("%s@%d", event.EventType, event.EventVersion)
		attributes := []Attribute{attr("event_class", event.EventClass), attr("persistence", event.Persistence),
			attr("producer", event.ProducerModule), attr("projection_rule", event.ProjectionRule),
			attr("payload_schema_digest", event.PayloadSchemaDigest)}
		for index, consumer := range event.ConsumerModules {
			attributes = append(attributes, attr(fmt.Sprintf("consumer_%02d", index), consumer))
		}
		records = append(records, Record{ID: identity, Kind: "event", Attributes: attributes})
	}
	if surfaceOnly && len(records) == 0 {
		return nil, fmt.Errorf("model-surface catalog is empty")
	}
	return records, nil
}

func dependencyRecords(packages []goPackage) []Record {
	const module = "github.com/ArronJablonowski/COH"
	var records []Record
	for _, pkg := range packages {
		records = append(records, Record{ID: pkg.ImportPath, Kind: "module", Attributes: []Attribute{attr("package_name", pkg.Name)}})
		for _, imported := range pkg.Imports {
			if imported == module || strings.HasPrefix(imported, module+"/") {
				records = append(records, Record{ID: pkg.ImportPath + "->" + imported, Kind: "module_edge", Attributes: []Attribute{}})
			}
		}
	}
	return records
}

func entrypointRecords(root string, packages []goPackage) ([]Record, error) {
	const module = "github.com/ArronJablonowski/COH"
	var records []Record
	for _, pkg := range packages {
		if pkg.Name != "main" {
			continue
		}
		relative, err := filepath.Rel(root, pkg.Dir)
		if err != nil || strings.HasPrefix(relative, "..") {
			return nil, fmt.Errorf("entrypoint outside repository")
		}
		path := filepath.ToSlash(relative)
		if !strings.HasPrefix(path, "cmd/") || pkg.ImportPath != module+"/"+path {
			return nil, fmt.Errorf("alternate launch path %s", path)
		}
		records = append(records, Record{ID: path, Kind: "application_entrypoint", Attributes: []Attribute{attr("package", pkg.ImportPath)}})
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("entrypoint inventory is empty")
	}
	return records, nil
}

func cyclic(graph map[string][]string) bool {
	state := make(map[string]uint8)
	var visit func(string) bool
	visit = func(node string) bool {
		if state[node] == 1 {
			return true
		}
		if state[node] == 2 {
			return false
		}
		state[node] = 1
		for _, next := range graph[node] {
			if visit(next) {
				return true
			}
		}
		state[node] = 2
		return false
	}
	keys := make([]string, 0, len(graph))
	for key := range graph {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if visit(key) {
			return true
		}
	}
	return false
}
