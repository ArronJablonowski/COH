package capabilityseam

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestResolveProducesDeterministicClosedGraph(t *testing.T) {
	bundle := decodeFixtureBundle(t)
	first, err := Resolve(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	second, err := Resolve(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve replay: %v", err)
	}
	if first.Digest() != second.Digest() || !bytes.Equal(first.CanonicalBytes(), second.CanonicalBytes()) {
		t.Fatal("resolution was not deterministic")
	}
	graph := first.Value()
	if graph.BundleDigest != bundle.Digest() || graph.ProfileDigest != bundle.Value().ProfileDigest ||
		len(graph.DefinitionNodes) != 1 || len(graph.ProviderNodes) != 1 || len(graph.ConsumerEdges) != 1 ||
		graph.ResolutionOrder[0] != "capability/model.inference@1.0.0" {
		t.Fatalf("unexpected graph: %+v", graph)
	}
}

func TestResolveOrdersDependenciesBeforeConsumers(t *testing.T) {
	bundle := bundleWithTokenizerDependency(t)
	graph, err := Resolve(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	want := []string{"capability/context.tokenizer@1.0.0", "capability/model.inference@1.0.0"}
	if got := graph.Value().ResolutionOrder; !slicesEqual(got, want) {
		t.Fatalf("order=%v want=%v", got, want)
	}
	if len(graph.Value().DependencyEdges) != 1 {
		t.Fatalf("dependency edges=%v", graph.Value().DependencyEdges)
	}
}

func TestResolveRequiresExactCapabilityVersion(t *testing.T) {
	bundle := mutateValidBundle(t, func(value *Bundle) {
		value.Consumers[0].Capability.Version = "2.0.0"
	})
	_, err := Resolve(context.Background(), bundle)
	if Code(err) != Denied || Reason(err) != "consumer_provider_missing" {
		t.Fatalf("code=%s reason=%s err=%v", Code(err), Reason(err), err)
	}
}

func decodeFixtureBundle(t *testing.T) ValidatedBundle {
	t.Helper()
	bundle, err := DecodeBundle(context.Background(), readFixture(t, "bundle.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func mutateValidBundle(t *testing.T, mutate func(*Bundle)) ValidatedBundle {
	t.Helper()
	value := decodeFixtureBundle(t).Value()
	mutate(&value)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := DecodeBundle(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func bundleWithTokenizerDependency(t *testing.T) ValidatedBundle {
	t.Helper()
	return mutateValidBundle(t, func(value *Bundle) {
		model := value.Definitions[0]
		model.Dependencies = []Dependency{{Capability: CapabilityRef{Name: "context.tokenizer", Version: "1.0.0"}, Kind: "required"}}
		tokenizer := model
		tokenizer.Capability = CapabilityRef{Name: "context.tokenizer", Version: "1.0.0"}
		tokenizer.Owner = Owner{Module: "internal/domain/providercontract", ArtifactDigest: digestOf("a")}
		tokenizer.Lifecycle = "static"
		tokenizer.Permissions = []string{"model.tokenize"}
		tokenizer.Dependencies = []Dependency{}
		value.Definitions = []Definition{tokenizer, model}

		provider := value.Providers[0]
		tokenizerProvider := provider
		tokenizerProvider.ProviderID = "builtin.tokenizer"
		tokenizerProvider.ArtifactDigest = digestOf("8")
		tokenizerProvider.Owner = Owner{Module: "internal/provider/ollama", ArtifactDigest: digestOf("8")}
		tokenizerProvider.Capability = tokenizer.Capability
		tokenizerProvider.Permissions = []string{"model.tokenize"}
		tokenizerProvider.Lifecycle = "static"
		tokenizerProvider.Qualification.RecordID = "018f0000-0000-7000-8000-000000000005"
		tokenizerProvider.Qualification.RecordDigest = digestOf("8")
		tokenizerProvider.Qualification.ProviderArtifactDigest = digestOf("8")
		value.Providers = []Provider{tokenizerProvider, provider}
		value.Revision = 2
	})
}

func digestOf(character string) string { return "sha256:" + strings.Repeat(character, 64) }
func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
