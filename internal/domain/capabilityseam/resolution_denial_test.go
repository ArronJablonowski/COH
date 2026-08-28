package capabilityseam

import (
	"context"
	"testing"
)

func TestResolverFailsClosedForInvalidGraphs(t *testing.T) {
	tests := []struct {
		name   string
		bundle func(*testing.T) ValidatedBundle
		reason string
	}{
		{"provider_missing", bundleMissingModelProvider, "provider_missing"},
		{"provider_ambiguous", bundleAmbiguousProvider, "provider_ambiguous"},
		{"consumer_definition_missing", func(t *testing.T) ValidatedBundle {
			return mutateValidBundle(t, func(value *Bundle) { value.Consumers[0].Capability.Version = "2.0.0" })
		}, "consumer_definition_missing"},
		{"provider_permission_widening", func(t *testing.T) ValidatedBundle {
			return mutateValidBundle(t, func(value *Bundle) { value.Providers[0].Permissions = []string{"model.admin"} })
		}, "provider_permission_widening"},
		{"consumer_permission_widening", func(t *testing.T) ValidatedBundle {
			return mutateValidBundle(t, func(value *Bundle) { value.Consumers[0].Permissions = []string{"model.admin"} })
		}, "consumer_permission_widening"},
		{"consumer_scope_widening", func(t *testing.T) ValidatedBundle {
			return mutateValidBundle(t, func(value *Bundle) { value.Consumers[0].Scope.CaseID = nil })
		}, "consumer_scope_widening"},
		{"provider_lifecycle_widening", func(t *testing.T) ValidatedBundle {
			return mutateValidBundle(t, func(value *Bundle) {
				value.Definitions[0].Lifecycle = "static"
				value.Providers[0].Lifecycle = "transactional"
			})
		}, "provider_lifecycle_widening"},
		{"broker_route_missing", func(t *testing.T) ValidatedBundle {
			return mutateValidBundle(t, func(value *Bundle) { value.Consumers[0].AccessMode = "broker_intent" })
		}, "broker_route_missing"},
		{"dependency_missing", func(t *testing.T) ValidatedBundle {
			return mutateValidBundle(t, func(value *Bundle) {
				value.Definitions[0].Dependencies = []Dependency{{Capability: CapabilityRef{Name: "missing.service", Version: "1.0.0"}, Kind: "required"}}
			})
		}, "dependency_missing"},
		{"dependency_cycle", bundleDependencyCycle, "dependency_cycle"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := resolveForTest(context.Background(), test.bundle(t))
			if Code(err) != Denied || Reason(err) != test.reason {
				t.Fatalf("code=%s reason=%s err=%v", Code(err), Reason(err), err)
			}
		})
	}
}

func bundleMissingModelProvider(t *testing.T) ValidatedBundle {
	return mutateBundle(t, bundleWithTokenizerDependency(t), func(value *Bundle) {
		value.Providers = value.Providers[:1]
	})
}

func bundleAmbiguousProvider(t *testing.T) ValidatedBundle {
	return mutateValidBundle(t, func(value *Bundle) {
		secondary := value.Providers[0]
		secondary.ProviderID = "ollama.secondary"
		secondary.Qualification.RecordID = "018f0000-0000-7000-8000-000000000006"
		secondary.Qualification.RecordDigest = digestOf("9")
		value.Providers = append(value.Providers, secondary)
	})
}

func bundleDependencyCycle(t *testing.T) ValidatedBundle {
	return mutateBundle(t, bundleWithTokenizerDependency(t), func(value *Bundle) {
		value.Definitions[0].Dependencies = []Dependency{{Capability: CapabilityRef{Name: "model.inference", Version: "1.0.0"}, Kind: "required"}}
	})
}

func mutateBundle(t *testing.T, source ValidatedBundle, mutate func(*Bundle)) ValidatedBundle {
	t.Helper()
	value := source.Value()
	mutate(&value)
	return encodeBundle(t, value)
}
