package capabilityseam

import (
	"context"
	"slices"
	"testing"
)

func TestEveryReservedAuthorityIsCompiledNonReplaceable(t *testing.T) {
	if len(reservedAuthorityCatalog) != 10 || !slices.IsSortedFunc(reservedAuthorityCatalog,
		func(left, right reservedAuthoritySpec) int { return compareStrings(left.capability, right.capability) }) {
		t.Fatalf("reserved catalog is incomplete or noncanonical: %+v", reservedAuthorityCatalog)
	}
	seenProviders := make(map[string]struct{}, len(reservedAuthorityCatalog))
	for _, spec := range reservedAuthorityCatalog {
		t.Run(spec.capability, func(t *testing.T) {
			if len(spec.definitionRoots) == 0 || len(spec.providerRoots) == 0 || spec.providerID == "" {
				t.Fatalf("incomplete reserved authority: %+v", spec)
			}
			if _, duplicate := seenProviders[spec.providerID]; duplicate {
				t.Fatalf("duplicate reserved provider ID: %s", spec.providerID)
			}
			seenProviders[spec.providerID] = struct{}{}
			graph, err := resolveForTest(context.Background(), reservedAuthorityBundle(t, spec))
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if !graph.Value().DefinitionNodes[0].NonReplaceable ||
				graph.Value().ConsumerEdges[0].AccessMode != "broker_intent" {
				t.Fatalf("authority graph is replaceable or direct: %+v", graph.Value())
			}
		})
	}
}

func TestReservedBrokerAuthorityResolvesAsNonReplaceableTypedIntent(t *testing.T) {
	bundle := reservedBrokerBundle(t)
	graph, err := resolveForTest(context.Background(), bundle)
	if err != nil {
		t.Fatalf("resolve reserved broker: %v", err)
	}
	value := graph.Value()
	if len(value.DefinitionNodes) != 1 || !value.DefinitionNodes[0].NonReplaceable ||
		len(value.ConsumerEdges) != 1 || value.ConsumerEdges[0].AccessMode != "broker_intent" {
		t.Fatalf("reserved broker graph = %+v", value)
	}
}

func TestReservedAuthorityAndBrokerRoutesFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		bundle func(*testing.T) ValidatedBundle
		reason string
	}{
		{"unknown_authority", func(t *testing.T) ValidatedBundle {
			return mutateBundle(t, reservedBrokerBundle(t), func(value *Bundle) {
				setCapability(value, "authority.shadow")
			})
		}, "reserved_authority_unknown"},
		{"replaceable_reserved_definition", func(t *testing.T) ValidatedBundle {
			return mutateValidBundle(t, func(value *Bundle) {
				setCapability(value, "authority.broker")
			})
		}, "reserved_authority_definition"},
		{"reserved_definition_owner", func(t *testing.T) ValidatedBundle {
			return mutateBundle(t, reservedBrokerBundle(t), func(value *Bundle) {
				value.Definitions[0].Owner.Module = "internal/domain/providercontract"
			})
		}, "reserved_authority_definition_owner"},
		{"reserved_provider_identity", func(t *testing.T) ValidatedBundle {
			return mutateBundle(t, reservedBrokerBundle(t), func(value *Bundle) {
				value.Providers[0].ProviderID = "coh.shadow"
			})
		}, "reserved_authority_provider"},
		{"reserved_provider_owner", func(t *testing.T) ValidatedBundle {
			return mutateBundle(t, reservedBrokerBundle(t), func(value *Bundle) {
				value.Providers[0].Owner.Module = "internal/provider/ollama"
			})
		}, "reserved_authority_provider_owner"},
		{"protected_implementation_alias", func(t *testing.T) ValidatedBundle {
			return mutateValidBundle(t, func(value *Bundle) {
				value.Providers[0].Owner.Module = "internal/connector/elastic"
			})
		}, "reserved_authority_alias"},
		{"reserved_consumer_read_only", func(t *testing.T) ValidatedBundle {
			return mutateBundle(t, reservedBrokerBundle(t), func(value *Bundle) {
				value.Consumers[0].AccessMode = "read_only_service"
			})
		}, "reserved_authority_consumer_route"},
		{"consequential_provider_without_broker", func(t *testing.T) ValidatedBundle {
			return consequentialBundle(t, false, false)
		}, "broker_route_required"},
		{"consequential_consumer_without_broker", func(t *testing.T) ValidatedBundle {
			return consequentialBundle(t, true, false)
		}, "broker_route_required"},
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

func reservedBrokerBundle(t *testing.T) ValidatedBundle {
	spec, _ := reservedAuthority("authority.broker")
	return reservedAuthorityBundle(t, spec)
}

func reservedAuthorityBundle(t *testing.T, spec reservedAuthoritySpec) ValidatedBundle {
	return mutateValidBundle(t, func(value *Bundle) {
		setCapability(value, spec.capability)
		definition := &value.Definitions[0]
		definition.Owner.Module = spec.definitionRoots[0]
		definition.AuthorityClass = "authority"
		definition.Replaceability = "non_replaceable"
		definition.Multiplicity = "exactly_one"
		definition.Lifecycle = "static"
		definition.AccessPolicy = "broker_intent_only"
		definition.Permissions = []string{"action.submit"}
		provider := &value.Providers[0]
		provider.ProviderID = spec.providerID
		provider.Owner.Module = spec.providerRoots[0]
		provider.Lifecycle = "static"
		provider.Permissions = []string{"action.submit"}
		provider.BrokerRoute = "typed_intent"
		value.Consumers[0].Permissions = []string{"action.submit"}
		value.Consumers[0].AccessMode = "broker_intent"
	})
}

func consequentialBundle(t *testing.T, providerRoute, consumerRoute bool) ValidatedBundle {
	return mutateValidBundle(t, func(value *Bundle) {
		value.Definitions[0].Permissions = []string{"action.submit"}
		value.Definitions[0].AccessPolicy = "broker_intent_only"
		value.Providers[0].Permissions = []string{"action.submit"}
		value.Consumers[0].Permissions = []string{"action.submit"}
		if providerRoute {
			value.Providers[0].BrokerRoute = "typed_intent"
		}
		if consumerRoute {
			value.Consumers[0].AccessMode = "broker_intent"
		}
	})
}

func setCapability(value *Bundle, name string) {
	capability := CapabilityRef{Name: name, Version: "1.0.0"}
	value.Definitions[0].Capability = capability
	value.Providers[0].Capability = capability
	value.Consumers[0].Capability = capability
}
