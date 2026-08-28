package capabilityseam

import "strings"

type reservedAuthoritySpec struct {
	capability      string
	definitionRoots []string
	providerRoots   []string
	providerID      string
}

var reservedAuthorityCatalog = []reservedAuthoritySpec{
	{"authority.approval", []string{"internal/domain/approvallifecycle"}, []string{"internal/broker/approvallifecycle"}, "coh.approval"},
	{"authority.audit", []string{"internal/domain/tamperaudit"}, []string{"internal/broker/auditsigner", "internal/workflow/auditlog"}, "coh.audit"},
	{"authority.broker", []string{"internal/domain/toolroute"}, []string{"internal/broker"}, "coh.broker"},
	{"authority.connector", []string{"internal/domain/queryconnector"}, []string{"internal/connector"}, "coh.connector"},
	{"authority.credential", []string{"internal/domain/credentiallease"}, []string{"internal/broker/credentiallease"}, "coh.credential"},
	{"authority.estop", []string{"internal/domain/estop"}, []string{"internal/broker/estop"}, "coh.estop"},
	{"authority.evidence", []string{"internal/workflow/evidencecatalog"}, []string{"internal/workflow/evidencecatalog", "internal/workflow/evidenceingest"}, "coh.evidence"},
	{"authority.policy", []string{"internal/policy"}, []string{"internal/policy"}, "coh.policy"},
	{"authority.runner", []string{"internal/domain/remoteworker"}, []string{"internal/broker/nativeexecutor", "internal/broker/ociexecutor", "internal/broker/remoteworker"}, "coh.runner"},
	{"authority.validator", []string{"internal/domain/queryconnector"}, []string{"internal/connector"}, "coh.validator"},
}

var protectedImplementationRoots = []string{
	"internal/broker", "internal/connector", "internal/policy",
	"internal/workflow/auditlog", "internal/workflow/evidencecatalog", "internal/workflow/evidenceingest",
}

var brokerPermissionPrefixes = []string{
	"action.", "approval.", "connector.", "credential.", "detection.", "estop.",
	"evidence.", "policy.", "query.", "runner.", "tool.", "validator.", "vulnerability.",
}

func validateReservedAuthorityBindings(bundle Bundle) error {
	for _, definition := range bundle.Definitions {
		spec, reserved := reservedAuthority(definition.Capability.Name)
		if strings.HasPrefix(definition.Capability.Name, "authority.") && !reserved {
			return newError(Denied, "reserved_authority_unknown")
		}
		if moduleWithinAny(definition.Owner.Module, protectedImplementationRoots) && !reserved {
			return newError(Denied, "reserved_authority_alias")
		}
		if reserved && (definition.AuthorityClass != "authority" || definition.Replaceability != "non_replaceable" ||
			definition.Multiplicity != "exactly_one" || definition.Lifecycle != "static" ||
			definition.AccessPolicy != "broker_intent_only") {
			return newError(Denied, "reserved_authority_definition")
		}
		if reserved && !moduleWithinAny(definition.Owner.Module, spec.definitionRoots) {
			return newError(Denied, "reserved_authority_definition_owner")
		}
	}
	for _, provider := range bundle.Providers {
		spec, reserved := reservedAuthority(provider.Capability.Name)
		if moduleWithinAny(provider.Owner.Module, protectedImplementationRoots) && !reserved {
			return newError(Denied, "reserved_authority_alias")
		}
		if reserved && (provider.ProviderID != spec.providerID || provider.Lifecycle != "static" ||
			provider.BrokerRoute != "typed_intent") {
			return newError(Denied, "reserved_authority_provider")
		}
		if reserved && !moduleWithinAny(provider.Owner.Module, spec.providerRoots) {
			return newError(Denied, "reserved_authority_provider_owner")
		}
	}
	for _, consumer := range bundle.Consumers {
		if _, reserved := reservedAuthority(consumer.Capability.Name); reserved && consumer.AccessMode != "broker_intent" {
			return newError(Denied, "reserved_authority_consumer_route")
		}
	}
	return validateBrokerRequiredPermissions(bundle)
}

func validateBrokerRequiredPermissions(bundle Bundle) error {
	definitions := make(map[string]Definition, len(bundle.Definitions))
	for _, definition := range bundle.Definitions {
		definitions[capabilityID(definition.Capability)] = definition
	}
	for _, provider := range bundle.Providers {
		definition := definitions[capabilityID(provider.Capability)]
		if permissionsRequireBroker(definition.Permissions) && definition.AccessPolicy != "broker_intent_only" {
			return newError(Denied, "broker_policy_misclassified")
		}
		if definition.AccessPolicy == "broker_intent_only" && provider.BrokerRoute != "typed_intent" ||
			definition.AccessPolicy == "read_only_service" && provider.BrokerRoute != "not_applicable" {
			return newError(Denied, "broker_route_required")
		}
	}
	for _, consumer := range bundle.Consumers {
		definition := definitions[capabilityID(consumer.Capability)]
		if definition.AccessPolicy == "broker_intent_only" && consumer.AccessMode != "broker_intent" ||
			definition.AccessPolicy == "read_only_service" && consumer.AccessMode != "read_only_service" {
			return newError(Denied, "broker_route_required")
		}
	}
	return nil
}

func reservedAuthority(capability string) (reservedAuthoritySpec, bool) {
	for _, spec := range reservedAuthorityCatalog {
		if spec.capability == capability {
			return spec, true
		}
	}
	return reservedAuthoritySpec{}, false
}

func moduleWithinAny(module string, roots []string) bool {
	for _, root := range roots {
		if module == root || strings.HasPrefix(module, root+"/") {
			return true
		}
	}
	return false
}

func permissionsRequireBroker(permissions []string) bool {
	for _, permission := range permissions {
		for _, prefix := range brokerPermissionPrefixes {
			if strings.HasPrefix(permission, prefix) {
				return true
			}
		}
	}
	return false
}
