package capabilityseam

import "slices"

func validateResolutionBindings(bundle Bundle, definitions map[string]Definition, selected map[string]Provider) error {
	if err := validateReservedAuthorityBindings(bundle); err != nil {
		return err
	}
	for _, provider := range bundle.Providers {
		definition := definitions[capabilityID(provider.Capability)]
		if !permissionSubset(provider.Permissions, definition.Permissions) {
			return newError(Denied, "provider_permission_widening")
		}
		if lifecycleRank(provider.Lifecycle) > lifecycleRank(definition.Lifecycle) {
			return newError(Denied, "provider_lifecycle_widening")
		}
	}
	for _, consumer := range bundle.Consumers {
		identifier := capabilityID(consumer.Capability)
		definition, exists := definitions[identifier]
		if !exists {
			return newError(Denied, "consumer_definition_missing")
		}
		provider, exists := selected[identifier]
		if !exists {
			return newError(Denied, "consumer_provider_missing")
		}
		if !permissionSubset(consumer.Permissions, definition.Permissions) ||
			!permissionSubset(consumer.Permissions, provider.Permissions) {
			return newError(Denied, "consumer_permission_widening")
		}
		if !scopeSubset(consumer.Scope, provider.Scope) {
			return newError(Denied, "consumer_scope_widening")
		}
		if consumer.AccessMode == "broker_intent" && provider.BrokerRoute != "typed_intent" {
			return newError(Denied, "broker_route_missing")
		}
	}
	return nil
}

func permissionSubset(requested, ceiling []string) bool {
	for _, permission := range requested {
		if _, exists := slices.BinarySearch(ceiling, permission); !exists {
			return false
		}
	}
	return true
}

func scopeSubset(requested, ceiling Scope) bool {
	if requested.OrganizationID != ceiling.OrganizationID || requested.TenantID != ceiling.TenantID ||
		requested.Environment != ceiling.Environment {
		return false
	}
	if ceiling.CaseID == nil {
		return true
	}
	return requested.CaseID != nil && *requested.CaseID == *ceiling.CaseID
}

func lifecycleRank(value string) int {
	switch value {
	case "static":
		return 0
	case "restart_bound":
		return 1
	case "transactional":
		return 2
	default:
		return 3
	}
}
