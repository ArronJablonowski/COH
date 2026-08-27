package elastic

import (
	"path"
	"slices"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func normalizeResolution(resource Resource, result ResolveResult) ([]string, error) {
	if len(result.DataStreams) != 0 {
		return nil, unsupported("elastic_data_stream_unsupported")
	}
	indices := make([]string, 0, len(result.Indices))
	for _, target := range result.Indices {
		if !safeConcreteIndex(target.Name) || !matches(resource.Expression, target.Name) {
			return nil, denied("elastic_resolved_target_invalid")
		}
		for _, attribute := range target.Attributes {
			if oneOf(attribute, "closed", "frozen", "hidden", "restricted", "system") {
				return nil, denied("elastic_resolved_target_forbidden")
			}
		}
		indices = append(indices, target.Name)
	}
	for _, alias := range result.Aliases {
		if !safeConcreteIndex(alias.Name) || !matches(resource.Expression, alias.Name) || len(alias.Indices) == 0 {
			return nil, denied("elastic_resolved_alias_invalid")
		}
		for _, index := range alias.Indices {
			if !safeConcreteIndex(index) {
				return nil, denied("elastic_resolved_target_invalid")
			}
			indices = append(indices, index)
		}
	}
	slices.Sort(indices)
	indices = slices.Compact(indices)
	if len(indices) == 0 || len(indices) > maximumResources {
		return nil, denied("elastic_resolution_empty_or_oversized")
	}
	return indices, nil
}

func normalizeCapabilities(resource Resource, configured []Field, indices []string, result FieldCapabilitiesResult) ([]queryconnector.SchemaEntry, error) {
	returnedIndices := append([]string(nil), result.Indices...)
	slices.Sort(returnedIndices)
	returnedIndices = slices.Compact(returnedIndices)
	if !slices.Equal(indices, returnedIndices) {
		return nil, conflict("elastic_field_caps_target_drift")
	}
	byVendorName := make(map[string]Field, len(configured))
	for _, field := range configured {
		byVendorName[field.VendorName] = field
	}
	seen := make(map[string]struct{}, len(result.Fields))
	entries := make([]queryconnector.SchemaEntry, 0, len(result.Fields))
	for _, capability := range result.Fields {
		field, ok := byVendorName[capability.Name]
		if !ok {
			return nil, denied("elastic_field_scope_widened")
		}
		if _, duplicate := seen[capability.Name]; duplicate {
			return nil, unsupported("elastic_field_type_conflict")
		}
		seen[capability.Name] = struct{}{}
		capabilityIndices := append([]string(nil), capability.Indices...)
		if len(capabilityIndices) == 0 {
			capabilityIndices = append(capabilityIndices, indices...)
		} else {
			slices.Sort(capabilityIndices)
			capabilityIndices = slices.Compact(capabilityIndices)
			for _, index := range capabilityIndices {
				if !slices.Contains(indices, index) {
					return nil, conflict("elastic_field_caps_target_drift")
				}
			}
		}
		cohType, nullable, ok := mapFieldType(capability.Type)
		if !ok {
			return nil, unsupported("elastic_field_type_unsupported")
		}
		if !capability.Searchable {
			return nil, unsupported("elastic_field_not_searchable")
		}
		entries = append(entries, queryconnector.SchemaEntry{ResourceID: resource.ID, Name: field.SchemaName,
			Type: cohType, Nullable: nullable || len(capabilityIndices) != len(indices)})
	}
	if len(entries) == 0 {
		return nil, denied("elastic_fields_empty")
	}
	return entries, nil
}

func mapFieldType(value string) (string, bool, bool) {
	switch value {
	case "keyword", "constant_keyword", "wildcard", "text", "match_only_text", "version":
		return "string", false, true
	case "byte", "short", "integer", "long", "unsigned_long":
		return "integer", false, true
	case "boolean":
		return "boolean", false, true
	case "date", "date_nanos":
		return "timestamp", false, true
	case "ip":
		return "ip", false, true
	case "binary":
		return "bytes", false, true
	case "object", "flattened", "nested":
		return "object", true, true
	default:
		return "", false, false
	}
}

func safeConcreteIndex(value string) bool {
	return vendorNamePattern.MatchString(value) && !strings.HasPrefix(value, ".") &&
		!strings.ContainsAny(value, "*,:/%\\") && value != "_all"
}

func matches(expression, value string) bool {
	matched, err := path.Match(expression, value)
	return err == nil && matched
}
