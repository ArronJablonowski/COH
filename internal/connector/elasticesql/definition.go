package elasticesql

import (
	"regexp"
	"slices"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var (
	namePattern       = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	vendorNamePattern = regexp.MustCompile(`^@?[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
	resourcePattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
)

func validateDefinition(value Definition) (Definition, error) {
	if !resourcePattern.MatchString(value.SourceID) || len(value.Resources) == 0 || len(value.Resources) > 256 ||
		!slices.IsSorted(value.Resources) || duplicate(value.Resources) || len(value.Fields) == 0 || len(value.Fields) > 4096 ||
		len(value.DefaultProjection) == 0 || len(value.DefaultProjection) > 256 || len(value.StableSort) == 0 ||
		len(value.StableSort) > 8 || !namePattern.MatchString(value.TimestampField) || value.HardMaximumRows == 0 ||
		value.HardMaximumRows > 100000 {
		return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "esql_definition_invalid", nil)
	}
	if (value.TenantField != "" && !namePattern.MatchString(value.TenantField)) ||
		(value.SourceField != "" && !namePattern.MatchString(value.SourceField)) {
		return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "esql_definition_invalid", nil)
	}
	fields := make(map[string]FieldRule, len(value.Fields))
	vendorFields := make(map[string]struct{}, len(value.Fields))
	for index, field := range value.Fields {
		if !namePattern.MatchString(field.Name) || !vendorNamePattern.MatchString(field.VendorName) ||
			!oneOf(field.Type, "string", "integer", "boolean", "timestamp", "ip") ||
			(!field.Projectable && !field.Filterable && !field.Sortable) || (index > 0 && value.Fields[index-1].Name >= field.Name) {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "esql_field_rule_invalid", nil)
		}
		if _, exists := vendorFields[field.VendorName]; exists {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "esql_field_rule_invalid", nil)
		}
		fields[field.Name] = field
		vendorFields[field.VendorName] = struct{}{}
	}
	for _, name := range value.DefaultProjection {
		if field, ok := fields[name]; !ok || !field.Projectable {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "esql_projection_invalid", nil)
		}
	}
	if duplicateUnsorted(value.DefaultProjection) {
		return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "esql_projection_invalid", nil)
	}
	stableNames := make(map[string]struct{}, len(value.StableSort))
	for _, sortField := range value.StableSort {
		if field, ok := fields[sortField.Name]; !ok || !field.Sortable || !oneOf(strings.ToUpper(sortField.Direction), "ASC", "DESC") {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "esql_sort_invalid", nil)
		}
		if _, exists := stableNames[sortField.Name]; exists {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "esql_sort_invalid", nil)
		}
		stableNames[sortField.Name] = struct{}{}
	}
	for _, required := range []string{value.TimestampField, value.TenantField, value.SourceField} {
		if required == "" {
			continue
		}
		if field, ok := fields[required]; !ok || !field.Filterable {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "esql_filter_field_invalid", nil)
		}
	}
	value.Resources = append([]string(nil), value.Resources...)
	value.Fields = append([]FieldRule(nil), value.Fields...)
	value.DefaultProjection = append([]string(nil), value.DefaultProjection...)
	value.StableSort = append([]SortField(nil), value.StableSort...)
	for index := range value.StableSort {
		value.StableSort[index].Direction = strings.ToUpper(value.StableSort[index].Direction)
	}
	return value, nil
}

func duplicate[T comparable](values []T) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

func duplicateUnsorted[T comparable](values []T) bool {
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func oneOf(value string, options ...string) bool { return slices.Contains(options, value) }
