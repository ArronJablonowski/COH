package elasticquerydsl

import (
	"regexp"
	"slices"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var (
	namePattern       = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	vendorNamePattern = regexp.MustCompile(`^@?[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
)

func validateDefinition(value Definition) (Definition, error) {
	if !namePattern.MatchString(value.SourceID) || len(value.Resources) == 0 || len(value.Resources) > 256 ||
		!slices.IsSorted(value.Resources) || duplicate(value.Resources) || len(value.Fields) == 0 || len(value.Fields) > 4096 ||
		len(value.Projection) == 0 || len(value.Projection) > 256 || len(value.StableSort) < 2 || len(value.StableSort) > 8 ||
		!namePattern.MatchString(value.TimestampField) || value.HardMaximumRows == 0 || value.HardMaximumRows > 1000000 ||
		value.HardMaximumPages == 0 || value.HardMaximumPages > 10000 || value.HardPageRows == 0 || value.HardPageRows > 10000 {
		return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "querydsl_definition_invalid", nil)
	}
	if value.TenantField != "" && !namePattern.MatchString(value.TenantField) ||
		value.SourceField != "" && !namePattern.MatchString(value.SourceField) {
		return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "querydsl_definition_invalid", nil)
	}
	fields := make(map[string]FieldRule, len(value.Fields))
	vendors := make(map[string]struct{}, len(value.Fields))
	for index, field := range value.Fields {
		if !namePattern.MatchString(field.Name) || !vendorNamePattern.MatchString(field.VendorName) ||
			!oneOf(field.Type, "string", "integer", "boolean", "timestamp", "ip") ||
			(!field.Projectable && !field.Exact && !field.Range && !field.Exists && !field.TextSearchable && !field.Sortable) ||
			field.Range && !oneOf(field.Type, "integer", "timestamp", "ip") || field.TextSearchable && field.Type != "string" ||
			index > 0 && value.Fields[index-1].Name >= field.Name {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "querydsl_field_rule_invalid", nil)
		}
		if _, exists := vendors[field.VendorName]; exists {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "querydsl_field_rule_invalid", nil)
		}
		fields[field.Name], vendors[field.VendorName] = field, struct{}{}
	}
	for _, name := range value.Projection {
		if field, ok := fields[name]; !ok || !field.Projectable {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "querydsl_projection_invalid", nil)
		}
	}
	if duplicateUnsorted(value.Projection) {
		return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "querydsl_projection_invalid", nil)
	}
	seenSort := map[string]struct{}{}
	for _, sortField := range value.StableSort {
		field, ok := fields[sortField.Name]
		if !ok || !field.Projectable || !field.Sortable || !oneOf(strings.ToUpper(sortField.Direction), "ASC", "DESC") {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "querydsl_sort_invalid", nil)
		}
		if _, exists := seenSort[sortField.Name]; exists {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "querydsl_sort_invalid", nil)
		}
		seenSort[sortField.Name] = struct{}{}
	}
	if value.StableSort[0].Name != value.TimestampField {
		return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "querydsl_sort_invalid", nil)
	}
	for _, required := range []string{value.TimestampField, value.TenantField, value.SourceField} {
		if required == "" {
			continue
		}
		field, ok := fields[required]
		if !ok || required == value.TimestampField && !field.Range || required != value.TimestampField && !field.Exact {
			return Definition{}, queryconnector.NewError(queryconnector.InvalidInput, "querydsl_filter_field_invalid", nil)
		}
	}
	value.Resources = append([]string(nil), value.Resources...)
	value.Fields = append([]FieldRule(nil), value.Fields...)
	value.Projection = append([]string(nil), value.Projection...)
	value.StableSort = append([]SortField(nil), value.StableSort...)
	for index := range value.StableSort {
		field := fields[value.StableSort[index].Name]
		value.StableSort[index].VendorName = field.VendorName
		value.StableSort[index].Type = field.Type
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

func oneOf(value string, allowed ...string) bool { return slices.Contains(allowed, value) }
