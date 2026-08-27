package securityonion

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var (
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	fieldPattern  = regexp.MustCompile(`^@?[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
)

func validateConfig(config Config) error {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return invalid("securityonion_endpoint_invalid")
	}
	if !tokenPattern.MatchString(config.SourceID) || !tokenPattern.MatchString(config.AdapterVersion) ||
		!tokenPattern.MatchString(config.CredentialReference) || !digestPattern.MatchString(config.TLSRootDigest) ||
		!digestPattern.MatchString(config.TransportIdentityDigest) || !slices.Equal(config.Permissions, []string{"events/read"}) ||
		!validLimits(config.HardLimits) || config.MaximumInterval <= 0 || config.MaximumInterval > 31*24*time.Hour ||
		config.MaximumEventLimit == 0 || config.MaximumEventLimit > config.HardLimits.MaximumRows ||
		config.MaximumMetricLimit == 0 || config.MaximumMetricLimit > config.HardLimits.MaximumRows ||
		config.MaximumOpenAPIBytes == 0 || config.MaximumOpenAPIBytes > queryconnector.MaximumDocumentBytes ||
		config.QualificationLifetime <= 0 || config.QualificationLifetime > time.Hour || len(config.Resources) == 0 ||
		len(config.Resources) > 256 || len(config.Fields) == 0 || len(config.Fields) > 4096 ||
		len(config.Projection) == 0 || len(config.Projection) > 256 || len(config.StableSort) < 2 || len(config.StableSort) > 8 ||
		!tokenPattern.MatchString(config.TimestampField) {
		return invalid("securityonion_configuration_invalid")
	}
	for index, resource := range config.Resources {
		if !tokenPattern.MatchString(resource.ID) || (index > 0 && config.Resources[index-1].ID >= resource.ID) {
			return invalid("securityonion_resource_invalid")
		}
	}
	vendorNames := map[string]struct{}{}
	for index, field := range config.Fields {
		if !tokenPattern.MatchString(field.LogicalName) || !fieldPattern.MatchString(field.VendorName) ||
			strings.ContainsAny(field.VendorName, "*|: \\") || !validFieldType(field.Type) ||
			(!field.Exact && !field.Range && !field.Exists && !field.Projectable && !field.Groupable && !field.Sortable) ||
			field.Range && !slices.Contains([]string{"integer", "timestamp", "ip"}, field.Type) ||
			(index > 0 && config.Fields[index-1].LogicalName >= field.LogicalName) {
			return invalid("securityonion_field_invalid")
		}
		if _, exists := vendorNames[field.VendorName]; exists {
			return invalid("securityonion_field_invalid")
		}
		vendorNames[field.VendorName] = struct{}{}
	}
	byName := make(map[string]Field, len(config.Fields))
	for _, field := range config.Fields {
		byName[field.LogicalName] = field
	}
	seen := map[string]struct{}{}
	for _, name := range config.Projection {
		field, ok := byName[name]
		if !ok || !field.Projectable {
			return invalid("securityonion_projection_invalid")
		}
		if _, exists := seen[name]; exists {
			return invalid("securityonion_projection_invalid")
		}
		seen[name] = struct{}{}
	}
	seen = map[string]struct{}{}
	for _, name := range config.StableSort {
		field, ok := byName[name]
		if !ok || !field.Sortable {
			return invalid("securityonion_sort_invalid")
		}
		if _, exists := seen[name]; exists {
			return invalid("securityonion_sort_invalid")
		}
		seen[name] = struct{}{}
	}
	if config.StableSort[0] != config.TimestampField {
		return invalid("securityonion_sort_invalid")
	}
	timestamp := byName[config.TimestampField]
	if timestamp.Type != "timestamp" || !timestamp.Range || !timestamp.Projectable || !timestamp.Sortable {
		return invalid("securityonion_sort_invalid")
	}
	for _, name := range config.StableSort {
		if !slices.Contains(config.Projection, name) {
			return invalid("securityonion_sort_invalid")
		}
	}
	for _, name := range []string{config.TenantField, config.SourceField} {
		if name != "" {
			field, ok := byName[name]
			if !ok || !field.Exact || field.Type != "string" {
				return invalid("securityonion_filter_field_invalid")
			}
		}
	}
	return nil
}

func validLimits(value queryconnector.Limits) bool {
	return value.MaximumRows > 0 && value.MaximumBytes > 0 && value.MaximumBytes <= queryconnector.MaximumDocumentBytes &&
		value.MaximumDurationMillis > 0 && value.MaximumDurationMillis <= 120000 && value.MaximumPages > 0 &&
		value.MaximumSlices > 0 && value.MaximumCostMillionths > 0 && value.RequestsPerMinute > 0
}

func validFieldType(value string) bool {
	return slices.Contains([]string{"string", "integer", "boolean", "timestamp", "ip"}, value)
}

func cloneConfig(value Config) Config {
	value.Permissions = append([]string(nil), value.Permissions...)
	value.Resources = append([]Resource(nil), value.Resources...)
	value.Fields = append([]Field(nil), value.Fields...)
	value.Projection = append([]string(nil), value.Projection...)
	value.StableSort = append([]string(nil), value.StableSort...)
	return value
}
