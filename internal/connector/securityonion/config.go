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
		len(config.Resources) > 256 || len(config.Fields) == 0 || len(config.Fields) > 4096 {
		return invalid("securityonion_configuration_invalid")
	}
	for index, resource := range config.Resources {
		if !tokenPattern.MatchString(resource.ID) || (index > 0 && config.Resources[index-1].ID >= resource.ID) {
			return invalid("securityonion_resource_invalid")
		}
	}
	for index, field := range config.Fields {
		if !tokenPattern.MatchString(field.LogicalName) || !fieldPattern.MatchString(field.VendorName) ||
			strings.ContainsAny(field.VendorName, "*|: \\") || !validFieldType(field.Type) ||
			(index > 0 && config.Fields[index-1].LogicalName >= field.LogicalName) {
			return invalid("securityonion_field_invalid")
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
	return value
}
