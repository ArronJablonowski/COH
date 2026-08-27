package elastic

import (
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

var (
	uuidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenPattern       = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	clusterUUIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	versionPattern     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)
	vendorNamePattern  = regexp.MustCompile(`^@?[A-Za-z0-9_][A-Za-z0-9_.-]{0,253}$`)
	expressionPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,253}\*?$`)
)

func validateBinding(scope queryconnector.Scope, authority queryconnector.AuthorityBinding) error {
	if !uuidPattern.MatchString(scope.OrganizationID) || !uuidPattern.MatchString(scope.TenantID) ||
		!uuidPattern.MatchString(scope.CaseID) || !uuidPattern.MatchString(authority.ActorID) ||
		!digestPattern.MatchString(authority.AuthorizationDigest) ||
		!digestPattern.MatchString(authority.PolicyDecisionDigest) ||
		!digestPattern.MatchString(authority.AuditReservationDigest) {
		return denied("elastic_authority_invalid")
	}
	return nil
}

func validateConfig(config Config) error {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		return invalid("elastic_endpoint_invalid")
	}
	if !tokenPattern.MatchString(config.SourceID) || !tokenPattern.MatchString(config.AdapterVersion) ||
		!oneOf(config.Deployment, "self_managed", "serverless") ||
		!clusterUUIDPattern.MatchString(config.ExpectedClusterUUID) || !tokenPattern.MatchString(config.ExpectedBuildFlavor) ||
		!digestPattern.MatchString(config.TransportIdentityDigest) ||
		config.MinimumMajorVersion == 0 || config.MaximumMajorVersion < config.MinimumMajorVersion ||
		config.CapabilityLifetime <= 0 || config.CapabilityLifetime > time.Hour ||
		!validLimits(config.HardLimits) || config.HardLimits.MaximumBytes > queryconnector.MaximumDocumentBytes ||
		config.HardLimits.MaximumDurationMillis > 120000 || len(config.Resources) == 0 || len(config.Resources) > maximumResources ||
		len(config.Fields) == 0 || len(config.Fields) > maximumFields || config.MaximumSchemaEntriesPerPage <= 0 ||
		config.MaximumSchemaEntriesPerPage > 4096 {
		return invalid("elastic_configuration_invalid")
	}
	if config.Deployment == "self_managed" && len(config.QualifiedMinorVersions) == 0 {
		return invalid("elastic_versions_unqualified")
	}
	if (config.Deployment == "serverless") != (config.ExpectedBuildFlavor == "serverless") {
		return invalid("elastic_build_flavor_invalid")
	}
	if !slices.IsSorted(config.QualifiedMinorVersions) || duplicate(config.QualifiedMinorVersions) {
		return invalid("elastic_versions_invalid")
	}
	for _, version := range config.QualifiedMinorVersions {
		if !regexp.MustCompile(`^[0-9]+\.[0-9]+$`).MatchString(version) {
			return invalid("elastic_versions_invalid")
		}
	}
	for index, resource := range config.Resources {
		if !tokenPattern.MatchString(resource.ID) || !validExpression(resource.Expression) ||
			(index > 0 && config.Resources[index-1].ID >= resource.ID) {
			return invalid("elastic_resource_invalid")
		}
	}
	for index, field := range config.Fields {
		if !vendorNamePattern.MatchString(field.VendorName) || strings.HasPrefix(field.VendorName, ".") ||
			strings.Contains(field.VendorName, "*") || !tokenPattern.MatchString(field.SchemaName) ||
			(index > 0 && config.Fields[index-1].VendorName >= field.VendorName) {
			return invalid("elastic_field_invalid")
		}
	}
	return nil
}

func validExpression(value string) bool {
	return expressionPattern.MatchString(value) && value != "*" && value != "_all" &&
		!strings.HasPrefix(value, ".") && !strings.ContainsAny(value, ",:%/\\") &&
		strings.Count(value, "*") <= 1
}

func validateScope(config Config, scope queryconnector.Scope) ([]Resource, error) {
	if scope.SourceID != config.SourceID || len(scope.ResourceIDs) == 0 || len(scope.ResourceIDs) > len(config.Resources) ||
		!slices.IsSorted(scope.ResourceIDs) || duplicate(scope.ResourceIDs) {
		return nil, denied("elastic_scope_invalid")
	}
	byID := make(map[string]Resource, len(config.Resources))
	for _, resource := range config.Resources {
		byID[resource.ID] = resource
	}
	resources := make([]Resource, 0, len(scope.ResourceIDs))
	for _, id := range scope.ResourceIDs {
		resource, ok := byID[id]
		if !ok {
			return nil, denied("elastic_resource_not_allowed")
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func validateIdentity(config Config, identity ClusterIdentity) error {
	if identity.ClusterUUID != config.ExpectedClusterUUID || identity.BuildFlavor != config.ExpectedBuildFlavor ||
		strings.TrimSpace(identity.BuildHash) == "" || identity.BuildHash == "<nil>" {
		return conflict("elastic_cluster_identity_mismatch")
	}
	if identity.Snapshot {
		return unsupported("elastic_snapshot_build_unsupported")
	}
	if config.Deployment == "serverless" {
		if identity.BuildFlavor != "serverless" {
			return conflict("elastic_deployment_mismatch")
		}
		return nil
	}
	if !versionPattern.MatchString(identity.Version) || identity.BuildFlavor == "serverless" {
		return unsupported("elastic_version_invalid")
	}
	parts := strings.Split(identity.Version, ".")
	major, _ := strconv.ParseUint(parts[0], 10, 32)
	minor := parts[0] + "." + parts[1]
	if uint32(major) < config.MinimumMajorVersion || uint32(major) > config.MaximumMajorVersion ||
		!slices.Contains(config.QualifiedMinorVersions, minor) {
		return unsupported("elastic_version_unqualified")
	}
	return nil
}

func validateReceipt(config Config, receipt CallReceipt) error {
	if !digestPattern.MatchString(receipt.RequestDigest) || !digestPattern.MatchString(receipt.ResponseDigest) ||
		!digestPattern.MatchString(receipt.LeaseDecisionDigest) || receipt.TransportDigest != config.TransportIdentityDigest {
		return denied("elastic_receipt_invalid")
	}
	return nil
}

func validLimits(value queryconnector.Limits) bool {
	return value.MaximumRows > 0 && value.MaximumBytes > 0 && value.MaximumDurationMillis > 0 &&
		value.MaximumPages > 0 && value.MaximumSlices > 0 && value.MaximumCostMillionths > 0 && value.RequestsPerMinute > 0
}

func duplicate[T comparable](values []T) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

func oneOf(value string, options ...string) bool { return slices.Contains(options, value) }

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
