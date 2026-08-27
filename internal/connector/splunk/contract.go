package splunk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const maximumContractBytes = 1 << 20

var (
	namePattern        = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	indexPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
	vendorFieldPattern = regexp.MustCompile(`^_?[A-Za-z][A-Za-z0-9_.-]{0,127}$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	guidPattern        = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	minorPattern       = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	versionPattern     = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	buildPattern       = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	testPattern        = regexp.MustCompile(`^Test[A-Za-z0-9]{3,127}$`)
)

var deniedCapabilities = []string{
	"admin_all_objects", "change_authentication", "delete_by_keyword", "edit_roles", "edit_scripted",
	"edit_user", "indexes_edit", "output_file", "rest_apps_management", "rest_properties_set", "run_debug_commands",
}

func DecodeConfig(input []byte) (Config, error) {
	var value Config
	if err := decodeExact(input, &value); err != nil {
		return Config{}, err
	}
	if err := validateConfig(value); err != nil {
		return Config{}, err
	}
	return value, nil
}

func DecodeQualification(input []byte) (Qualification, error) {
	var value Qualification
	if err := decodeExact(input, &value); err != nil {
		return Qualification{}, err
	}
	if err := validateQualification(value); err != nil {
		return Qualification{}, err
	}
	return value, nil
}

func DecodeDenialCorpus(input []byte) (DenialCorpus, error) {
	var value DenialCorpus
	if err := decodeExact(input, &value); err != nil {
		return DenialCorpus{}, err
	}
	if value.SchemaVersion != DenialCorpusVersion || value.ContractVersion != ContractVersion || len(value.Cases) < 12 || len(value.Cases) > 64 {
		return DenialCorpus{}, denied("denial corpus identity invalid")
	}
	seen := make(map[string]struct{}, len(value.Cases))
	for _, item := range value.Cases {
		key := item.Class + "\x00" + item.Reason
		if !namePattern.MatchString(item.Class) || len(item.Reason) < 3 || len(item.Reason) > 160 || strings.ContainsAny(item.Reason, "\r\n") ||
			!testPattern.MatchString(item.CoveredBy) {
			return DenialCorpus{}, denied("denial case invalid")
		}
		if _, exists := seen[key]; exists {
			return DenialCorpus{}, denied("duplicate denial case")
		}
		seen[key] = struct{}{}
	}
	return value, nil
}

func DecodeRedactedError(input []byte) (RedactedError, error) {
	var value RedactedError
	if err := decodeExact(input, &value); err != nil {
		return RedactedError{}, err
	}
	if value.SchemaVersion != RedactedErrorVersion || value.ContractVersion != ContractVersion ||
		!namePattern.MatchString(value.Event) || !namePattern.MatchString(value.ReasonCode) || !namePattern.MatchString(value.SourceID) ||
		!validDigests(value.RequestDigest, value.ResponseDigest, value.LeaseDecisionDigest, value.TransportIdentityDigest) ||
		value.CredentialExposed || value.BearerExposed || value.SIDExposed || value.NativeTextExposed || value.ResultRowExposed || value.VendorBodyExposed {
		return RedactedError{}, denied("redacted error invalid")
	}
	return value, nil
}

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > maximumContractBytes {
		return denied("contract size invalid")
	}
	unique, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return denied("contract JSON invalid")
	}
	encoded, err := json.Marshal(unique)
	if err != nil {
		return denied("contract JSON invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return denied("contract shape invalid")
	}
	return nil
}

func validateConfig(value Config) error {
	if value.SchemaVersion != ConfigVersion || value.ContractVersion != ContractVersion || !namePattern.MatchString(value.SourceID) ||
		!namePattern.MatchString(value.AdapterVersion) || value.Deployment != "enterprise" || value.ExpectedProductType != "enterprise" ||
		!guidPattern.MatchString(value.ExpectedServerGUID) || !validEndpoint(value.Endpoint) || !namePattern.MatchString(value.CredentialReference) ||
		!validDigests(value.TLSRootDigest, value.TransportIdentityDigest) || !slices.Equal(value.RequiredCapabilities, []string{"search"}) ||
		!slices.Equal(value.DeniedCapabilities, deniedCapabilities) || !validNames(value.ExpectedServerRoles, 1, 16) ||
		!slices.Contains(value.ExpectedServerRoles, "search_head") || !validMinors(value.QualifiedMinorVersions) ||
		len(value.Resources) == 0 || len(value.Resources) > 256 || len(value.Fields) == 0 || len(value.Fields) > 4096 ||
		!validLimits(value) || value.QualificationLifetimeSeconds < 1 || value.QualificationLifetimeSeconds > 3600 {
		return denied("configuration invalid")
	}
	resourceIDs, resourceIndexes := make(map[string]struct{}, len(value.Resources)), make(map[string]struct{}, len(value.Resources))
	previous := ""
	for _, resource := range value.Resources {
		if !namePattern.MatchString(resource.ID) || !safeIndex(resource.Index) || resource.ID <= previous {
			return denied("resource invalid")
		}
		if _, exists := resourceIndexes[resource.Index]; exists {
			return denied("duplicate resource index")
		}
		resourceIDs[resource.ID], resourceIndexes[resource.Index], previous = struct{}{}, struct{}{}, resource.ID
	}
	fieldNames, vendorNames := make(map[string]struct{}, len(value.Fields)), make(map[string]struct{}, len(value.Fields))
	previous = ""
	for _, field := range value.Fields {
		if !vendorFieldPattern.MatchString(field.VendorName) || !namePattern.MatchString(field.SchemaName) || field.SchemaName <= previous ||
			!slices.Contains([]string{"string", "integer", "boolean", "timestamp", "ip", "bytes"}, field.Type) ||
			!validNames(field.ResourceIDs, 1, len(value.Resources)) {
			return denied("field invalid")
		}
		for _, resourceID := range field.ResourceIDs {
			if _, exists := resourceIDs[resourceID]; !exists {
				return denied("field resource invalid")
			}
		}
		if _, exists := fieldNames[field.SchemaName]; exists {
			return denied("duplicate schema field")
		}
		if _, exists := vendorNames[strings.ToLower(field.VendorName)]; exists {
			return denied("duplicate vendor field")
		}
		fieldNames[field.SchemaName], vendorNames[strings.ToLower(field.VendorName)], previous = struct{}{}, struct{}{}, field.SchemaName
	}
	return nil
}

func validateQualification(value Qualification) error {
	observed, observedErr := time.Parse(time.RFC3339Nano, value.ObservedAt)
	validUntil, validErr := time.Parse(time.RFC3339Nano, value.ValidUntil)
	if value.SchemaVersion != QualificationVersion || value.ContractVersion != ContractVersion || !namePattern.MatchString(value.SourceID) ||
		!namePattern.MatchString(value.AdapterVersion) || !guidPattern.MatchString(value.ServerGUID) || value.ProductType != "enterprise" ||
		!versionPattern.MatchString(value.Version) || !buildPattern.MatchString(value.Build) || !validNames(value.ServerRoles, 1, 16) ||
		!validNames(value.Capabilities, 1, 256) || !slices.Contains(value.Capabilities, "search") || intersects(value.Capabilities, deniedCapabilities) ||
		!validDigests(value.ConfigDigest, value.ServerIdentityDigest, value.CapabilitiesDigest, value.Digest) ||
		observedErr != nil || validErr != nil || !observed.Before(validUntil) || len(value.Receipts) != 2 {
		return denied("qualification invalid")
	}
	want := []string{"splunk.server_info", "splunk.current_context"}
	for index, receipt := range value.Receipts {
		if receipt.Operation != want[index] || !validDigests(receipt.RequestDigest, receipt.ResponseDigest,
			receipt.LeaseDecisionDigest, receipt.TransportDigest) {
			return denied("qualification receipt invalid")
		}
	}
	return nil
}

func validEndpoint(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme == "https" && parsed.Hostname() != "" && parsed.User == nil && parsed.RawQuery == "" &&
		parsed.Fragment == "" && (parsed.Path == "" || parsed.Path == "/") && parsed.RawPath == ""
}

func safeIndex(value string) bool {
	return indexPattern.MatchString(value) && !strings.HasPrefix(value, "_") && !strings.ContainsAny(value, "*,:/%\\") && value != "all"
}

func validNames(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !namePattern.MatchString(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validMinors(values []string) bool {
	if len(values) == 0 || len(values) > 32 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !minorPattern.MatchString(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validLimits(value Config) bool {
	limits := value.HardLimits
	return limits.MaximumRows > 0 && limits.MaximumRows <= 100000 && limits.MaximumBytes > 0 && limits.MaximumBytes <= maximumContractBytes &&
		limits.MaximumDurationMillis > 0 && limits.MaximumDurationMillis <= 120000 && limits.MaximumPages > 0 && limits.MaximumPages <= 1000 &&
		limits.MaximumSlices > 0 && limits.MaximumSlices <= 1000 && limits.MaximumCostMillionths > 0 && limits.RequestsPerMinute > 0 &&
		limits.RequestsPerMinute <= 1000 && value.MaximumInventoryEntries >= 1 && value.MaximumInventoryEntries <= 10000 &&
		value.MaximumSchemaEntriesPerPage >= 1 && value.MaximumSchemaEntriesPerPage <= 4096
}

func validDigests(values ...string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func intersects(left, right []string) bool {
	for _, value := range left {
		if slices.Contains(right, value) {
			return true
		}
	}
	return false
}

func denied(reason string) error { return fmt.Errorf("splunk contract denied: %s", reason) }
