package sentinel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const maximumContractBytes = 1 << 20

var (
	namePattern     = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	vendorPattern   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,127}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuidPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	regionPattern   = regexp.MustCompile(`^[a-z][a-z0-9]{1,31}$`)
	resourcePattern = regexp.MustCompile(`^/subscriptions/[0-9a-f-]{36}/resourceGroups/[A-Za-z0-9_.()-]{1,90}/providers/Microsoft[.]OperationalInsights/workspaces/[A-Za-z0-9_.()-]{1,90}$`)
	testPattern     = regexp.MustCompile(`^Test[A-Za-z0-9]{3,127}$`)
)

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

func DecodeMetadata(input []byte) (Metadata, error) {
	var value Metadata
	if err := decodeExact(input, &value); err != nil {
		return Metadata{}, err
	}
	if err := validateMetadata(value); err != nil {
		return Metadata{}, err
	}
	return value, nil
}

func DecodeQualification(input []byte) (Qualification, error) {
	var value Qualification
	if err := decodeExact(input, &value); err != nil {
		return Qualification{}, err
	}
	observed, observedErr := time.Parse(time.RFC3339Nano, value.ObservedAt)
	validUntil, validErr := time.Parse(time.RFC3339Nano, value.ValidUntil)
	if value.SchemaVersion != QualificationVersion || value.ContractVersion != ContractVersion ||
		!namePattern.MatchString(value.SourceID) || !namePattern.MatchString(value.AdapterVersion) ||
		!uuidPattern.MatchString(value.WorkspaceID) || !resourcePattern.MatchString(value.WorkspaceResourceID) ||
		!regionPattern.MatchString(value.Region) || value.APIVersion != APIVersion || value.Digest != qualificationDigest(value) ||
		!validDigests(value.ConfigDigest, value.MetadataDigest, value.Digest) || observedErr != nil || validErr != nil ||
		!observed.Before(validUntil) || len(value.Receipts) != 1 || value.Receipts[0].Operation != "sentinel.metadata.get" ||
		!validDigests(value.Receipts[0].RequestDigest, value.Receipts[0].ResponseDigest,
			value.Receipts[0].LeaseDecisionDigest, value.Receipts[0].TransportDigest) {
		return Qualification{}, denied("qualification invalid")
	}
	return value, nil
}

func DecodeDenialCorpus(input []byte) (DenialCorpus, error) {
	var value DenialCorpus
	if err := decodeExact(input, &value); err != nil {
		return DenialCorpus{}, err
	}
	if value.SchemaVersion != DenialCorpusVersion || value.ContractVersion != ContractVersion ||
		len(value.Cases) < 12 || len(value.Cases) > 64 {
		return DenialCorpus{}, denied("denial corpus invalid")
	}
	seen := map[string]struct{}{}
	for _, item := range value.Cases {
		if !namePattern.MatchString(item.Class) || len(item.Reason) < 3 || len(item.Reason) > 160 ||
			strings.ContainsAny(item.Reason, "\r\n") || !testPattern.MatchString(item.CoveredBy) {
			return DenialCorpus{}, denied("denial case invalid")
		}
		if _, exists := seen[item.Class]; exists {
			return DenialCorpus{}, denied("duplicate denial case")
		}
		seen[item.Class] = struct{}{}
	}
	return value, nil
}

func DecodeRedactedError(input []byte) (RedactedError, error) {
	var value RedactedError
	if err := decodeExact(input, &value); err != nil {
		return RedactedError{}, err
	}
	if value.SchemaVersion != RedactedErrorVersion || value.ContractVersion != ContractVersion ||
		!namePattern.MatchString(value.Event) || !namePattern.MatchString(value.ReasonCode) ||
		!namePattern.MatchString(value.SourceID) || !validDigests(value.RequestDigest, value.ResponseDigest,
		value.LeaseDecisionDigest, value.TransportIdentityDigest) || value.CredentialExposed || value.BearerExposed ||
		value.TenantSecretExposed || value.WorkspaceURLExposed || value.NativeTextExposed ||
		value.ResultRowExposed || value.VendorBodyExposed {
		return RedactedError{}, denied("redacted error invalid")
	}
	return value, nil
}

func validateConfig(value Config) error {
	if value.SchemaVersion != ConfigVersion || value.ContractVersion != ContractVersion ||
		!namePattern.MatchString(value.SourceID) || !namePattern.MatchString(value.AdapterVersion) ||
		value.Deployment != "azure_public" || value.Endpoint != PublicEndpoint || value.APIVersion != APIVersion ||
		value.TokenAudience != TokenAudience || !uuidPattern.MatchString(value.TenantID) ||
		!uuidPattern.MatchString(value.WorkspaceID) || !resourcePattern.MatchString(value.WorkspaceResourceID) ||
		!regionPattern.MatchString(value.ExpectedRegion) || !namePattern.MatchString(value.CredentialReference) ||
		!validDigests(value.TLSRootDigest, value.TransportIdentityDigest) || len(value.Resources) == 0 ||
		len(value.Resources) > 256 || len(value.Fields) == 0 || len(value.Fields) > 4096 || !validLimits(value) {
		return denied("configuration invalid")
	}
	resources := map[string]Resource{}
	previous := ""
	for _, resource := range value.Resources {
		if !namePattern.MatchString(resource.ID) || !vendorPattern.MatchString(resource.Table) ||
			!vendorPattern.MatchString(resource.TimespanColumn) || resource.ID <= previous {
			return denied("resource invalid")
		}
		for _, existing := range resources {
			if strings.EqualFold(existing.Table, resource.Table) {
				return denied("duplicate resource table")
			}
		}
		resources[resource.ID], previous = resource, resource.ID
	}
	previous = ""
	seenFields := map[string]struct{}{}
	for _, field := range value.Fields {
		if !vendorPattern.MatchString(field.VendorName) || !namePattern.MatchString(field.SchemaName) ||
			field.SchemaName <= previous || !slices.Contains([]string{"boolean", "bytes", "integer", "ip", "number", "string", "timestamp"}, field.Type) ||
			!validNames(field.ResourceIDs, 1, len(resources)) {
			return denied("field invalid")
		}
		for _, resourceID := range field.ResourceIDs {
			if _, exists := resources[resourceID]; !exists {
				return denied("field resource invalid")
			}
			key := strings.ToLower(resourceID + "\x00" + field.VendorName)
			if _, exists := seenFields[key]; exists {
				return denied("duplicate vendor field")
			}
			seenFields[key] = struct{}{}
		}
		previous = field.SchemaName
	}
	return nil
}

func validateMetadata(value Metadata) error {
	if value.SchemaVersion != MetadataVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.WorkspaceID) || !resourcePattern.MatchString(value.WorkspaceResourceID) ||
		!regionPattern.MatchString(value.Region) || value.APIVersion != APIVersion ||
		value.Digest != metadataDigest(value) || len(value.Tables) == 0 || len(value.Tables) > 10000 {
		return denied("metadata invalid")
	}
	previous := ""
	for _, table := range value.Tables {
		if !vendorPattern.MatchString(table.Name) || !vendorPattern.MatchString(table.TimespanColumn) ||
			table.Name <= previous || len(table.Columns) == 0 || len(table.Columns) > 4096 {
			return denied("metadata table invalid")
		}
		columnPrevious, foundTimespan := "", false
		for _, column := range table.Columns {
			if !vendorPattern.MatchString(column.Name) || column.Name <= columnPrevious ||
				!slices.Contains([]string{"bool", "datetime", "decimal", "dynamic", "guid", "int", "long", "real", "string", "timespan"}, column.Type) {
				return denied("metadata column invalid")
			}
			if column.Name == table.TimespanColumn && column.Type == "datetime" {
				foundTimespan = true
			}
			columnPrevious = column.Name
		}
		if !foundTimespan {
			return denied("metadata timespan invalid")
		}
		previous = table.Name
	}
	return nil
}

func validLimits(value Config) bool {
	limits := value.HardLimits
	return limits.MaximumRows > 0 && limits.MaximumRows <= 100000 && limits.MaximumBytes > 0 && limits.MaximumBytes <= maximumContractBytes &&
		limits.MaximumDurationMillis > 0 && limits.MaximumDurationMillis <= 120000 && limits.MaximumPages > 0 && limits.MaximumPages <= 1000 &&
		limits.MaximumSlices > 0 && limits.MaximumSlices <= 1000 && limits.MaximumCostMillionths > 0 && limits.RequestsPerMinute > 0 &&
		limits.RequestsPerMinute <= 1000 && value.MaximumMetadataBytes >= 1024 && value.MaximumMetadataBytes <= maximumContractBytes &&
		value.MaximumMetadataTables > 0 && value.MaximumMetadataTables <= 10000 && value.MaximumMetadataColumns > 0 &&
		value.MaximumMetadataColumns <= 100000 && value.MaximumSchemaEntriesPerPage > 0 &&
		value.MaximumSchemaEntriesPerPage <= 4096 && value.QualificationLifetimeSeconds > 0 && value.QualificationLifetimeSeconds <= 3600
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

func validDigests(values ...string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
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

func metadataDigest(value Metadata) string {
	value.Digest = ""
	return hashValue("COH-SENTINEL-METADATA-V1\x00", value)
}

func qualificationDigest(value Qualification) string {
	value.Digest = ""
	return hashValue("COH-SENTINEL-QUALIFICATION-V1\x00", value)
}

func hashValue(domain string, value any) string {
	encoded, _ := json.Marshal(value)
	hash := sha256.Sum256(append([]byte(domain), encoded...))
	return "sha256:" + hex.EncodeToString(hash[:])
}

func denied(reason string) error { return fmt.Errorf("sentinel contract denied: %s", reason) }
