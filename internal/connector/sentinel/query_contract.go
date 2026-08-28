package sentinel

import (
	"encoding/json"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/kustovalidator"
)

const maximumCanonicalKQLBytes = 131072

var queryUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func DecodeQueryRuntimeConfig(input []byte) (QueryRuntimeConfig, error) {
	var value QueryRuntimeConfig
	if err := decodeExact(input, &value); err != nil {
		return QueryRuntimeConfig{}, err
	}
	if value.SchemaVersion != QueryRuntimeConfigVersion || value.ContractVersion != ContractVersion ||
		!validDigests(value.DiscoveryConfigDigest, value.Digest) || value.Digest != queryRuntimeConfigDigest(value) ||
		value.MinimumSliceDurationMillis == 0 || value.MinimumSliceDurationMillis > 86400000 ||
		value.SplitThresholdRows == 0 || value.SplitThresholdRows > 100000 ||
		value.SplitThresholdBytes < 1024 || value.SplitThresholdBytes > maximumContractBytes ||
		value.MaximumResponseBytes < value.SplitThresholdBytes || value.MaximumResponseBytes > maximumContractBytes ||
		len(value.StableKeys) == 0 || len(value.StableKeys) > 256 {
		return QueryRuntimeConfig{}, denied("query runtime configuration invalid")
	}
	previous := ""
	for _, profile := range value.StableKeys {
		if !namePattern.MatchString(profile.ResourceID) || profile.ResourceID <= previous ||
			!vendorPattern.MatchString(profile.TimestampColumn) || !validVendorNames(profile.Columns, 1, 16) ||
			slices.Contains(profile.Columns, profile.TimestampColumn) {
			return QueryRuntimeConfig{}, denied("stable key profile invalid")
		}
		previous = profile.ResourceID
	}
	return value, nil
}

func DecodeQueryTransportRequest(input []byte) (QueryTransportRequest, error) {
	var value QueryTransportRequest
	if err := decodeExact(input, &value); err != nil {
		return QueryTransportRequest{}, err
	}
	start, startOK := queryTime(value.TimeRange.Start)
	end, endOK := queryTime(value.TimeRange.End)
	if value.SchemaVersion != QueryRequestVersion || value.ContractVersion != ContractVersion ||
		value.Operation != QueryOperation || !queryUUIDPattern.MatchString(value.QueryID) ||
		!queryUUIDPattern.MatchString(value.AttemptID) || value.SliceNumber == 0 ||
		!namePattern.MatchString(value.SourceID) || !uuidPattern.MatchString(value.WorkspaceID) ||
		!validDigests(value.ScopeDigest, value.AuthorityDigest, value.CapabilityDigest, value.SchemaDigest,
			value.QualificationDigest, value.CommonQueryDigest, value.ValidationDigest, value.CanonicalKQLDigest,
			value.PolicyDecisionDigest, value.AuditRecordDigest, value.TransportIdentityDigest, value.RequestDigest) ||
		len(value.CanonicalKQL) == 0 || len(value.CanonicalKQL) > maximumCanonicalKQLBytes ||
		strings.ContainsRune(value.CanonicalKQL, 0) || value.CanonicalKQLDigest != queryCanonicalKQLDigest(value.CanonicalKQL) ||
		!startOK || !endOK || !start.Before(end) || value.MaximumRows == 0 || value.MaximumRows > 100000 ||
		value.MaximumBytes < 1024 || value.MaximumBytes > maximumContractBytes || value.ServerWaitSeconds == 0 ||
		value.ServerWaitSeconds > 600 || value.RequestDigest != queryTransportRequestDigest(value) {
		return QueryTransportRequest{}, denied("query transport request invalid")
	}
	return value, nil
}

func DecodeQueryTransportResponse(input []byte) (QueryTransportResponse, error) {
	var value QueryTransportResponse
	if err := decodeExact(input, &value); err != nil {
		return QueryTransportResponse{}, err
	}
	if value.SchemaVersion != QueryResponseVersion || value.ContractVersion != ContractVersion ||
		!validDigests(value.RequestDigest, value.ResponseDigest, value.Statistics.ResourceUsageDigest) ||
		value.ResponseDigest != queryTransportResponseDigest(value) || validateQueryReceipt(value) != nil ||
		value.Statistics.BytesReturned > maximumContractBytes || value.Statistics.DurationMillis > 600000 ||
		value.Statistics.RowsReturned > value.Statistics.RowsScanned {
		return QueryTransportResponse{}, denied("query transport response invalid")
	}
	if value.Error != nil {
		if len(value.Tables) != 0 || value.Statistics.RowsReturned != 0 || value.Error.Code != "PartialError" ||
			!validReasonNames(value.Error.DetailCodes, 1, 32) || !validDigests(value.Error.MessageDigest) {
			return QueryTransportResponse{}, denied("partial query response invalid")
		}
		return value, nil
	}
	if len(value.Tables) != 1 || value.Tables[0].Name != "PrimaryResult" || validateQueryTable(value.Tables[0]) != nil ||
		value.Statistics.RowsReturned != uint64(len(value.Tables[0].Rows)) {
		return QueryTransportResponse{}, denied("query result invalid")
	}
	return value, nil
}

func DecodeSlicePlan(input []byte) (SlicePlan, error) {
	var value SlicePlan
	if err := decodeExact(input, &value); err != nil {
		return SlicePlan{}, err
	}
	start, startOK := queryTime(value.OriginalTimeRange.Start)
	end, endOK := queryTime(value.OriginalTimeRange.End)
	if value.SchemaVersion != SlicePlanVersion || value.ContractVersion != ContractVersion ||
		!queryUUIDPattern.MatchString(value.QueryID) || !queryUUIDPattern.MatchString(value.AttemptID) ||
		!startOK || !endOK || !start.Before(end) || value.MaximumSlices == 0 || value.MaximumSlices > 1000 ||
		value.MinimumDurationMS == 0 || value.SplitThresholdRows == 0 || value.SplitThresholdBytes < 1024 ||
		len(value.Slices) == 0 || len(value.Slices) > int(value.MaximumSlices) || !validDigests(value.PlanDigest) ||
		value.PlanDigest != slicePlanDigest(value) {
		return SlicePlan{}, denied("slice plan invalid")
	}
	seen := make(map[uint32]SliceRecord, len(value.Slices))
	for index, item := range value.Slices {
		itemStart, itemStartOK := queryTime(item.TimeRange.Start)
		itemEnd, itemEndOK := queryTime(item.TimeRange.End)
		if item.Number != uint32(index+1) || !itemStartOK || !itemEndOK || !itemStart.Before(itemEnd) ||
			itemStart.Before(start) || itemEnd.After(end) || !slices.Contains([]string{"planned", "split", "complete", "denied", "canceled", "unknown"}, item.State) ||
			(item.Parent != 0 && item.Parent >= item.Number) ||
			(item.RequestDigest != "" && !validDigests(item.RequestDigest)) ||
			(item.ResponseDigest != "" && !validDigests(item.ResponseDigest)) {
			return SlicePlan{}, denied("slice record invalid")
		}
		if item.Parent != 0 {
			if parent, ok := seen[item.Parent]; !ok || parent.State != "split" || itemStart.Before(mustQueryTime(parent.TimeRange.Start)) || itemEnd.After(mustQueryTime(parent.TimeRange.End)) {
				return SlicePlan{}, denied("slice parent invalid")
			}
		}
		seen[item.Number] = item
	}
	return value, nil
}

func validVendorNames(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !vendorPattern.MatchString(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validReasonNames(values []string, minimum, maximum int) bool {
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

func validateQueryTable(value QueryTable) error {
	if len(value.Columns) == 0 || len(value.Columns) > 256 || len(value.Rows) > 100000 {
		return denied("query table invalid")
	}
	seen := map[string]struct{}{}
	for _, column := range value.Columns {
		if !vendorPattern.MatchString(column.Name) || !slices.Contains([]string{"bool", "datetime", "decimal", "guid", "int", "long", "real", "string", "timespan"}, column.Type) {
			return denied("query column invalid")
		}
		if _, exists := seen[column.Name]; exists {
			return denied("query column duplicate")
		}
		seen[column.Name] = struct{}{}
	}
	for _, row := range value.Rows {
		if len(row) != len(value.Columns) {
			return denied("query row width invalid")
		}
		for index, item := range row {
			if !validQueryCell(value.Columns[index].Type, item) {
				return denied("query row type invalid")
			}
		}
	}
	return nil
}

func validQueryCell(kind string, value interface{}) bool {
	if value == nil {
		return true
	}
	switch kind {
	case "bool":
		_, ok := value.(bool)
		return ok
	case "int", "long", "real", "decimal":
		number, ok := value.(float64)
		return ok && !math.IsInf(number, 0) && !math.IsNaN(number)
	case "datetime":
		text, ok := value.(string)
		_, valid := queryTime(text)
		return ok && valid
	case "string", "guid", "timespan":
		text, ok := value.(string)
		return ok && len(text) <= 65536 && !strings.ContainsRune(text, 0)
	default:
		return false
	}
}

func validateQueryReceipt(value QueryTransportResponse) error {
	receipt := value.Receipt
	if receipt.Operation != QueryOperation || receipt.HTTPStatus != 200 || receipt.RequestDigest != value.RequestDigest ||
		!validDigests(receipt.VendorResponseDigest, receipt.LeaseDecisionDigest, receipt.TransportDigest,
			receipt.TransportIdentityDigest) {
		return denied("query receipt invalid")
	}
	return nil
}

func queryTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(sentinelTimestampLayout, value)
	return parsed, err == nil && parsed.Format(sentinelTimestampLayout) == value
}

func mustQueryTime(value string) time.Time {
	parsed, _ := time.Parse(sentinelTimestampLayout, value)
	return parsed
}

func queryRuntimeConfigDigest(value QueryRuntimeConfig) string {
	value.Digest = ""
	return hashValue("COH-SENTINEL-QUERY-RUNTIME-CONFIG-V1\x00", value)
}

func queryCanonicalKQLDigest(value string) string {
	return kustovalidator.CanonicalKQLDigest(value)
}

func queryTransportRequestDigest(value QueryTransportRequest) string {
	value.RequestDigest = ""
	return hashValue("COH-SENTINEL-QUERY-REQUEST-V1\x00", value)
}

func queryTransportResponseDigest(value QueryTransportResponse) string {
	value.ResponseDigest = ""
	return hashValue("COH-SENTINEL-QUERY-RESPONSE-V1\x00", value)
}

func slicePlanDigest(value SlicePlan) string {
	value.PlanDigest = ""
	return hashValue("COH-SENTINEL-SLICE-PLAN-V1\x00", value)
}

func encodeQueryContract(value interface{}) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
