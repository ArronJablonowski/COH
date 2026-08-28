package sentinel

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const (
	QueryRuntimeConfigVersion = "coh.sentinel-query-runtime-config/v1"
	QueryRequestVersion       = "coh.sentinel-query-request/v1"
	QueryResponseVersion      = "coh.sentinel-query-response/v1"
	SlicePlanVersion          = "coh.sentinel-slice-plan/v1"
	QueryOperation            = "sentinel.query.post"
)

// QueryRuntimeConfig adds execution-only policy to an immutable qualified
// discovery configuration without revising that separately released contract.
type QueryRuntimeConfig struct {
	SchemaVersion              string             `json:"schema_version"`
	ContractVersion            string             `json:"contract_version"`
	DiscoveryConfigDigest      string             `json:"discovery_config_digest"`
	MinimumSliceDurationMillis uint64             `json:"minimum_slice_duration_millis"`
	SplitThresholdRows         uint64             `json:"split_threshold_rows"`
	SplitThresholdBytes        uint64             `json:"split_threshold_bytes"`
	MaximumResponseBytes       uint64             `json:"maximum_response_bytes"`
	StableKeys                 []StableKeyProfile `json:"stable_keys"`
	Digest                     string             `json:"digest"`
}

type StableKeyProfile struct {
	ResourceID      string   `json:"resource_id"`
	TimestampColumn string   `json:"timestamp_column"`
	Columns         []string `json:"columns"`
}

// QueryTransportRequest is the only credentialless value accepted by the
// typed Sentinel query transport. Bearer material is lent out of band.
type QueryTransportRequest struct {
	SchemaVersion           string                   `json:"schema_version"`
	ContractVersion         string                   `json:"contract_version"`
	Operation               string                   `json:"operation"`
	QueryID                 string                   `json:"query_id"`
	AttemptID               string                   `json:"attempt_id"`
	SliceNumber             uint32                   `json:"slice_number"`
	SourceID                string                   `json:"source_id"`
	WorkspaceID             string                   `json:"workspace_id"`
	ScopeDigest             string                   `json:"scope_digest"`
	AuthorityDigest         string                   `json:"authority_digest"`
	CapabilityDigest        string                   `json:"capability_digest"`
	SchemaDigest            string                   `json:"schema_digest"`
	QualificationDigest     string                   `json:"qualification_digest"`
	CommonQueryDigest       string                   `json:"common_query_digest"`
	ValidationDigest        string                   `json:"validation_digest"`
	CanonicalKQL            string                   `json:"canonical_kql"`
	CanonicalKQLDigest      string                   `json:"canonical_kql_digest"`
	PolicyDecisionDigest    string                   `json:"policy_decision_digest"`
	AuditRecordDigest       string                   `json:"audit_record_digest"`
	TimeRange               queryconnector.TimeRange `json:"time_range"`
	MaximumRows             uint64                   `json:"maximum_rows"`
	MaximumBytes            uint64                   `json:"maximum_bytes"`
	ServerWaitSeconds       uint32                   `json:"server_wait_seconds"`
	TransportIdentityDigest string                   `json:"transport_identity_digest"`
	RequestDigest           string                   `json:"request_digest"`
}

type QueryTransportResponse struct {
	SchemaVersion   string          `json:"schema_version"`
	ContractVersion string          `json:"contract_version"`
	RequestDigest   string          `json:"request_digest"`
	Tables          []QueryTable    `json:"tables"`
	Statistics      QueryStatistics `json:"statistics"`
	Error           *QueryAPIError  `json:"error"`
	Receipt         QueryReceipt    `json:"receipt"`
	ResponseDigest  string          `json:"response_digest"`
}

type QueryTable struct {
	Name    string          `json:"name"`
	Columns []QueryColumn   `json:"columns"`
	Rows    [][]interface{} `json:"rows"`
}

type QueryColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type QueryStatistics struct {
	RowsScanned         uint64 `json:"rows_scanned"`
	RowsReturned        uint64 `json:"rows_returned"`
	BytesReturned       uint64 `json:"bytes_returned"`
	DurationMillis      uint64 `json:"duration_millis"`
	ResourceUsageDigest string `json:"resource_usage_digest"`
}

type QueryAPIError struct {
	Code          string   `json:"code"`
	DetailCodes   []string `json:"detail_codes"`
	MessageDigest string   `json:"message_digest"`
}

type QueryReceipt struct {
	Operation               string `json:"operation"`
	HTTPStatus              uint16 `json:"http_status"`
	RequestDigest           string `json:"request_digest"`
	VendorResponseDigest    string `json:"vendor_response_digest"`
	LeaseDecisionDigest     string `json:"lease_decision_digest"`
	TransportDigest         string `json:"transport_digest"`
	TransportIdentityDigest string `json:"transport_identity_digest"`
}

// QueryCall keeps authority and credential-lease binding out of the serialized
// vendor request while still requiring the transport to verify it.
type QueryCall struct {
	Binding CallBinding
	Request QueryTransportRequest
}

type QueryClient interface {
	Query(context.Context, QueryCall) (QueryTransportResponse, error)
}

type SlicePlan struct {
	SchemaVersion       string                   `json:"schema_version"`
	ContractVersion     string                   `json:"contract_version"`
	QueryID             string                   `json:"query_id"`
	AttemptID           string                   `json:"attempt_id"`
	OriginalTimeRange   queryconnector.TimeRange `json:"original_time_range"`
	MaximumSlices       uint32                   `json:"maximum_slices"`
	MinimumDurationMS   uint64                   `json:"minimum_duration_millis"`
	SplitThresholdRows  uint64                   `json:"split_threshold_rows"`
	SplitThresholdBytes uint64                   `json:"split_threshold_bytes"`
	Slices              []SliceRecord            `json:"slices"`
	PlanDigest          string                   `json:"plan_digest"`
}

type SliceRecord struct {
	Number         uint32                   `json:"number"`
	Parent         uint32                   `json:"parent"`
	TimeRange      queryconnector.TimeRange `json:"time_range"`
	State          string                   `json:"state"`
	RequestDigest  string                   `json:"request_digest"`
	ResponseDigest string                   `json:"response_digest"`
}
