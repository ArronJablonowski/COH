// Package sentinel implements COH's bounded Microsoft Sentinel workspace discovery boundary.
package sentinel

import "github.com/ArronJablonowski/COH/internal/domain/queryconnector"

const (
	ContractVersion      = "1.0.0"
	ConfigVersion        = "coh.sentinel-discovery-config/v1"
	MetadataVersion      = "coh.sentinel-metadata/v1"
	QualificationVersion = "coh.sentinel-qualification/v1"
	DenialCorpusVersion  = "coh.sentinel-denials/v1"
	RedactedErrorVersion = "coh.sentinel-redacted-error/v1"
	PublicEndpoint       = "https://api.loganalytics.azure.com"
	APIVersion           = "v1"
	TokenAudience        = "https://api.loganalytics.io/.default"
)

type Config struct {
	SchemaVersion                string                `json:"schema_version"`
	ContractVersion              string                `json:"contract_version"`
	SourceID                     string                `json:"source_id"`
	AdapterVersion               string                `json:"adapter_version"`
	Deployment                   string                `json:"deployment"`
	Endpoint                     string                `json:"endpoint"`
	APIVersion                   string                `json:"api_version"`
	TokenAudience                string                `json:"token_audience"`
	TenantID                     string                `json:"tenant_id"`
	WorkspaceID                  string                `json:"workspace_id"`
	WorkspaceResourceID          string                `json:"workspace_resource_id"`
	ExpectedRegion               string                `json:"expected_region"`
	CredentialReference          string                `json:"credential_reference"`
	TLSRootDigest                string                `json:"tls_root_digest"`
	TransportIdentityDigest      string                `json:"transport_identity_digest"`
	Resources                    []Resource            `json:"resources"`
	Fields                       []Field               `json:"fields"`
	HardLimits                   queryconnector.Limits `json:"hard_limits"`
	MaximumMetadataBytes         uint64                `json:"maximum_metadata_bytes"`
	MaximumMetadataTables        uint32                `json:"maximum_metadata_tables"`
	MaximumMetadataColumns       uint32                `json:"maximum_metadata_columns"`
	MaximumSchemaEntriesPerPage  uint32                `json:"maximum_schema_entries_per_page"`
	QualificationLifetimeSeconds uint32                `json:"qualification_lifetime_seconds"`
}

type Resource struct {
	ID             string `json:"id"`
	Table          string `json:"table"`
	TimespanColumn string `json:"timespan_column"`
}

type Field struct {
	VendorName  string   `json:"vendor_name"`
	SchemaName  string   `json:"schema_name"`
	Type        string   `json:"type"`
	Nullable    bool     `json:"nullable"`
	ResourceIDs []string `json:"resource_ids"`
}

type Metadata struct {
	SchemaVersion       string          `json:"schema_version"`
	ContractVersion     string          `json:"contract_version"`
	WorkspaceID         string          `json:"workspace_id"`
	WorkspaceResourceID string          `json:"workspace_resource_id"`
	Region              string          `json:"region"`
	APIVersion          string          `json:"api_version"`
	Tables              []MetadataTable `json:"tables"`
	Digest              string          `json:"digest"`
}

type MetadataTable struct {
	Name           string           `json:"name"`
	TimespanColumn string           `json:"timespan_column"`
	Columns        []MetadataColumn `json:"columns"`
}

type MetadataColumn struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type Qualification struct {
	SchemaVersion       string    `json:"schema_version"`
	ContractVersion     string    `json:"contract_version"`
	SourceID            string    `json:"source_id"`
	AdapterVersion      string    `json:"adapter_version"`
	ObservedAt          string    `json:"observed_at"`
	ValidUntil          string    `json:"valid_until"`
	WorkspaceID         string    `json:"workspace_id"`
	WorkspaceResourceID string    `json:"workspace_resource_id"`
	Region              string    `json:"region"`
	APIVersion          string    `json:"api_version"`
	ConfigDigest        string    `json:"config_digest"`
	MetadataDigest      string    `json:"metadata_digest"`
	Receipts            []Receipt `json:"receipts"`
	Digest              string    `json:"digest"`
}

type Receipt struct {
	Operation           string `json:"operation"`
	RequestDigest       string `json:"request_digest"`
	ResponseDigest      string `json:"response_digest"`
	LeaseDecisionDigest string `json:"lease_decision_digest"`
	TransportDigest     string `json:"transport_digest"`
}

type DenialCorpus struct {
	SchemaVersion   string       `json:"schema_version"`
	ContractVersion string       `json:"contract_version"`
	Cases           []DenialCase `json:"cases"`
}

type DenialCase struct {
	Class     string `json:"class"`
	Reason    string `json:"reason"`
	CoveredBy string `json:"covered_by"`
}

type RedactedError struct {
	SchemaVersion           string `json:"schema_version"`
	ContractVersion         string `json:"contract_version"`
	Event                   string `json:"event"`
	ReasonCode              string `json:"reason_code"`
	SourceID                string `json:"source_id"`
	RequestDigest           string `json:"request_digest"`
	ResponseDigest          string `json:"response_digest"`
	LeaseDecisionDigest     string `json:"lease_decision_digest"`
	TransportIdentityDigest string `json:"transport_identity_digest"`
	CredentialExposed       bool   `json:"credential_exposed"`
	BearerExposed           bool   `json:"bearer_exposed"`
	TenantSecretExposed     bool   `json:"tenant_secret_exposed"`
	WorkspaceURLExposed     bool   `json:"workspace_url_exposed"`
	NativeTextExposed       bool   `json:"native_text_exposed"`
	ResultRowExposed        bool   `json:"result_row_exposed"`
	VendorBodyExposed       bool   `json:"vendor_body_exposed"`
}
