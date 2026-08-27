// Package splunk implements COH's bounded Splunk Enterprise connector.
package splunk

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const (
	ContractVersion      = "1.0.0"
	ConfigVersion        = "coh.splunk-discovery-config/v1"
	QualificationVersion = "coh.splunk-qualification/v1"
	DenialCorpusVersion  = "coh.splunk-denials/v1"
	RedactedErrorVersion = "coh.splunk-redacted-error/v1"
)

type Config struct {
	SchemaVersion                string                `json:"schema_version"`
	ContractVersion              string                `json:"contract_version"`
	SourceID                     string                `json:"source_id"`
	AdapterVersion               string                `json:"adapter_version"`
	Deployment                   string                `json:"deployment"`
	Endpoint                     string                `json:"endpoint"`
	ExpectedServerGUID           string                `json:"expected_server_guid"`
	ExpectedProductType          string                `json:"expected_product_type"`
	ExpectedServerRoles          []string              `json:"expected_server_roles"`
	QualifiedMinorVersions       []string              `json:"qualified_minor_versions"`
	CredentialReference          string                `json:"credential_reference"`
	TLSRootDigest                string                `json:"tls_root_digest"`
	TransportIdentityDigest      string                `json:"transport_identity_digest"`
	RequiredCapabilities         []string              `json:"required_capabilities"`
	DeniedCapabilities           []string              `json:"denied_capabilities"`
	Resources                    []Resource            `json:"resources"`
	Fields                       []Field               `json:"fields"`
	HardLimits                   queryconnector.Limits `json:"hard_limits"`
	MaximumInventoryEntries      int                   `json:"maximum_inventory_entries"`
	MaximumSchemaEntriesPerPage  int                   `json:"maximum_schema_entries_per_page"`
	QualificationLifetimeSeconds int                   `json:"qualification_lifetime_seconds"`
}

type Resource struct {
	ID    string `json:"id"`
	Index string `json:"index"`
}

type Field struct {
	VendorName      string   `json:"vendor_name"`
	SchemaName      string   `json:"schema_name"`
	Type            string   `json:"type"`
	Nullable        bool     `json:"nullable"`
	IndexedRequired bool     `json:"indexed_required"`
	ResourceIDs     []string `json:"resource_ids"`
}

type Qualification struct {
	SchemaVersion        string                 `json:"schema_version"`
	ContractVersion      string                 `json:"contract_version"`
	SourceID             string                 `json:"source_id"`
	AdapterVersion       string                 `json:"adapter_version"`
	ObservedAt           string                 `json:"observed_at"`
	ValidUntil           string                 `json:"valid_until"`
	ServerGUID           string                 `json:"server_guid"`
	ProductType          string                 `json:"product_type"`
	Version              string                 `json:"version"`
	Build                string                 `json:"build"`
	ServerRoles          []string               `json:"server_roles"`
	Capabilities         []string               `json:"capabilities"`
	ConfigDigest         string                 `json:"config_digest"`
	ServerIdentityDigest string                 `json:"server_identity_digest"`
	CapabilitiesDigest   string                 `json:"capabilities_digest"`
	Receipts             []QualificationReceipt `json:"receipts"`
	Digest               string                 `json:"digest"`
}

type QualificationReceipt struct {
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
	SIDExposed              bool   `json:"sid_exposed"`
	NativeTextExposed       bool   `json:"native_text_exposed"`
	ResultRowExposed        bool   `json:"result_row_exposed"`
	VendorBodyExposed       bool   `json:"vendor_body_exposed"`
}

// Client intentionally exposes no generic Splunk REST operation.
type Client interface {
	ServerInfo(context.Context, CallBinding) (ServerIdentity, CallReceipt, error)
	CurrentContext(context.Context, CallBinding) (CurrentContext, CallReceipt, error)
	Indexes(context.Context, InventoryRequest) (IndexInventory, CallReceipt, error)
	RegisteredFields(context.Context, InventoryRequest) (RegisteredFieldInventory, CallReceipt, error)
}

// CredentialSource lends one broker-owned authentication token to one bound
// callback. Implementations must destroy the temporary bytes after it returns.
type CredentialSource interface {
	Use(context.Context, CallBinding, func([]byte) error) (string, error)
}

type Clock interface {
	Now() time.Time
}

type ValidatedQualification struct {
	value  Qualification
	bytes  []byte
	digest string
}

func (value ValidatedQualification) Value() Qualification { return cloneQualification(value.value) }
func (value ValidatedQualification) CanonicalBytes() []byte {
	return append([]byte(nil), value.bytes...)
}
func (value ValidatedQualification) Digest() string { return value.digest }

type CallBinding struct {
	Scope     queryconnector.Scope
	Authority queryconnector.AuthorityBinding
	Operation string
	Targets   []string
}

type CallReceipt struct {
	RequestDigest       string
	ResponseDigest      string
	LeaseDecisionDigest string
	TransportDigest     string
}

type ServerIdentity struct {
	GUID        string
	ProductType string
	Version     string
	Build       string
	ServerRoles []string
}

type CurrentContext struct {
	Capabilities []string
}

type InventoryRequest struct {
	Binding        CallBinding
	MaximumEntries int
}

type IndexInventory struct {
	Names     []string
	Truncated bool
}

type RegisteredField struct {
	Name    string
	Indexed bool
}

type RegisteredFieldInventory struct {
	Fields    []RegisteredField
	Truncated bool
}
