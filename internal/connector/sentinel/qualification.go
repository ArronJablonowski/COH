package sentinel

import (
	"context"
	"encoding/json"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const sentinelTimestampLayout = "2006-01-02T15:04:05.000000000Z"

type Qualifier struct {
	config Config
	client Client
	clock  Clock
}

func NewQualifier(config Config, client Client, clock Clock) (*Qualifier, error) {
	if err := validateConfig(config); err != nil || nilPort(client) || nilPort(clock) {
		return nil, invalidInput("sentinel_qualifier_configuration_invalid")
	}
	return &Qualifier{config: cloneConfig(config), client: client, clock: clock}, nil
}

func (qualifier *Qualifier) Qualify(ctx context.Context, scope queryconnector.Scope,
	authority queryconnector.AuthorityBinding) (ValidatedQualification, error) {
	if qualifier == nil {
		return ValidatedQualification{}, invalidInput("sentinel_qualifier_required")
	}
	if err := contextError(ctx); err != nil {
		return ValidatedQualification{}, err
	}
	binding := CallBinding{Scope: scope, Authority: authority, Operation: "sentinel.metadata.get",
		Targets: append([]string(nil), scope.ResourceIDs...), TenantID: qualifier.config.TenantID,
		Audience: qualifier.config.TokenAudience, Endpoint: qualifier.config.Endpoint,
		TransportIdentityDigest: qualifier.config.TransportIdentityDigest}
	if err := validateCallBinding(qualifier.config, binding); err != nil {
		return ValidatedQualification{}, err
	}
	metadata, receipt, err := qualifier.client.Metadata(ctx, MetadataRequest{Binding: binding})
	if err != nil {
		return ValidatedQualification{}, err
	}
	if err := validateQualificationReceipt(qualifier.config, receipt); err != nil {
		return ValidatedQualification{}, err
	}
	if err := validateLiveMetadata(qualifier.config, metadata); err != nil {
		return ValidatedQualification{}, err
	}
	now := qualifier.clock.Now().UTC()
	if now.IsZero() {
		return ValidatedQualification{}, deniedCall("sentinel_qualification_time_invalid")
	}
	validUntil := now.Add(time.Duration(qualifier.config.QualificationLifetimeSeconds) * time.Second)
	value := Qualification{SchemaVersion: QualificationVersion, ContractVersion: ContractVersion,
		SourceID: qualifier.config.SourceID, AdapterVersion: qualifier.config.AdapterVersion,
		ObservedAt: now.Format(sentinelTimestampLayout), ValidUntil: validUntil.Format(sentinelTimestampLayout),
		WorkspaceID: metadata.WorkspaceID, WorkspaceResourceID: metadata.WorkspaceResourceID, Region: metadata.Region,
		APIVersion: metadata.APIVersion, ConfigDigest: hashValue("COH-SENTINEL-CONFIG-V1\x00", qualifier.config),
		MetadataDigest: metadata.Digest, Receipts: []Receipt{qualificationReceipt("sentinel.metadata.get", receipt)}}
	value.Digest = qualificationDigest(value)
	return validateQualificationDocument(ctx, value)
}

func DecodeValidatedQualification(ctx context.Context, input []byte) (ValidatedQualification, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedQualification{}, err
	}
	value, err := DecodeQualification(input)
	if err != nil {
		return ValidatedQualification{}, deniedCall("sentinel_qualification_document_invalid")
	}
	if value.Digest != qualificationDigest(value) {
		return ValidatedQualification{}, deniedCall("sentinel_qualification_digest_invalid")
	}
	return validateQualificationDocument(ctx, value)
}

func validateQualificationDocument(ctx context.Context, value Qualification) (ValidatedQualification, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedQualification{}, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ValidatedQualification{}, deniedCall("sentinel_qualification_encoding_invalid")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return ValidatedQualification{}, deniedCall("sentinel_qualification_encoding_invalid")
	}
	decoded, err := DecodeQualification(canonical)
	if err != nil || decoded.Digest != qualificationDigest(decoded) {
		return ValidatedQualification{}, deniedCall("sentinel_qualification_digest_invalid")
	}
	return ValidatedQualification{value: decoded, bytes: canonical, digest: decoded.Digest}, nil
}

func validateLiveMetadata(config Config, metadata Metadata) error {
	if err := validateMetadata(metadata); err != nil {
		return deniedCall("sentinel_metadata_invalid")
	}
	if metadata.WorkspaceID != config.WorkspaceID || metadata.WorkspaceResourceID != config.WorkspaceResourceID ||
		metadata.Region != config.ExpectedRegion || metadata.APIVersion != config.APIVersion {
		return conflictCall("sentinel_workspace_identity_mismatch")
	}
	if len(metadata.Tables) != len(config.Resources) {
		return conflictCall("sentinel_metadata_drift")
	}
	tables := make(map[string]MetadataTable, len(metadata.Tables))
	for _, table := range metadata.Tables {
		tables[table.Name] = table
	}
	for _, resource := range config.Resources {
		table, exists := tables[resource.Table]
		if !exists || table.TimespanColumn != resource.TimespanColumn {
			return conflictCall("sentinel_metadata_drift")
		}
		for _, field := range config.Fields {
			if !slices.Contains(field.ResourceIDs, resource.ID) {
				continue
			}
			columnIndex := slices.IndexFunc(table.Columns, func(column MetadataColumn) bool { return column.Name == field.VendorName })
			if columnIndex < 0 || !compatibleMetadataType(field.Type, table.Columns[columnIndex].Type) {
				return conflictCall("sentinel_metadata_drift")
			}
		}
	}
	return nil
}

func compatibleMetadataType(logical, vendor string) bool {
	switch logical {
	case "boolean":
		return vendor == "bool"
	case "integer":
		return vendor == "int" || vendor == "long"
	case "number":
		return vendor == "real" || vendor == "decimal"
	case "timestamp":
		return vendor == "datetime"
	case "string":
		return vendor == "string" || vendor == "guid"
	case "ip", "bytes":
		return vendor == "string"
	default:
		return false
	}
}

func validateQualificationReceipt(config Config, receipt CallReceipt) error {
	if !validDigests(receipt.RequestDigest, receipt.ResponseDigest, receipt.LeaseDecisionDigest) ||
		receipt.TransportDigest != config.TransportIdentityDigest {
		return deniedCall("sentinel_qualification_receipt_invalid")
	}
	return nil
}

func qualificationReceipt(operation string, receipt CallReceipt) Receipt {
	return Receipt{Operation: operation, RequestDigest: receipt.RequestDigest, ResponseDigest: receipt.ResponseDigest,
		LeaseDecisionDigest: receipt.LeaseDecisionDigest, TransportDigest: receipt.TransportDigest}
}

func cloneQualification(value Qualification) Qualification {
	value.Receipts = append([]Receipt(nil), value.Receipts...)
	return value
}
