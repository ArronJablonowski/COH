package broker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/domain"
	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

type metadataEnvelope struct {
	Schema         string          `json:"schema"`
	Kind           string          `json:"kind"`
	ID             string          `json:"id"`
	OrganizationID string          `json:"organization_id"`
	TenantID       string          `json:"tenant_id"`
	CaseID         string          `json:"case_id"`
	Revision       uint64          `json:"revision"`
	CreatedAt      string          `json:"created_at"`
	Data           json.RawMessage `json:"data"`
}

func metadataRecord(record lifecycle.Record) (workflow.MetadataRecord, error) {
	data, err := lifecycle.CanonicalRecord(record)
	if err != nil {
		return workflow.MetadataRecord{}, err
	}
	envelope := metadataEnvelope{Schema: "coh.domain/v1", Kind: "approval", ID: record.ApprovalID,
		OrganizationID: record.OrganizationID, TenantID: record.TenantID, CaseID: record.CaseID,
		Revision: record.Revision, CreatedAt: record.RequestedAt, Data: data}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return workflow.MetadataRecord{}, lifecycle.NewError(lifecycle.InvalidInput, "record_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return workflow.MetadataRecord{}, lifecycle.NewError(lifecycle.InvalidInput, "record_encoding")
	}
	key := recordKey(record.OrganizationID, record.TenantID, record.CaseID, record.ApprovalID)
	result := workflow.MetadataRecord{Key: key, Schema: "coh.domain/v1", Revision: record.Revision,
		Canonical: canonical, Digest: lifecycle.Digest(canonical)}
	if err := workflow.ValidateMetadataRecord(result); err != nil {
		return workflow.MetadataRecord{}, lifecycle.NewError(lifecycle.InvalidInput, "metadata_encoding")
	}
	return result, nil
}

func decodeMetadata(record workflow.MetadataRecord) (lifecycle.Record, error) {
	var envelope metadataEnvelope
	decoder := json.NewDecoder(bytes.NewReader(record.Canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || envelope.Schema != "coh.domain/v1" || envelope.Kind != "approval" {
		return lifecycle.Record{}, lifecycle.NewError(lifecycle.Denied, "stored_record_invalid")
	}
	canonical, err := domaincontract.Canonicalize(envelope.Data)
	if err != nil {
		return lifecycle.Record{}, lifecycle.NewError(lifecycle.Denied, "stored_record_invalid")
	}
	result, err := lifecycle.DecodeRecord(canonical)
	if err != nil || result.ApprovalID != record.Key.ID || result.Revision != record.Revision {
		return lifecycle.Record{}, lifecycle.NewError(lifecycle.Denied, "stored_record_invalid")
	}
	return result, nil
}

func recordKey(organizationID, tenantID, caseID, approvalID string) workflow.RecordKey {
	return workflow.RecordKey{Case: domain.CaseRef{OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID}, Kind: "approval", ID: approvalID}
}

func operationDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", lifecycle.NewError(lifecycle.InvalidInput, "operation_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", lifecycle.NewError(lifecycle.InvalidInput, "operation_encoding")
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
