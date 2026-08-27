package evidencelifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	lifecycleRepositorySchema = "coh.domain/v1"
	lifecycleRepositoryKind   = "evidence_lifecycle"
)

type lifecycleRepositoryEnvelope struct {
	Schema         string          `json:"schema"`
	Kind           string          `json:"kind"`
	ID             string          `json:"id"`
	OrganizationID string          `json:"organization_id"`
	TenantID       string          `json:"tenant_id"`
	CaseID         *string         `json:"case_id"`
	Revision       uint64          `json:"revision"`
	CreatedAt      string          `json:"created_at"`
	EntryType      string          `json:"entry_type"`
	Data           json.RawMessage `json:"data"`
}

func lifecycleMetadata(key workflowbase.RecordKey, revision uint64, entryType string,
	createdAt time.Time, value any) (workflowbase.MetadataRecord, error) {
	data, err := lifecycleEncode(value)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	caseID := key.Case.CaseID
	envelope := lifecycleRepositoryEnvelope{Schema: lifecycleRepositorySchema, Kind: lifecycleRepositoryKind,
		ID: key.ID, OrganizationID: key.Case.OrganizationID, TenantID: key.Case.TenantID, CaseID: &caseID,
		Revision: revision, CreatedAt: formatTime(createdAt), EntryType: entryType, Data: data}
	canonical, err := lifecycleEncode(envelope)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	return workflowbase.MetadataRecord{Key: key, Schema: lifecycleRepositorySchema, Revision: revision,
		Canonical: canonical, Digest: lifecycleRawDigest(canonical)}, nil
}

func lifecycleDecodeEnvelope(metadata workflowbase.MetadataRecord, key workflowbase.RecordKey,
	entryType string) (lifecycleRepositoryEnvelope, error) {
	var envelope lifecycleRepositoryEnvelope
	if err := lifecycleDecode(metadata.Canonical, &envelope); err != nil {
		return lifecycleRepositoryEnvelope{}, err
	}
	if envelope.Schema != lifecycleRepositorySchema || envelope.Kind != lifecycleRepositoryKind ||
		envelope.ID != key.ID || envelope.OrganizationID != key.Case.OrganizationID ||
		envelope.TenantID != key.Case.TenantID || envelope.CaseID == nil || *envelope.CaseID != key.Case.CaseID ||
		envelope.Revision != metadata.Revision || envelope.EntryType != entryType || metadata.Key != key ||
		metadata.Schema != lifecycleRepositorySchema || metadata.Digest != lifecycleRawDigest(metadata.Canonical) {
		return lifecycleRepositoryEnvelope{}, newError(Denied, entryType+"_envelope_invalid", false, nil)
	}
	return envelope, nil
}

func lifecycleEncode(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(InvalidInput, "repository_encoding_invalid", false, err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(InvalidInput, "repository_encoding_invalid", false, err)
	}
	return canonical, nil
}

func lifecycleDecode(data []byte, output any) error {
	if len(data) == 0 || len(data) > 16<<20 || !json.Valid(data) {
		return newError(Denied, "repository_encoding_invalid", false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "repository_encoding_invalid", false, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "repository_encoding_invalid", false, nil)
	}
	canonical, err := lifecycleEncode(output)
	if err != nil || !bytes.Equal(canonical, data) {
		return newError(Denied, "repository_noncanonical", false, err)
	}
	return nil
}

func lifecycleRawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func lifecycleStorageError(operation string, err error) error {
	switch workflowbase.StorageCode(err) {
	case workflowbase.StorageInvalidInput:
		return newError(InvalidInput, operation+"_invalid", false, err)
	case workflowbase.StorageDenied:
		return newError(Denied, operation+"_denied", false, err)
	case workflowbase.StorageNotFound:
		return newError(NotFound, operation+"_not_found", false, err)
	case workflowbase.StorageConflict:
		return newError(Conflict, operation+"_conflict", true, err)
	case workflowbase.StorageCanceled:
		return newError(Canceled, operation+"_canceled", false, err)
	case workflowbase.StorageTimeout:
		return newError(Timeout, operation+"_timeout", true, err)
	default:
		return newError(Unavailable, operation+"_unavailable", true, err)
	}
}

func lifecycleContextError(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "repository_context_invalid", false, nil)
	}
	return operationContextError(ctx)
}
