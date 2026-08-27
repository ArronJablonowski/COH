package evidenceingest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	repositoryRecordSchema = "coh.domain/v1"
	repositoryKind         = "artifact_manifest"
)

type RepositoryStore struct{ repository workflowbase.MetadataStore }

type repositoryEnvelope struct {
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

func NewRepositoryStore(repository workflowbase.MetadataStore) (*RepositoryStore, error) {
	if repository == nil {
		return nil, newError(InvalidInput, "repository_required", false, nil)
	}
	return &RepositoryStore{repository: repository}, nil
}

func (store *RepositoryStore) Recover(ctx context.Context, scope domain.CaseRef,
	idempotency string) (Receipt, bool, error) {
	return store.loadReceipt(ctx, ingestionReceiptKey(scope, idempotency), scope,
		"receipt", idempotency, "")
}

// ResolveReceipt loads an immutable ingestion receipt by its canonical digest.
// The index is only a lookup path: the complete receipt is decoded and
// validated again before it is returned.
func (store *RepositoryStore) ResolveReceipt(ctx context.Context, scope domain.CaseRef,
	receiptDigest string) (Receipt, bool, error) {
	return store.loadReceipt(ctx, ingestionReceiptIndexKey(scope, receiptDigest), scope,
		"receipt_index", "", receiptDigest)
}

func (store *RepositoryStore) loadReceipt(ctx context.Context, key workflowbase.RecordKey,
	scope domain.CaseRef, entryType, idempotency, receiptDigest string) (Receipt, bool, error) {
	if err := contextError(ctx); err != nil {
		return Receipt{}, false, err
	}
	if !validCase(scope) || idempotency != "" && !digestPattern.MatchString(idempotency) ||
		receiptDigest != "" && !digestPattern.MatchString(receiptDigest) {
		return Receipt{}, false, newError(InvalidInput, "receipt_key_invalid", false, nil)
	}
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return Receipt{}, found, err
	}
	envelope, err := decodeIngestionEnvelope(metadata, key, entryType)
	if err != nil {
		return Receipt{}, false, err
	}
	var wire receiptWire
	if err = decodeIngestionRecord(envelope.Data, &wire); err != nil {
		return Receipt{}, false, err
	}
	value, err := receiptFromWire(wire)
	if err != nil || validateReceipt(value) != nil || value.Case != scope ||
		idempotency != "" && value.IdempotencyDigest != idempotency ||
		receiptDigest != "" && value.ReceiptDigest != receiptDigest || envelope.Revision != 1 ||
		envelope.CreatedAt != formatTime(value.CreatedAt) {
		return Receipt{}, false, newError(Denied, "receipt_record_invalid", false, err)
	}
	return value, true, nil
}

func (store *RepositoryStore) Commit(ctx context.Context, idempotencyKey, intent string,
	receipt Receipt) (Receipt, bool, error) {
	if err := contextError(ctx); err != nil {
		return Receipt{}, false, err
	}
	if !validOpaque(idempotencyKey, 1, 256) || !digestPattern.MatchString(intent) ||
		validateReceipt(receipt) != nil || receipt.IntentDigest != intent ||
		IdempotencyBindingDigest(idempotencyKey) != receipt.IdempotencyDigest {
		return Receipt{}, false, newError(InvalidInput, "receipt_commit_invalid", false, nil)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if recovered, found, err := store.Recover(ctx, receipt.Case, receipt.IdempotencyDigest); err != nil {
			return Receipt{}, false, err
		} else if found {
			if recovered.IntentDigest != intent || recovered.ReceiptDigest != receipt.ReceiptDigest {
				return Receipt{}, false, newError(Denied, "changed_replay", false, nil)
			}
			return recovered, true, nil
		}
		result, err := store.commitTracked(ctx, receipt)
		if err != nil {
			if CodeOf(err) == Conflict && attempt == 0 {
				continue
			}
			return Receipt{}, false, err
		}
		if result.Replayed {
			recovered, found, recoverErr := store.Recover(ctx, receipt.Case, receipt.IdempotencyDigest)
			if recoverErr != nil {
				return Receipt{}, false, recoverErr
			}
			if !found || recovered.IntentDigest != intent || recovered.ReceiptDigest != receipt.ReceiptDigest {
				return Receipt{}, false, newError(Denied, "replayed_receipt_invalid", false, nil)
			}
			return recovered, true, nil
		}
		return receipt, false, nil
	}
	return Receipt{}, false, newError(Conflict, "receipt_commit_conflict", true, nil)
}

func (store *RepositoryStore) loadMetadata(ctx context.Context,
	key workflowbase.RecordKey) (workflowbase.MetadataRecord, bool, error) {
	metadata, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return workflowbase.MetadataRecord{}, false, nil
		}
		return workflowbase.MetadataRecord{}, false, mapStorageError("receipt_load", err)
	}
	return metadata, true, nil
}

func decodeIngestionEnvelope(metadata workflowbase.MetadataRecord,
	key workflowbase.RecordKey, entryType string) (repositoryEnvelope, error) {
	var envelope repositoryEnvelope
	if err := decodeIngestionRecord(metadata.Canonical, &envelope); err != nil {
		return repositoryEnvelope{}, err
	}
	if envelope.Schema != repositoryRecordSchema || envelope.Kind != repositoryKind || envelope.ID != key.ID ||
		envelope.OrganizationID != key.Case.OrganizationID || envelope.TenantID != key.Case.TenantID ||
		envelope.CaseID == nil || *envelope.CaseID != key.Case.CaseID || envelope.Revision != metadata.Revision ||
		envelope.EntryType != entryType || metadata.Key != key || metadata.Schema != repositoryRecordSchema ||
		metadata.Digest != contentDigest(metadata.Canonical) {
		return repositoryEnvelope{}, newError(Denied, entryType+"_envelope_invalid", false, nil)
	}
	return envelope, nil
}

func ingestionMetadata(key workflowbase.RecordKey, receipt Receipt) (workflowbase.MetadataRecord, error) {
	return ingestionReceiptMetadata(key, "receipt", receipt)
}

func ingestionIndexMetadata(key workflowbase.RecordKey, receipt Receipt) (workflowbase.MetadataRecord, error) {
	return ingestionReceiptMetadata(key, "receipt_index", receipt)
}

func ingestionReceiptMetadata(key workflowbase.RecordKey, entryType string,
	receipt Receipt) (workflowbase.MetadataRecord, error) {
	encoded, err := canonicalValue(receiptToWire(receipt))
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	caseID := key.Case.CaseID
	envelope := repositoryEnvelope{Schema: repositoryRecordSchema, Kind: repositoryKind, ID: key.ID,
		OrganizationID: key.Case.OrganizationID, TenantID: key.Case.TenantID, CaseID: &caseID,
		Revision: 1, CreatedAt: formatTime(receipt.CreatedAt), EntryType: entryType, Data: encoded}
	canonical, err := canonicalValue(envelope)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	return workflowbase.MetadataRecord{Key: key, Schema: repositoryRecordSchema, Revision: 1,
		Canonical: canonical, Digest: contentDigest(canonical)}, nil
}

func ingestionReceiptKey(scope domain.CaseRef, idempotency string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-EVIDENCE-INGEST-RECEIPT-ID-V1\x00", scope.OrganizationID+"\x00"+
			scope.TenantID+"\x00"+scope.CaseID+"\x00"+idempotency)}
}

func ingestionReceiptIndexKey(scope domain.CaseRef, receiptDigest string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-EVIDENCE-INGEST-RECEIPT-INDEX-ID-V1\x00", scope.OrganizationID+"\x00"+
			scope.TenantID+"\x00"+scope.CaseID+"\x00"+receiptDigest)}
}

func decodeIngestionRecord(data []byte, output any) error {
	if len(data) == 0 || len(data) > 1<<20 || !json.Valid(data) {
		return newError(Denied, "record_encoding_invalid", false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "record_encoding_invalid", false, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "record_encoding_invalid", false, nil)
	}
	canonical, err := canonicalValue(output)
	if err != nil || !bytes.Equal(canonical, data) {
		return newError(Denied, "record_noncanonical", false, err)
	}
	return nil
}

func mapStorageError(operation string, err error) error {
	switch workflowbase.StorageCode(err) {
	case workflowbase.StorageInvalidInput:
		return newError(InvalidInput, operation+"_invalid", false, err)
	case workflowbase.StorageDenied:
		return newError(Denied, operation+"_denied", false, err)
	case workflowbase.StorageNotFound:
		return newError(NotFound, operation+"_not_found", false, err)
	case workflowbase.StorageConflict:
		return newError(Conflict, operation+"_conflict", false, err)
	case workflowbase.StorageCanceled:
		return newError(Canceled, operation+"_canceled", false, err)
	case workflowbase.StorageTimeout:
		return newError(Timeout, operation+"_timeout", false, err)
	default:
		return newError(Unavailable, operation+"_unavailable", true, err)
	}
}

var _ ManifestStore = (*RepositoryStore)(nil)
