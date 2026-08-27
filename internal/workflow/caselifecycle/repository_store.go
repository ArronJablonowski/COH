package caselifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	repositoryRecordSchema = "coh.domain/v1"
	repositoryKind         = "case_lifecycle"
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

func (store *RepositoryStore) Load(ctx context.Context, scope domain.CaseRef) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	if !validCase(scope) {
		return Record{}, false, newError(InvalidInput, "case_key_invalid", false, nil)
	}
	key := currentRecordKey(scope)
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return Record{}, found, err
	}
	envelope, err := decodeEnvelope(metadata, key, "current")
	if err != nil {
		return Record{}, false, err
	}
	var wire recordWire
	if err = decodeRepositoryRecord(envelope.Data, &wire); err != nil {
		return Record{}, false, err
	}
	value, err := recordFromWire(wire)
	if err != nil || validateRecord(value) != nil || value.Case != scope ||
		envelope.Revision != value.Revision || envelope.CreatedAt != formatTime(value.CreatedAt) {
		return Record{}, false, newError(Denied, "current_record_invalid", false, err)
	}
	return cloneRecord(value), true, nil
}

func (store *RepositoryStore) Recover(ctx context.Context, scope domain.CaseRef,
	idempotency string) (Receipt, bool, error) {
	return store.loadReceipt(ctx, receiptRecordKey(scope, idempotency), scope, "receipt", idempotency, "")
}

// ResolveReceipt loads an immutable lifecycle receipt by its canonical digest.
// The digest index is a lookup convenience only; the complete receipt is
// decoded and validated again before it is returned.
func (store *RepositoryStore) ResolveReceipt(ctx context.Context, scope domain.CaseRef,
	receiptDigest string) (Receipt, bool, error) {
	return store.loadReceipt(ctx, receiptIndexKey(scope, receiptDigest), scope,
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
	envelope, err := decodeEnvelope(metadata, key, entryType)
	if err != nil {
		return Receipt{}, false, err
	}
	var wire receiptWire
	if err = decodeRepositoryRecord(envelope.Data, &wire); err != nil {
		return Receipt{}, false, err
	}
	value, err := receiptFromWire(wire)
	if err != nil || validateReceipt(value) != nil || value.Case != scope ||
		idempotency != "" && value.IdempotencyDigest != idempotency ||
		receiptDigest != "" && value.ReceiptDigest != receiptDigest || envelope.Revision != 1 ||
		envelope.CreatedAt != formatTime(value.CreatedAt) {
		return Receipt{}, false, newError(Denied, "receipt_record_invalid", false, err)
	}
	return cloneReceipt(value), true, nil
}

func (store *RepositoryStore) Commit(ctx context.Context, idempotencyKey, intent string,
	expected uint64, record Record, receipt Receipt) (Receipt, bool, error) {
	if err := contextError(ctx); err != nil {
		return Receipt{}, false, err
	}
	if !validOpaque(idempotencyKey, 1, 256) || !digestPattern.MatchString(intent) ||
		validateRecord(record) != nil || validateReceipt(receipt) != nil ||
		record.IntentDigest != intent || receipt.IntentDigest != intent || receipt.Record.ProvenanceDigest != record.ProvenanceDigest ||
		record.Revision != expected+1 || IdempotencyBindingDigest(idempotencyKey) != record.IdempotencyDigest {
		return Receipt{}, false, newError(InvalidInput, "case_commit_invalid", false, nil)
	}
	if recovered, found, err := store.Recover(ctx, record.Case, record.IdempotencyDigest); err != nil {
		return Receipt{}, false, err
	} else if found {
		if recovered.IntentDigest != intent || recovered.ReceiptDigest != receipt.ReceiptDigest {
			return Receipt{}, false, newError(Denied, "changed_replay", false, nil)
		}
		return recovered, true, nil
	}
	currentKey := currentRecordKey(record.Case)
	receiptKey := receiptRecordKey(record.Case, record.IdempotencyDigest)
	indexKey := receiptIndexKey(record.Case, receipt.ReceiptDigest)
	currentMetadata, err := metadataFor(currentKey, record.Revision, "current", record.CreatedAt, recordToWire(record))
	if err != nil {
		return Receipt{}, false, err
	}
	receiptMetadata, err := metadataFor(receiptKey, 1, "receipt", receipt.CreatedAt, receiptToWire(receipt))
	if err != nil {
		return Receipt{}, false, err
	}
	indexMetadata, err := metadataFor(indexKey, 1, "receipt_index", receipt.CreatedAt, receiptToWire(receipt))
	if err != nil {
		return Receipt{}, false, err
	}
	mutations := []workflowbase.Mutation{
		{Kind: workflowbase.MutationPut, Key: currentKey, ExpectedRevision: expected, Record: &currentMetadata},
		{Kind: workflowbase.MutationPut, Key: receiptKey, ExpectedRevision: 0, Record: &receiptMetadata},
		{Kind: workflowbase.MutationPut, Key: indexKey, ExpectedRevision: 0, Record: &indexMetadata},
	}
	sort.Slice(mutations, func(i, j int) bool { return mutations[i].Key.ID < mutations[j].Key.ID })
	transactionKey := digest("COH-CASE-TRANSACTION-V1\x00", []byte(record.Case.OrganizationID+"\x00"+
		record.Case.TenantID+"\x00"+record.Case.CaseID+"\x00"+record.IdempotencyDigest))
	result, err := store.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: transactionKey, Mutations: mutations})
	if err != nil {
		return Receipt{}, false, mapStorageError("case_commit", err)
	}
	if result.Replayed {
		recovered, found, recoverErr := store.Recover(ctx, record.Case, record.IdempotencyDigest)
		if recoverErr != nil {
			return Receipt{}, false, recoverErr
		}
		if !found || recovered.IntentDigest != intent {
			return Receipt{}, false, newError(Denied, "replayed_receipt_invalid", false, nil)
		}
		return recovered, true, nil
	}
	return cloneReceipt(receipt), false, nil
}

func (store *RepositoryStore) loadMetadata(ctx context.Context, key workflowbase.RecordKey) (workflowbase.MetadataRecord, bool, error) {
	metadata, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return workflowbase.MetadataRecord{}, false, nil
		}
		return workflowbase.MetadataRecord{}, false, mapStorageError("case_load", err)
	}
	return metadata, true, nil
}

func decodeEnvelope(metadata workflowbase.MetadataRecord, key workflowbase.RecordKey,
	entryType string) (repositoryEnvelope, error) {
	var envelope repositoryEnvelope
	if err := decodeRepositoryRecord(metadata.Canonical, &envelope); err != nil {
		return repositoryEnvelope{}, err
	}
	if envelope.Schema != repositoryRecordSchema || envelope.Kind != repositoryKind || envelope.ID != key.ID ||
		envelope.OrganizationID != key.Case.OrganizationID || envelope.TenantID != key.Case.TenantID ||
		envelope.CaseID == nil || *envelope.CaseID != key.Case.CaseID || envelope.Revision != metadata.Revision ||
		envelope.EntryType != entryType || metadata.Key != key || metadata.Schema != repositoryRecordSchema ||
		metadata.Digest != rawDigest(metadata.Canonical) {
		return repositoryEnvelope{}, newError(Denied, entryType+"_envelope_invalid", false, nil)
	}
	return envelope, nil
}

func metadataFor(key workflowbase.RecordKey, revision uint64, entryType string,
	createdAt time.Time, data any) (workflowbase.MetadataRecord, error) {
	encoded, err := canonicalValue(data)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	caseID := key.Case.CaseID
	envelope := repositoryEnvelope{Schema: repositoryRecordSchema, Kind: repositoryKind, ID: key.ID,
		OrganizationID: key.Case.OrganizationID, TenantID: key.Case.TenantID, CaseID: &caseID,
		Revision: revision, CreatedAt: formatTime(createdAt), EntryType: entryType, Data: encoded}
	canonical, err := canonicalValue(envelope)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	return workflowbase.MetadataRecord{Key: key, Schema: repositoryRecordSchema, Revision: revision,
		Canonical: canonical, Digest: rawDigest(canonical)}, nil
}

func currentRecordKey(scope domain.CaseRef) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-CASE-CURRENT-ID-V1\x00", scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+scope.CaseID)}
}

func receiptRecordKey(scope domain.CaseRef, idempotency string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-CASE-RECEIPT-ID-V1\x00", scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+
			scope.CaseID+"\x00"+idempotency)}
}

func receiptIndexKey(scope domain.CaseRef, receiptDigest string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-CASE-RECEIPT-INDEX-ID-V1\x00", scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+
			scope.CaseID+"\x00"+receiptDigest)}
}

func decodeRepositoryRecord(data []byte, output any) error {
	if len(data) == 0 || len(data) > 1<<20 || !json.Valid(data) {
		return newError(Denied, "record_encoding_invalid", false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "record_encoding_invalid", false, nil)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "record_encoding_invalid", false, nil)
	}
	canonical, err := canonicalValue(output)
	if err != nil || !bytes.Equal(canonical, data) {
		return newError(Denied, "record_noncanonical", false, nil)
	}
	return nil
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
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

var _ Store = (*RepositoryStore)(nil)
