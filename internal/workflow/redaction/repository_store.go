package redaction

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	repositorySchema = "coh.domain/v1"
	repositoryKind   = "redaction_record"
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
	if err := contextError(ctx); err != nil {
		return Receipt{}, false, err
	}
	if !validCase(scope) || !digestPattern.MatchString(idempotency) {
		return Receipt{}, false, newError(InvalidInput, "receipt_key_invalid", false, nil)
	}
	receipt, found, err := store.loadReceipt(ctx, redactionReceiptKey(scope, idempotency), scope, idempotency)
	if err != nil || !found {
		return Receipt{}, found, err
	}
	record, found, err := store.loadRecord(ctx, redactionRecordKey(scope, receipt.RedactionID), scope, receipt.RedactionID)
	if err != nil {
		return Receipt{}, false, err
	}
	if !found || validateReceiptRecord(receipt, record) != nil {
		return Receipt{}, false, newError(Denied, "receipt_record_invalid", false, nil)
	}
	return cloneReceipt(receipt), true, nil
}

func (store *RepositoryStore) LoadProgress(ctx context.Context, scope domain.CaseRef,
	idempotency string) (Progress, bool, error) {
	if err := contextError(ctx); err != nil {
		return Progress{}, false, err
	}
	if !validCase(scope) || !digestPattern.MatchString(idempotency) {
		return Progress{}, false, newError(InvalidInput, "progress_key_invalid", false, nil)
	}
	key := redactionProgressKey(scope, idempotency)
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return Progress{}, found, err
	}
	envelope, err := decodeRepositoryEnvelope(metadata, key, "progress")
	if err != nil {
		return Progress{}, false, err
	}
	var wire progressWire
	if err = decodeRepositoryValue(envelope.Data, &wire); err != nil {
		return Progress{}, false, err
	}
	value, err := progressFromWire(wire)
	if err != nil || validateProgress(value) != nil || value.Case != scope ||
		value.IdempotencyDigest != idempotency || value.Revision != metadata.Revision ||
		envelope.CreatedAt != formatTime(value.UpdatedAt) {
		return Progress{}, false, newError(Denied, "progress_record_invalid", false, err)
	}
	return cloneProgress(value), true, nil
}

func (store *RepositoryStore) Advance(ctx context.Context, idempotencyKey string,
	expected uint64, value Progress) (Progress, bool, error) {
	if err := contextError(ctx); err != nil {
		return Progress{}, false, err
	}
	idempotency, digestErr := IdempotencyBindingDigest(idempotencyKey)
	if digestErr != nil || !validOpaque(idempotencyKey, 1, 256) || validateProgress(value) != nil ||
		value.IdempotencyDigest != idempotency || value.Revision != expected+1 {
		return Progress{}, false, newError(InvalidInput, "progress_advance_invalid", false, nil)
	}
	current, found, err := store.LoadProgress(ctx, value.Case, value.IdempotencyDigest)
	if err != nil {
		return Progress{}, false, err
	}
	if found {
		if current.IntentDigest != value.IntentDigest {
			return Progress{}, false, newError(Denied, "changed_replay", false, nil)
		}
		if current.Revision >= value.Revision {
			return current, true, nil
		}
		if current.Revision != expected || !validProgressTransition(current, value) {
			return Progress{}, false, newError(Conflict, "progress_conflict", true, nil)
		}
	} else if expected != 0 || value.Phase != PhasePlanned {
		return Progress{}, false, newError(Conflict, "progress_missing", true, nil)
	}
	key := redactionProgressKey(value.Case, value.IdempotencyDigest)
	metadata, err := redactionMetadata(key, value.Revision, "progress", value.UpdatedAt, progressToWire(value))
	if err != nil {
		return Progress{}, false, err
	}
	transactionKey := digest("COH-REDACTION-PROGRESS-TRANSACTION-V1\x00", []byte(value.Case.OrganizationID+"\x00"+
		value.Case.TenantID+"\x00"+value.Case.CaseID+"\x00"+value.IdempotencyDigest+"\x00"+metadata.Digest))
	_, err = store.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: transactionKey, Mutations: []workflowbase.Mutation{{Kind: workflowbase.MutationPut,
			Key: key, ExpectedRevision: expected, Record: &metadata}}})
	if err != nil {
		recovered, recoveredFound, recoverErr := store.LoadProgress(ctx, value.Case, value.IdempotencyDigest)
		if recoverErr == nil && recoveredFound && recovered.IntentDigest == value.IntentDigest && recovered.Revision >= value.Revision {
			return recovered, true, nil
		}
		if recoverErr != nil && workflowbase.StorageCode(err) == workflowbase.StorageConflict {
			return Progress{}, false, recoverErr
		}
		return Progress{}, false, mapStorageError("progress_advance", err)
	}
	return cloneProgress(value), false, nil
}

func (store *RepositoryStore) Commit(ctx context.Context, idempotencyKey, intent string,
	record Record, receipt Receipt) (Receipt, bool, error) {
	if err := contextError(ctx); err != nil {
		return Receipt{}, false, err
	}
	idempotency, digestErr := IdempotencyBindingDigest(idempotencyKey)
	if digestErr != nil || !validOpaque(idempotencyKey, 1, 256) || !digestPattern.MatchString(intent) ||
		ValidateRecord(record) != nil || ValidateReceipt(receipt) != nil ||
		record.IntentDigest != intent || receipt.IntentDigest != intent ||
		receipt.IdempotencyDigest != idempotency ||
		validateReceiptRecord(receipt, record) != nil {
		return Receipt{}, false, newError(InvalidInput, "redaction_commit_invalid", false, nil)
	}
	if recovered, found, err := store.Recover(ctx, record.Case, receipt.IdempotencyDigest); err != nil {
		return Receipt{}, false, err
	} else if found {
		if recovered.IntentDigest != intent {
			return Receipt{}, false, newError(Denied, "changed_replay", false, nil)
		}
		return recovered, true, nil
	}
	progress, found, err := store.LoadProgress(ctx, record.Case, receipt.IdempotencyDigest)
	if err != nil {
		return Receipt{}, false, err
	}
	if !found || !progressMatchesRecord(progress, record) {
		return Receipt{}, false, newError(Denied, "commit_progress_invalid", false, nil)
	}
	recordKey := redactionRecordKey(record.Case, record.RedactionID)
	receiptKey := redactionReceiptKey(record.Case, receipt.IdempotencyDigest)
	recordMetadata, err := redactionMetadata(recordKey, 1, "record", record.CreatedAt, recordToWire(record))
	if err != nil {
		return Receipt{}, false, err
	}
	receiptMetadata, err := redactionMetadata(receiptKey, 1, "receipt", receipt.CreatedAt, receiptToWire(receipt))
	if err != nil {
		return Receipt{}, false, err
	}
	mutations := []workflowbase.Mutation{
		{Kind: workflowbase.MutationPut, Key: recordKey, ExpectedRevision: 0, Record: &recordMetadata},
		{Kind: workflowbase.MutationPut, Key: receiptKey, ExpectedRevision: 0, Record: &receiptMetadata},
	}
	sort.Slice(mutations, func(i, j int) bool { return mutations[i].Key.ID < mutations[j].Key.ID })
	outbox := workflowbase.OutboxMessage{ID: deterministicUUID("COH-REDACTION-OUTBOX-ID-V1\x00", record.RedactionID),
		Case: record.Case, Topic: "evidence.redaction.commit",
		PayloadRef:    "coh-redaction://" + record.Case.CaseID + "/" + record.RedactionID,
		PayloadDigest: record.RecordDigest}
	transactionKey := digest("COH-REDACTION-COMMIT-TRANSACTION-V1\x00", []byte(record.Case.OrganizationID+"\x00"+
		record.Case.TenantID+"\x00"+record.Case.CaseID+"\x00"+receipt.IdempotencyDigest))
	result, err := store.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: transactionKey, Mutations: mutations, Outbox: []workflowbase.OutboxMessage{outbox}})
	if err != nil {
		recovered, found, recoverErr := store.Recover(ctx, record.Case, receipt.IdempotencyDigest)
		if recoverErr == nil && found && recovered.IntentDigest == intent {
			return recovered, true, nil
		}
		return Receipt{}, false, mapStorageError("redaction_commit", err)
	}
	if result.Replayed {
		recovered, found, recoverErr := store.Recover(ctx, record.Case, receipt.IdempotencyDigest)
		if recoverErr != nil || !found || recovered.IntentDigest != intent {
			return Receipt{}, false, newError(Denied, "replayed_receipt_invalid", false, recoverErr)
		}
		return recovered, true, nil
	}
	return cloneReceipt(receipt), false, nil
}

func validProgressTransition(current, next Progress) bool {
	if !sameProgressIdentity(current, next) || next.Revision != current.Revision+1 ||
		next.UpdatedAt.Before(current.UpdatedAt) {
		return false
	}
	switch current.Phase {
	case PhasePlanned:
		return next.Phase == PhasePublished
	case PhasePublished:
		return next.Phase == PhaseCustodied && *current.MappingDigest == *next.MappingDigest &&
			*current.Derived == *next.Derived && *current.Mapping == *next.Mapping
	default:
		return false
	}
}

func progressMatchesRecord(progress Progress, record Record) bool {
	return progress.Phase == PhaseCustodied && progress.IntentDigest == record.IntentDigest &&
		progress.PlanDigest == record.PlanDigest && progress.DecisionDigest == record.DecisionDigest &&
		progress.ApprovalUseDigest == record.ApprovalUseDigest && progress.Derived != nil &&
		progress.Mapping != nil && progress.MappingDigest != nil && progress.Custody != nil &&
		progress.Derived.Reference == record.Derived && progress.Derived.ReceiptDigest == record.DerivedIngestionReceiptDigest &&
		progress.Mapping.Reference == record.MappingReference && progress.Mapping.ReceiptDigest == record.MappingIngestionReceiptDigest &&
		*progress.MappingDigest == record.MappingDigest && progress.Custody.ReceiptDigest == record.CustodyReceiptDigest
}

func validateReceiptRecord(receipt Receipt, record Record) error {
	if receipt.Case != record.Case || receipt.RequestID != record.Command.RequestID ||
		receipt.IntentDigest != record.IntentDigest || receipt.RedactionID != record.RedactionID ||
		receipt.RecordDigest != record.RecordDigest || receipt.Derived != record.Derived ||
		receipt.MappingReference != record.MappingReference || receipt.MappingDigest != record.MappingDigest ||
		receipt.CustodyReceiptDigest != record.CustodyReceiptDigest || receipt.AuditEventDigest != record.AuditEventDigest ||
		receipt.ProvenanceDigest != record.ProvenanceDigest || !receipt.CreatedAt.Equal(record.CreatedAt) {
		return newError(Denied, "receipt_record_invalid", false, nil)
	}
	return nil
}

func (store *RepositoryStore) loadReceipt(ctx context.Context, key workflowbase.RecordKey,
	scope domain.CaseRef, idempotency string) (Receipt, bool, error) {
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return Receipt{}, found, err
	}
	envelope, err := decodeRepositoryEnvelope(metadata, key, "receipt")
	if err != nil {
		return Receipt{}, false, err
	}
	var wire receiptWire
	if err = decodeRepositoryValue(envelope.Data, &wire); err != nil {
		return Receipt{}, false, err
	}
	value, err := receiptFromWire(wire)
	if err != nil || ValidateReceipt(value) != nil || value.Case != scope ||
		value.IdempotencyDigest != idempotency || metadata.Revision != 1 ||
		envelope.CreatedAt != formatTime(value.CreatedAt) {
		return Receipt{}, false, newError(Denied, "receipt_record_invalid", false, err)
	}
	return value, true, nil
}

func (store *RepositoryStore) loadRecord(ctx context.Context, key workflowbase.RecordKey,
	scope domain.CaseRef, redactionID string) (Record, bool, error) {
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return Record{}, found, err
	}
	envelope, err := decodeRepositoryEnvelope(metadata, key, "record")
	if err != nil {
		return Record{}, false, err
	}
	var wire recordWire
	if err = decodeRepositoryValue(envelope.Data, &wire); err != nil {
		return Record{}, false, err
	}
	value, err := recordFromWire(wire)
	if err != nil || ValidateRecord(value) != nil || value.Case != scope || value.RedactionID != redactionID ||
		metadata.Revision != 1 || envelope.CreatedAt != formatTime(value.CreatedAt) {
		return Record{}, false, newError(Denied, "redaction_record_invalid", false, err)
	}
	return value, true, nil
}

func (store *RepositoryStore) loadMetadata(ctx context.Context,
	key workflowbase.RecordKey) (workflowbase.MetadataRecord, bool, error) {
	metadata, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return workflowbase.MetadataRecord{}, false, nil
		}
		return workflowbase.MetadataRecord{}, false, mapStorageError("redaction_load", err)
	}
	return metadata, true, nil
}

func redactionMetadata(key workflowbase.RecordKey, revision uint64, entryType string,
	createdAt time.Time, data any) (workflowbase.MetadataRecord, error) {
	encoded, err := canonicalValue(data)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	caseID := key.Case.CaseID
	envelope := repositoryEnvelope{Schema: repositorySchema, Kind: repositoryKind, ID: key.ID,
		OrganizationID: key.Case.OrganizationID, TenantID: key.Case.TenantID, CaseID: &caseID,
		Revision: revision, CreatedAt: formatTime(createdAt), EntryType: entryType, Data: encoded}
	canonical, err := canonicalValue(envelope)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	return workflowbase.MetadataRecord{Key: key, Schema: repositorySchema, Revision: revision,
		Canonical: canonical, Digest: contentDigest(canonical)}, nil
}

func decodeRepositoryEnvelope(metadata workflowbase.MetadataRecord, key workflowbase.RecordKey,
	entryType string) (repositoryEnvelope, error) {
	var envelope repositoryEnvelope
	if err := decodeRepositoryValue(metadata.Canonical, &envelope); err != nil {
		return repositoryEnvelope{}, err
	}
	if envelope.Schema != repositorySchema || envelope.Kind != repositoryKind || envelope.ID != key.ID ||
		envelope.OrganizationID != key.Case.OrganizationID || envelope.TenantID != key.Case.TenantID ||
		envelope.CaseID == nil || *envelope.CaseID != key.Case.CaseID || envelope.Revision != metadata.Revision ||
		envelope.EntryType != entryType || metadata.Key != key || metadata.Schema != repositorySchema ||
		metadata.Digest != contentDigest(metadata.Canonical) {
		return repositoryEnvelope{}, newError(Denied, entryType+"_envelope_invalid", false, nil)
	}
	return envelope, nil
}

func decodeRepositoryValue(data []byte, output any) error {
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

func redactionProgressKey(scope domain.CaseRef, idempotency string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-REDACTION-PROGRESS-ID-V1\x00", scope.OrganizationID+"\x00"+
			scope.TenantID+"\x00"+scope.CaseID+"\x00"+idempotency)}
}

func redactionReceiptKey(scope domain.CaseRef, idempotency string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-REDACTION-RECEIPT-ID-V1\x00", scope.OrganizationID+"\x00"+
			scope.TenantID+"\x00"+scope.CaseID+"\x00"+idempotency)}
}

func redactionRecordKey(scope domain.CaseRef, redactionID string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-REDACTION-RECORD-INDEX-ID-V1\x00", scope.OrganizationID+"\x00"+
			scope.TenantID+"\x00"+scope.CaseID+"\x00"+redactionID)}
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
		return newError(Conflict, operation+"_conflict", true, err)
	case workflowbase.StorageCanceled:
		return newError(Canceled, operation+"_canceled", false, err)
	case workflowbase.StorageTimeout:
		return newError(Timeout, operation+"_timeout", true, err)
	default:
		return newError(Unavailable, operation+"_unavailable", true, err)
	}
}

var _ Store = (*RepositoryStore)(nil)
