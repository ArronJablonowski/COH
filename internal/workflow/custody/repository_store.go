package custody

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	repositorySchema = "coh.domain/v1"
	repositoryKind   = "custody_record"
)

type RepositoryStore struct{ repository workflowbase.MetadataStore }

type custodyEnvelope struct {
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

func (store *RepositoryStore) LoadHead(ctx context.Context, scope domain.CaseRef) (Head, error) {
	if err := contextError(ctx); err != nil {
		return Head{}, err
	}
	if !validCase(scope) {
		return Head{}, newError(InvalidInput, "head_key_invalid", false, nil)
	}
	key := custodyHeadKey(scope)
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil {
		return Head{}, err
	}
	if !found {
		return Head{Case: scope, ChainHash: GenesisHash}, nil
	}
	envelope, err := decodeCustodyEnvelope(metadata, key, "head")
	if err != nil {
		return Head{}, err
	}
	var wire headWire
	if err = decodeCanonical(envelope.Data, &wire); err != nil {
		return Head{}, err
	}
	head, err := headFromWire(wire)
	if err != nil || !validHead(head) || head.Case != scope || head.Sequence != metadata.Revision {
		return Head{}, newError(Denied, "head_record_invalid", false, err)
	}
	return cloneHead(head), nil
}

func (store *RepositoryStore) Recover(ctx context.Context, scope domain.CaseRef,
	idempotency string) (Receipt, bool, error) {
	return store.loadReceipt(ctx, custodyIdempotencyKey(scope, idempotency), scope, "receipt", idempotency, "")
}

func (store *RepositoryStore) ResolveReceipt(ctx context.Context, scope domain.CaseRef,
	receiptDigest string) (Receipt, bool, error) {
	return store.loadReceipt(ctx, custodyReceiptIndexKey(scope, receiptDigest), scope,
		"receipt_index", "", receiptDigest)
}

func (store *RepositoryStore) Append(ctx context.Context, idempotencyKey, intent string, expected Head,
	record Record, receipt Receipt) (Receipt, bool, error) {
	if err := contextError(ctx); err != nil {
		return Receipt{}, false, err
	}
	if !validOpaque(idempotencyKey, 1, 256) || !digestPattern.MatchString(intent) || !validHead(expected) ||
		validateRecord(record) != nil || validateReceipt(receipt) != nil || record.Case != expected.Case ||
		record.Sequence != expected.Sequence+1 || record.PreviousChainHash != expected.ChainHash ||
		record.IntentDigest != intent || receipt.IntentDigest != intent ||
		receipt.IdempotencyDigest != IdempotencyBindingDigest(idempotencyKey) ||
		validateReceiptRecordDirect(receipt, record) != nil {
		return Receipt{}, false, newError(InvalidInput, "custody_commit_invalid", false, nil)
	}
	if recovered, found, err := store.Recover(ctx, record.Case, receipt.IdempotencyDigest); err != nil {
		return Receipt{}, false, err
	} else if found {
		if recovered.IntentDigest != intent {
			return Receipt{}, false, newError(Denied, "changed_replay", false, nil)
		}
		return recovered, true, nil
	}
	mutations, err := custodyMutations(expected, record, receipt)
	if err != nil {
		return Receipt{}, false, err
	}
	outbox := workflowbase.OutboxMessage{ID: deterministicUUID("COH-CUSTODY-OUTBOX-ID-V1\x00", record.CustodyID),
		Case: record.Case, Topic: "evidence.custody.commit",
		PayloadRef:    "coh-custody://" + record.Case.CaseID + "/" + record.CustodyID,
		PayloadDigest: record.AuditEventDigest}
	transactionKey := digest("COH-CUSTODY-TRANSACTION-V1\x00", []byte(record.Case.OrganizationID+"\x00"+
		record.Case.TenantID+"\x00"+record.Case.CaseID+"\x00"+receipt.IdempotencyDigest))
	result, err := store.repository.Transact(ctx, workflowbase.Transaction{
		ContractVersion: workflowbase.StorageContractVersion, IdempotencyKey: transactionKey,
		Mutations: mutations, Outbox: []workflowbase.OutboxMessage{outbox}})
	if err != nil {
		recovered, found, recoverErr := store.Recover(ctx, record.Case, receipt.IdempotencyDigest)
		if recoverErr == nil && found && recovered.IntentDigest == intent {
			return recovered, true, nil
		}
		if recoverErr != nil && workflowbase.StorageCode(err) == workflowbase.StorageConflict {
			return Receipt{}, false, recoverErr
		}
		return Receipt{}, false, mapCustodyStorageError("custody_commit", err)
	}
	if result.Replayed {
		recovered, found, recoverErr := store.Recover(ctx, record.Case, receipt.IdempotencyDigest)
		if recoverErr != nil || !found || recovered.IntentDigest != intent {
			return Receipt{}, false, newError(Denied, "replayed_receipt_invalid", false, recoverErr)
		}
		return recovered, true, nil
	}
	return receipt, false, nil
}

func (store *RepositoryStore) Read(ctx context.Context, scope domain.CaseRef, after uint64,
	limit uint16) ([]Record, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !validCase(scope) || after > math.MaxInt64 || limit == 0 || limit > custodyReadBatch {
		return nil, newError(InvalidInput, "custody_read_invalid", false, nil)
	}
	result := make([]Record, 0, limit)
	for offset := uint64(1); offset <= uint64(limit); offset++ {
		sequence := after + offset
		if sequence > math.MaxInt64 {
			break
		}
		key := custodySequenceKey(scope, sequence)
		metadata, found, err := store.loadMetadata(ctx, key)
		if err != nil {
			return nil, err
		}
		if !found {
			break
		}
		envelope, err := decodeCustodyEnvelope(metadata, key, "record")
		if err != nil {
			return nil, err
		}
		var wire recordWire
		if err = decodeCanonical(envelope.Data, &wire); err != nil {
			return nil, err
		}
		record, err := recordFromWire(wire)
		if err != nil || validateRecord(record) != nil || record.Case != scope || record.Sequence != sequence ||
			metadata.Revision != 1 || envelope.CreatedAt != formatTime(record.OccurredAt) {
			return nil, newError(Denied, "custody_record_invalid", false, err)
		}
		result = append(result, cloneRecord(record))
	}
	return result, nil
}

func custodyMutations(expected Head, record Record, receipt Receipt) ([]workflowbase.Mutation, error) {
	last := record.OccurredAt
	head := Head{Case: record.Case, Sequence: record.Sequence, ChainHash: record.ChainHash, LastRecordAt: &last}
	headKey, recordKey := custodyHeadKey(record.Case), custodySequenceKey(record.Case, record.Sequence)
	receiptKey := custodyIdempotencyKey(record.Case, receipt.IdempotencyDigest)
	indexKey := custodyReceiptIndexKey(record.Case, receipt.ReceiptDigest)
	headMetadata, err := custodyMetadata(headKey, record.Sequence, "head", record.OccurredAt, headToWire(head))
	if err != nil {
		return nil, err
	}
	recordMetadata, err := custodyMetadata(recordKey, 1, "record", record.OccurredAt, recordToWire(record))
	if err != nil {
		return nil, err
	}
	receiptMetadata, err := custodyMetadata(receiptKey, 1, "receipt", receipt.CreatedAt, receiptToWire(receipt))
	if err != nil {
		return nil, err
	}
	indexMetadata, err := custodyMetadata(indexKey, 1, "receipt_index", receipt.CreatedAt, receiptToWire(receipt))
	if err != nil {
		return nil, err
	}
	mutations := []workflowbase.Mutation{
		{Kind: workflowbase.MutationPut, Key: headKey, ExpectedRevision: expected.Sequence, Record: &headMetadata},
		{Kind: workflowbase.MutationPut, Key: recordKey, ExpectedRevision: 0, Record: &recordMetadata},
		{Kind: workflowbase.MutationPut, Key: receiptKey, ExpectedRevision: 0, Record: &receiptMetadata},
		{Kind: workflowbase.MutationPut, Key: indexKey, ExpectedRevision: 0, Record: &indexMetadata},
	}
	sort.Slice(mutations, func(left, right int) bool {
		return mutations[left].Key.Kind+mutations[left].Key.ID < mutations[right].Key.Kind+mutations[right].Key.ID
	})
	return mutations, nil
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
	envelope, err := decodeCustodyEnvelope(metadata, key, entryType)
	if err != nil {
		return Receipt{}, false, err
	}
	var wire receiptWire
	if err = decodeCanonical(envelope.Data, &wire); err != nil {
		return Receipt{}, false, err
	}
	receipt, err := receiptFromWire(wire)
	if err != nil || validateReceipt(receipt) != nil || receipt.Case != scope || metadata.Revision != 1 ||
		envelope.CreatedAt != formatTime(receipt.CreatedAt) || idempotency != "" && receipt.IdempotencyDigest != idempotency ||
		receiptDigest != "" && receipt.ReceiptDigest != receiptDigest {
		return Receipt{}, false, newError(Denied, "receipt_record_invalid", false, err)
	}
	return receipt, true, nil
}

func (store *RepositoryStore) loadMetadata(ctx context.Context,
	key workflowbase.RecordKey) (workflowbase.MetadataRecord, bool, error) {
	metadata, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return workflowbase.MetadataRecord{}, false, nil
		}
		return workflowbase.MetadataRecord{}, false, mapCustodyStorageError("custody_load", err)
	}
	return metadata, true, nil
}

func custodyMetadata(key workflowbase.RecordKey, revision uint64, entryType string,
	createdAt time.Time, data any) (workflowbase.MetadataRecord, error) {
	encoded, err := canonicalValue(data)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	caseID := key.Case.CaseID
	envelope := custodyEnvelope{Schema: repositorySchema, Kind: repositoryKind, ID: key.ID,
		OrganizationID: key.Case.OrganizationID, TenantID: key.Case.TenantID, CaseID: &caseID,
		Revision: revision, CreatedAt: formatTime(createdAt), EntryType: entryType, Data: encoded}
	canonical, err := canonicalValue(envelope)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	return workflowbase.MetadataRecord{Key: key, Schema: repositorySchema, Revision: revision,
		Canonical: canonical, Digest: rawDigest(canonical)}, nil
}

func decodeCustodyEnvelope(metadata workflowbase.MetadataRecord, key workflowbase.RecordKey,
	entryType string) (custodyEnvelope, error) {
	var envelope custodyEnvelope
	if err := decodeCanonical(metadata.Canonical, &envelope); err != nil {
		return custodyEnvelope{}, err
	}
	if envelope.Schema != repositorySchema || envelope.Kind != repositoryKind || envelope.ID != key.ID ||
		envelope.OrganizationID != key.Case.OrganizationID || envelope.TenantID != key.Case.TenantID ||
		envelope.CaseID == nil || *envelope.CaseID != key.Case.CaseID || envelope.Revision != metadata.Revision ||
		envelope.EntryType != entryType || metadata.Key != key || metadata.Schema != repositorySchema ||
		metadata.Digest != rawDigest(metadata.Canonical) {
		return custodyEnvelope{}, newError(Denied, entryType+"_envelope_invalid", false, nil)
	}
	return envelope, nil
}

func custodyHeadKey(scope domain.CaseRef) workflowbase.RecordKey {
	return custodyKey(scope, "COH-CUSTODY-HEAD-ID-V1\x00", "head")
}

func custodySequenceKey(scope domain.CaseRef, sequence uint64) workflowbase.RecordKey {
	return custodyKey(scope, "COH-CUSTODY-SEQUENCE-ID-V1\x00", "sequence\x00"+strconv.FormatUint(sequence, 10))
}

func custodyIdempotencyKey(scope domain.CaseRef, idempotency string) workflowbase.RecordKey {
	return custodyKey(scope, "COH-CUSTODY-RECEIPT-ID-V1\x00", "idempotency\x00"+idempotency)
}

func custodyReceiptIndexKey(scope domain.CaseRef, receiptDigest string) workflowbase.RecordKey {
	return custodyKey(scope, "COH-CUSTODY-RECEIPT-INDEX-ID-V1\x00", "receipt\x00"+receiptDigest)
}

func custodyKey(scope domain.CaseRef, domainName, suffix string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID(domainName, scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+scope.CaseID+"\x00"+suffix)}
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func mapCustodyStorageError(operation string, err error) error {
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

var _ Ledger = (*RepositoryStore)(nil)
