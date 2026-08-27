package evidencelifecycle

import (
	"context"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

type RepositoryStore struct{ repository workflowbase.MetadataStore }

func NewRepositoryStore(repository workflowbase.MetadataStore) (*RepositoryStore, error) {
	if repository == nil {
		return nil, newError(InvalidInput, "repository_required", false, nil)
	}
	return &RepositoryStore{repository: repository}, nil
}

func (store *RepositoryStore) Recover(ctx context.Context, scope domain.CaseRef,
	idempotency string) (Receipt, bool, error) {
	if err := lifecycleContextError(ctx); err != nil {
		return Receipt{}, false, err
	}
	if !validCase(scope) || !digestPattern.MatchString(idempotency) {
		return Receipt{}, false, newError(InvalidInput, "receipt_key_invalid", false, nil)
	}
	receipt, found, err := store.loadReceipt(ctx, lifecycleReceiptKey(scope, idempotency), scope, idempotency)
	if err != nil || !found {
		return Receipt{}, found, err
	}
	record, found, err := store.loadRecord(ctx, lifecycleRecordKey(scope, receipt.OperationID), scope,
		receipt.OperationID)
	if err != nil {
		return Receipt{}, false, err
	}
	if !found || !lifecycleReceiptMatchesRecord(receipt, record) {
		return Receipt{}, false, newError(Denied, "receipt_record_invalid", false, nil)
	}
	return receipt, true, nil
}

func (store *RepositoryStore) LoadProgress(ctx context.Context, scope domain.CaseRef,
	idempotency string) (Progress, bool, error) {
	if err := lifecycleContextError(ctx); err != nil {
		return Progress{}, false, err
	}
	if !validCase(scope) || !digestPattern.MatchString(idempotency) {
		return Progress{}, false, newError(InvalidInput, "progress_key_invalid", false, nil)
	}
	key := lifecycleProgressKey(scope, idempotency)
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return Progress{}, found, err
	}
	envelope, err := lifecycleDecodeEnvelope(metadata, key, "progress")
	if err != nil {
		return Progress{}, false, err
	}
	var value Progress
	if err = lifecycleDecode(envelope.Data, &value); err != nil || ValidateProgress(value) != nil ||
		value.Case != scope || value.Revision != metadata.Revision || envelope.CreatedAt != formatTime(value.UpdatedAt) {
		return Progress{}, false, newError(Denied, "progress_record_invalid", false, err)
	}
	return value, true, nil
}

func (store *RepositoryStore) Advance(ctx context.Context, idempotencyKey, intent string,
	value Progress) (Progress, bool, error) {
	if err := lifecycleContextError(ctx); err != nil {
		return Progress{}, false, err
	}
	idempotency, digestErr := IdempotencyBindingDigest(idempotencyKey)
	if digestErr != nil || ValidateProgress(value) != nil || value.IntentDigest != intent {
		return Progress{}, false, newError(InvalidInput, "progress_advance_invalid", false, digestErr)
	}
	current, found, err := store.LoadProgress(ctx, value.Case, idempotency)
	if err != nil {
		return Progress{}, false, err
	}
	if found {
		if current.IntentDigest != intent {
			return Progress{}, false, newError(Denied, string(ReasonChangedReplay), false, nil)
		}
		if current.ProgressDigest == value.ProgressDigest {
			return current, true, nil
		}
		if !validStoredProgressTransition(current, value) {
			return Progress{}, false, newError(Conflict, "progress_conflict", true, nil)
		}
	} else if !validInitialProgress(value) {
		return Progress{}, false, newError(Conflict, "progress_missing", true, nil)
	}
	key := lifecycleProgressKey(value.Case, idempotency)
	metadata, err := lifecycleMetadata(key, value.Revision, "progress", value.UpdatedAt, value)
	if err != nil {
		return Progress{}, false, err
	}
	expected := value.Revision - 1
	transactionKey := digest("COH-EVIDENCE-LIFECYCLE-PROGRESS-TRANSACTION-V1\x00",
		[]byte(value.Case.OrganizationID+"\x00"+value.Case.TenantID+"\x00"+value.Case.CaseID+"\x00"+
			idempotency+"\x00"+value.ProgressDigest))
	result, err := store.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: transactionKey, Mutations: []workflowbase.Mutation{{Kind: workflowbase.MutationPut,
			Key: key, ExpectedRevision: expected, Record: &metadata}}})
	if err != nil {
		recovered, recoveredFound, recoverErr := store.LoadProgress(ctx, value.Case, idempotency)
		if recoverErr == nil && recoveredFound && recovered.ProgressDigest == value.ProgressDigest {
			return recovered, true, nil
		}
		return Progress{}, false, lifecycleStorageError("progress_advance", err)
	}
	if result.Replayed {
		recovered, recoveredFound, recoverErr := store.LoadProgress(ctx, value.Case, idempotency)
		if recoverErr != nil || !recoveredFound || recovered.ProgressDigest != value.ProgressDigest {
			return Progress{}, false, newError(Denied, "replayed_progress_invalid", false, recoverErr)
		}
		return recovered, true, nil
	}
	return value, false, nil
}

func (store *RepositoryStore) Commit(ctx context.Context, idempotencyKey, intent string, progress Progress,
	record Record, receipt Receipt) (Receipt, bool, error) {
	if err := lifecycleContextError(ctx); err != nil {
		return Receipt{}, false, err
	}
	idempotency, digestErr := IdempotencyBindingDigest(idempotencyKey)
	if digestErr != nil || ValidateProgress(progress) != nil || ValidateRecord(record) != nil ||
		ValidateReceipt(receipt) != nil || progress.IntentDigest != intent || record.IntentDigest != intent ||
		receipt.IntentDigest != intent || receipt.IdempotencyDigest != idempotency ||
		!progressMatchesLifecycleRecord(progress, record) || !lifecycleReceiptMatchesRecord(receipt, record) {
		return Receipt{}, false, newError(InvalidInput, "lifecycle_commit_invalid", false, digestErr)
	}
	if recovered, found, err := store.Recover(ctx, record.Case, idempotency); err != nil {
		return Receipt{}, false, err
	} else if found {
		if recovered.IntentDigest != intent || recovered.ReceiptDigest != receipt.ReceiptDigest {
			return Receipt{}, false, newError(Denied, string(ReasonChangedReplay), false, nil)
		}
		return recovered, true, nil
	}
	current, found, err := store.LoadProgress(ctx, record.Case, idempotency)
	if err != nil {
		return Receipt{}, false, err
	}
	if !found || !validStoredProgressTransition(current, progress) {
		return Receipt{}, false, newError(Denied, "commit_progress_invalid", false, nil)
	}
	progressKey := lifecycleProgressKey(record.Case, idempotency)
	recordKey := lifecycleRecordKey(record.Case, record.OperationID)
	receiptKey := lifecycleReceiptKey(record.Case, idempotency)
	progressMetadata, err := lifecycleMetadata(progressKey, progress.Revision, "progress", progress.UpdatedAt, progress)
	if err != nil {
		return Receipt{}, false, err
	}
	recordMetadata, err := lifecycleMetadata(recordKey, 1, "record", record.CompletedAt, record)
	if err != nil {
		return Receipt{}, false, err
	}
	receiptMetadata, err := lifecycleMetadata(receiptKey, 1, "receipt", receipt.CreatedAt, receipt)
	if err != nil {
		return Receipt{}, false, err
	}
	mutations := []workflowbase.Mutation{
		{Kind: workflowbase.MutationPut, Key: progressKey, ExpectedRevision: current.Revision, Record: &progressMetadata},
		{Kind: workflowbase.MutationPut, Key: recordKey, ExpectedRevision: 0, Record: &recordMetadata},
		{Kind: workflowbase.MutationPut, Key: receiptKey, ExpectedRevision: 0, Record: &receiptMetadata},
	}
	sort.Slice(mutations, func(left, right int) bool { return mutations[left].Key.ID < mutations[right].Key.ID })
	outbox := workflowbase.OutboxMessage{ID: deterministicUUID("COH-EVIDENCE-LIFECYCLE-OUTBOX-ID-V1\x00",
		record.OperationID), Case: record.Case, Topic: "evidence.lifecycle.commit",
		PayloadRef:    "coh-evidence-lifecycle://" + record.Case.CaseID + "/" + record.OperationID,
		PayloadDigest: record.RecordDigest}
	transactionKey := digest("COH-EVIDENCE-LIFECYCLE-COMMIT-TRANSACTION-V1\x00",
		[]byte(record.Case.OrganizationID+"\x00"+record.Case.TenantID+"\x00"+record.Case.CaseID+"\x00"+idempotency))
	result, err := store.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: transactionKey, Mutations: mutations, Outbox: []workflowbase.OutboxMessage{outbox}})
	if err != nil {
		recovered, recoveredFound, recoverErr := store.Recover(ctx, record.Case, idempotency)
		if recoverErr == nil && recoveredFound && recovered.ReceiptDigest == receipt.ReceiptDigest {
			return recovered, true, nil
		}
		return Receipt{}, false, lifecycleStorageError("lifecycle_commit", err)
	}
	if result.Replayed {
		recovered, recoveredFound, recoverErr := store.Recover(ctx, record.Case, idempotency)
		if recoverErr != nil || !recoveredFound || recovered.ReceiptDigest != receipt.ReceiptDigest {
			return Receipt{}, false, newError(Denied, "replayed_receipt_invalid", false, recoverErr)
		}
		return recovered, true, nil
	}
	return receipt, false, nil
}

func (store *RepositoryStore) loadMetadata(ctx context.Context,
	key workflowbase.RecordKey) (workflowbase.MetadataRecord, bool, error) {
	metadata, err := store.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return workflowbase.MetadataRecord{}, false, nil
		}
		return workflowbase.MetadataRecord{}, false, lifecycleStorageError("lifecycle_load", err)
	}
	return metadata, true, nil
}

func lifecycleProgressKey(scope domain.CaseRef, idempotency string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: lifecycleRepositoryKind,
		ID: deterministicUUID("COH-EVIDENCE-LIFECYCLE-PROGRESS-ID-V1\x00",
			scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+scope.CaseID+"\x00"+idempotency)}
}

func lifecycleReceiptKey(scope domain.CaseRef, idempotency string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: lifecycleRepositoryKind,
		ID: deterministicUUID("COH-EVIDENCE-LIFECYCLE-RECEIPT-ID-V1\x00",
			scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+scope.CaseID+"\x00"+idempotency)}
}

func lifecycleRecordKey(scope domain.CaseRef, operationID string) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: lifecycleRepositoryKind,
		ID: deterministicUUID("COH-EVIDENCE-LIFECYCLE-RECORD-ID-V1\x00",
			scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+scope.CaseID+"\x00"+operationID)}
}

var _ Store = (*RepositoryStore)(nil)
