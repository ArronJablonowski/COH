package evidencelifecycle

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

func (store *RepositoryStore) loadReceipt(ctx context.Context, key workflowbase.RecordKey,
	scope domain.CaseRef, idempotency string) (Receipt, bool, error) {
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return Receipt{}, found, err
	}
	envelope, err := lifecycleDecodeEnvelope(metadata, key, "receipt")
	if err != nil {
		return Receipt{}, false, err
	}
	var value Receipt
	if err = lifecycleDecode(envelope.Data, &value); err != nil || ValidateReceipt(value) != nil ||
		value.Case != scope || value.IdempotencyDigest != idempotency || metadata.Revision != 1 ||
		envelope.CreatedAt != formatTime(value.CreatedAt) {
		return Receipt{}, false, newError(Denied, "receipt_record_invalid", false, err)
	}
	return value, true, nil
}

func (store *RepositoryStore) loadRecord(ctx context.Context, key workflowbase.RecordKey,
	scope domain.CaseRef, operationID string) (Record, bool, error) {
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return Record{}, found, err
	}
	envelope, err := lifecycleDecodeEnvelope(metadata, key, "record")
	if err != nil {
		return Record{}, false, err
	}
	var value Record
	if err = lifecycleDecode(envelope.Data, &value); err != nil || ValidateRecord(value) != nil ||
		value.Case != scope || value.OperationID != operationID || metadata.Revision != 1 ||
		envelope.CreatedAt != formatTime(value.CompletedAt) {
		return Record{}, false, newError(Denied, "lifecycle_record_invalid", false, err)
	}
	return value, true, nil
}
