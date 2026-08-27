package evidenceingest

import (
	"context"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

type pendingObjectWire struct {
	Role                    PublicationRole `json:"role"`
	Case                    caseWire        `json:"case"`
	PlaintextDigest         string          `json:"plaintext_digest"`
	PlaintextLength         int64           `json:"plaintext_length"`
	MediaType               string          `json:"media_type"`
	Classification          string          `json:"classification"`
	EncryptionContextDigest string          `json:"encryption_context_digest"`
	LocatorDigest           string          `json:"locator_digest"`
	CreatedAt               string          `json:"created_at"`
}

type pendingRecordWire struct {
	IntentDigest      string            `json:"intent_digest"`
	IdempotencyDigest string            `json:"idempotency_digest"`
	Pending           pendingObjectWire `json:"pending"`
}

type referenceRecordWire struct {
	Object        publishedObjectWire `json:"object"`
	ReceiptDigest string              `json:"receipt_digest"`
}

func (store *RepositoryStore) Track(ctx context.Context, idempotencyKey, intent string,
	pending PendingObject) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	idempotency := IdempotencyBindingDigest(idempotencyKey)
	if !validOpaque(idempotencyKey, 1, 256) || !digestPattern.MatchString(intent) ||
		validatePendingObject(pending) != nil {
		return newError(InvalidInput, "pending_track_invalid", false, nil)
	}
	if receipt, found, err := store.Recover(ctx, pending.Case, idempotency); err != nil {
		return err
	} else if found {
		if receipt.IntentDigest != intent {
			return newError(Denied, "changed_replay", false, nil)
		}
		return nil
	}
	if existing, found, err := store.loadPending(ctx, pending.Case, idempotency, pending.Role); err != nil {
		return err
	} else if found {
		storedIntent, intentErr := store.pendingIntent(ctx, pending.Case, idempotency, pending.Role)
		if intentErr != nil {
			return intentErr
		}
		if !samePendingIdentity(existing, pending) || storedIntent != intent {
			return newError(Denied, "changed_pending_replay", false, nil)
		}
		return nil
	}
	key := pendingRecordKey(pending.Case, idempotency, pending.Role)
	data := pendingRecordWire{IntentDigest: intent, IdempotencyDigest: idempotency,
		Pending: pendingToWire(pending)}
	metadata, err := reconciliationMetadata(key, 1, "pending", pending.CreatedAt, data)
	if err != nil {
		return err
	}
	transactionKey := digest("COH-EVIDENCE-PENDING-TRANSACTION-V1\x00",
		[]byte(pending.Case.OrganizationID+"\x00"+pending.Case.TenantID+"\x00"+pending.Case.CaseID+"\x00"+
			idempotency+"\x00"+string(pending.Role)))
	_, err = store.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: transactionKey, Mutations: []workflowbase.Mutation{{Kind: workflowbase.MutationPut,
			Key: key, ExpectedRevision: 0, Record: &metadata}}})
	if err == nil {
		return nil
	}
	if workflowbase.StorageCode(err) == workflowbase.StorageConflict {
		existing, found, loadErr := store.loadPending(ctx, pending.Case, idempotency, pending.Role)
		if loadErr == nil && found && samePendingIdentity(existing, pending) {
			storedIntent, intentErr := store.pendingIntent(ctx, pending.Case, idempotency, pending.Role)
			if intentErr == nil && storedIntent == intent {
				return nil
			}
			if intentErr != nil {
				return intentErr
			}
		}
		if loadErr != nil {
			return loadErr
		}
		return newError(Denied, "changed_pending_replay", false, err)
	}
	return mapStorageError("pending_track", err)
}

func (store *RepositoryStore) RecoverPending(ctx context.Context, scope domain.CaseRef,
	idempotency string) ([]PendingObject, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !validCase(scope) || !digestPattern.MatchString(idempotency) {
		return nil, newError(InvalidInput, "pending_key_invalid", false, nil)
	}
	result := make([]PendingObject, 0, 2)
	for _, role := range []PublicationRole{ArtifactPublication, ManifestPublication} {
		value, found, err := store.loadPending(ctx, scope, idempotency, role)
		if err != nil {
			return nil, err
		}
		if found {
			result = append(result, value)
		}
	}
	return result, nil
}

func (store *RepositoryStore) Referenced(ctx context.Context, object PublishedObject) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	if validatePublishedObject(object) != nil {
		return false, newError(InvalidInput, "reference_lookup_invalid", false, nil)
	}
	key := referenceRecordKey(object)
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return false, err
	}
	envelope, err := decodeIngestionEnvelope(metadata, key, "reference")
	if err != nil {
		return false, err
	}
	var wire referenceRecordWire
	if err = decodeIngestionRecord(envelope.Data, &wire); err != nil {
		return false, err
	}
	stored := publishedObjectFromWire(wire.Object)
	if stored != object || !digestPattern.MatchString(wire.ReceiptDigest) || envelope.Revision != 1 {
		return false, newError(Denied, "reference_record_invalid", false, nil)
	}
	return true, nil
}

func (store *RepositoryStore) commitTracked(ctx context.Context,
	receipt Receipt) (workflowbase.CommitResult, error) {
	pending, err := store.RecoverPending(ctx, receipt.Case, receipt.IdempotencyDigest)
	if err != nil {
		return workflowbase.CommitResult{}, err
	}
	if len(pending) != 2 || !pendingMatchesReceipt(pending[0], receipt) ||
		!pendingMatchesReceipt(pending[1], receipt) {
		return workflowbase.CommitResult{}, newError(Denied, "tracked_publication_invalid", false, nil)
	}
	receiptKey := ingestionReceiptKey(receipt.Case, receipt.IdempotencyDigest)
	receiptMetadata, err := ingestionMetadata(receiptKey, receipt)
	if err != nil {
		return workflowbase.CommitResult{}, err
	}
	mutations := []workflowbase.Mutation{{Kind: workflowbase.MutationPut, Key: receiptKey,
		ExpectedRevision: 0, Record: &receiptMetadata}}
	for _, candidate := range pending {
		mutations = append(mutations, workflowbase.Mutation{Kind: workflowbase.MutationDelete,
			Key: pendingRecordKey(receipt.Case, receipt.IdempotencyDigest, candidate.Role), ExpectedRevision: 1})
	}
	for _, object := range []PublishedObject{receipt.EncryptedArtifact, receipt.EncryptedManifest} {
		referenced, referenceErr := store.Referenced(ctx, object)
		if referenceErr != nil {
			return workflowbase.CommitResult{}, referenceErr
		}
		if referenced {
			continue
		}
		key := referenceRecordKey(object)
		metadata, metadataErr := reconciliationMetadata(key, 1, "reference", receipt.CreatedAt,
			referenceRecordWire{Object: publishedObjectToWire(object), ReceiptDigest: receipt.ReceiptDigest})
		if metadataErr != nil {
			return workflowbase.CommitResult{}, metadataErr
		}
		mutations = append(mutations, workflowbase.Mutation{Kind: workflowbase.MutationPut,
			Key: key, ExpectedRevision: 0, Record: &metadata})
	}
	sort.Slice(mutations, func(left, right int) bool { return mutations[left].Key.ID < mutations[right].Key.ID })
	transactionKey := digest("COH-EVIDENCE-INGEST-TRANSACTION-V2\x00", []byte(receipt.Case.OrganizationID+"\x00"+
		receipt.Case.TenantID+"\x00"+receipt.Case.CaseID+"\x00"+receipt.IdempotencyDigest))
	result, err := store.repository.Transact(ctx, workflowbase.Transaction{ContractVersion: workflowbase.StorageContractVersion,
		IdempotencyKey: transactionKey, Mutations: mutations})
	if err != nil {
		return workflowbase.CommitResult{}, mapStorageError("receipt_commit", err)
	}
	return result, nil
}

func (store *RepositoryStore) loadPending(ctx context.Context, scope domain.CaseRef, idempotency string,
	role PublicationRole) (PendingObject, bool, error) {
	key := pendingRecordKey(scope, idempotency, role)
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return PendingObject{}, found, err
	}
	envelope, err := decodeIngestionEnvelope(metadata, key, "pending")
	if err != nil {
		return PendingObject{}, false, err
	}
	var wire pendingRecordWire
	if err = decodeIngestionRecord(envelope.Data, &wire); err != nil {
		return PendingObject{}, false, err
	}
	value, err := pendingFromWire(wire.Pending)
	if err != nil || validatePendingObject(value) != nil || value.Case != scope || value.Role != role ||
		wire.IdempotencyDigest != idempotency || !digestPattern.MatchString(wire.IntentDigest) || envelope.Revision != 1 ||
		envelope.CreatedAt != formatTime(value.CreatedAt) {
		return PendingObject{}, false, newError(Denied, "pending_record_invalid", false, err)
	}
	return value, true, nil
}

// pending intents are reloaded separately to keep PendingObject's public shape
// free of command authorization metadata.
func (store *RepositoryStore) pendingIntent(ctx context.Context, scope domain.CaseRef, idempotency string,
	role PublicationRole) (string, error) {
	key := pendingRecordKey(scope, idempotency, role)
	metadata, found, err := store.loadMetadata(ctx, key)
	if err != nil || !found {
		return "", err
	}
	envelope, err := decodeIngestionEnvelope(metadata, key, "pending")
	if err != nil {
		return "", err
	}
	var wire pendingRecordWire
	if err = decodeIngestionRecord(envelope.Data, &wire); err != nil {
		return "", err
	}
	return wire.IntentDigest, nil
}

func pendingToWire(value PendingObject) pendingObjectWire {
	return pendingObjectWire{Role: value.Role, Case: caseToWire(value.Case), PlaintextDigest: value.PlaintextDigest,
		PlaintextLength: value.PlaintextLength, MediaType: value.MediaType, Classification: value.Classification,
		EncryptionContextDigest: value.EncryptionContextDigest, LocatorDigest: value.LocatorDigest,
		CreatedAt: formatTime(value.CreatedAt)}
}

func pendingFromWire(value pendingObjectWire) (PendingObject, error) {
	createdAt, err := parseTime(value.CreatedAt)
	if err != nil {
		return PendingObject{}, err
	}
	return PendingObject{Role: value.Role, Case: caseFromWire(value.Case), PlaintextDigest: value.PlaintextDigest,
		PlaintextLength: value.PlaintextLength, MediaType: value.MediaType, Classification: value.Classification,
		EncryptionContextDigest: value.EncryptionContextDigest, LocatorDigest: value.LocatorDigest,
		CreatedAt: createdAt}, nil
}

func samePendingIdentity(left, right PendingObject) bool {
	left.CreatedAt, right.CreatedAt = time.Time{}, time.Time{}
	return left == right
}

func pendingMatchesReceipt(value PendingObject, receipt Receipt) bool {
	switch value.Role {
	case ArtifactPublication:
		return value.Case == receipt.Case && value.PlaintextDigest == receipt.Artifact.Digest &&
			value.PlaintextLength == receipt.Artifact.Length && value.MediaType == receipt.Artifact.MediaType &&
			value.Classification == receipt.Artifact.Classification &&
			publishedMatchesPending(receipt.EncryptedArtifact, value)
	case ManifestPublication:
		return value.Case == receipt.Case && value.PlaintextDigest == receipt.Manifest.Digest &&
			value.PlaintextLength == receipt.Manifest.Length && value.MediaType == receipt.Manifest.MediaType &&
			value.Classification == receipt.Manifest.Classification &&
			publishedMatchesPending(receipt.EncryptedManifest, value)
	default:
		return false
	}
}

func reconciliationMetadata(key workflowbase.RecordKey, revision uint64, entryType string,
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
		Canonical: canonical, Digest: contentDigest(canonical)}, nil
}

func pendingRecordKey(scope domain.CaseRef, idempotency string, role PublicationRole) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: scope, Kind: repositoryKind,
		ID: deterministicUUID("COH-EVIDENCE-PENDING-ID-V1\x00", scope.OrganizationID+"\x00"+scope.TenantID+"\x00"+
			scope.CaseID+"\x00"+idempotency+"\x00"+string(role))}
}

func referenceRecordKey(object PublishedObject) workflowbase.RecordKey {
	return workflowbase.RecordKey{Case: object.Case, Kind: repositoryKind,
		ID: deterministicUUID("COH-EVIDENCE-REFERENCE-ID-V1\x00", object.Case.OrganizationID+"\x00"+
			object.Case.TenantID+"\x00"+object.Case.CaseID+"\x00"+object.LocatorDigest)}
}
