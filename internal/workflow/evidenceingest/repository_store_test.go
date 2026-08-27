package evidenceingest

import (
	"bytes"
	"context"
	"testing"

	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

type metadataMemory struct {
	records map[workflowbase.RecordKey]workflowbase.MetadataRecord
}

func (memory *metadataMemory) Get(_ context.Context,
	key workflowbase.RecordKey) (workflowbase.MetadataRecord, error) {
	value, found := memory.records[key]
	if !found {
		return workflowbase.MetadataRecord{}, workflowbase.NewStorageError(workflowbase.StorageNotFound,
			"get", "key", "not found", nil)
	}
	return value, nil
}

func (memory *metadataMemory) Transact(_ context.Context,
	transaction workflowbase.Transaction) (workflowbase.CommitResult, error) {
	for _, mutation := range transaction.Mutations {
		record, found := memory.records[mutation.Key]
		if !found && mutation.ExpectedRevision != 0 || found && record.Revision != mutation.ExpectedRevision {
			return workflowbase.CommitResult{}, workflowbase.NewStorageError(workflowbase.StorageConflict,
				"transact", "revision", "revision mismatch", nil)
		}
	}
	for _, mutation := range transaction.Mutations {
		if mutation.Kind == workflowbase.MutationDelete {
			delete(memory.records, mutation.Key)
		} else {
			memory.records[mutation.Key] = *mutation.Record
		}
	}
	return workflowbase.CommitResult{IdempotencyKey: transaction.IdempotencyKey, CommitSequence: 1,
		RecordVersions: map[string]uint64{}, OutboxIDs: []string{}}, nil
}

func TestRepositoryStoreCommitsRecoversAndRejectsChangedReplay(t *testing.T) {
	memory := &metadataMemory{records: map[workflowbase.RecordKey]workflowbase.MetadataRecord{}}
	store, err := NewRepositoryStore(memory)
	if err != nil {
		t.Fatal(err)
	}
	command := validCommand()
	authorization := validAuthorization(command)
	decision := validDecision(command, authorization)
	manifest := validManifest(command, authorization, decision)
	receipt := validReceipt(command, authorization, decision, manifest)
	trackReceiptObjects(t, store, command, authorization.IntentDigest, receipt)
	stored, replayed, err := store.Commit(t.Context(), command.IdempotencyKey, authorization.IntentDigest, receipt)
	if err != nil || replayed || stored.ReceiptDigest != receipt.ReceiptDigest || len(memory.records) != 3 {
		t.Fatalf("stored=%+v replayed=%v records=%d err=%v", stored, replayed, len(memory.records), err)
	}
	for _, record := range memory.records {
		if bytes.Contains(record.Canonical, []byte(command.Source.Identity)) {
			t.Fatal("sensitive source identity was persisted in receipt metadata")
		}
	}
	recovered, found, err := store.Recover(t.Context(), command.Case, receipt.IdempotencyDigest)
	if err != nil || !found || recovered.ReceiptDigest != receipt.ReceiptDigest {
		t.Fatalf("recovered=%+v found=%v err=%v", recovered, found, err)
	}
	if pending, pendingErr := store.RecoverPending(t.Context(), command.Case,
		receipt.IdempotencyDigest); pendingErr != nil || len(pending) != 0 {
		t.Fatalf("pending=%+v err=%v", pending, pendingErr)
	}
	for _, object := range []PublishedObject{receipt.EncryptedArtifact, receipt.EncryptedManifest} {
		if referenced, referenceErr := store.Referenced(t.Context(), object); referenceErr != nil || !referenced {
			t.Fatalf("referenced=%v err=%v", referenced, referenceErr)
		}
	}
	replayedReceipt, replayed, err := store.Commit(t.Context(), command.IdempotencyKey,
		authorization.IntentDigest, receipt)
	if err != nil || !replayed || replayedReceipt.ReceiptDigest != receipt.ReceiptDigest {
		t.Fatalf("replayed=%+v flag=%v err=%v", replayedReceipt, replayed, err)
	}

	changed := command
	changed.MediaType = "application/cbor"
	changedAuthorization := validAuthorization(changed)
	changedDecision := validDecision(changed, changedAuthorization)
	changedManifest := validManifest(changed, changedAuthorization, changedDecision)
	changedReceipt := validReceipt(changed, changedAuthorization, changedDecision, changedManifest)
	if _, _, err = store.Commit(t.Context(), changed.IdempotencyKey,
		changedAuthorization.IntentDigest, changedReceipt); CodeOf(err) != Denied || Reason(err) != "changed_replay" {
		t.Fatalf("changed replay code=%s reason=%s err=%v", CodeOf(err), Reason(err), err)
	}
}

func TestRepositoryStoreFailsClosedOnTamperedCanonicalReceipt(t *testing.T) {
	memory := &metadataMemory{records: map[workflowbase.RecordKey]workflowbase.MetadataRecord{}}
	store, _ := NewRepositoryStore(memory)
	command := validCommand()
	authorization := validAuthorization(command)
	decision := validDecision(command, authorization)
	receipt := validReceipt(command, authorization, decision, validManifest(command, authorization, decision))
	trackReceiptObjects(t, store, command, authorization.IntentDigest, receipt)
	if _, _, err := store.Commit(t.Context(), command.IdempotencyKey, authorization.IntentDigest, receipt); err != nil {
		t.Fatal(err)
	}
	for key, record := range memory.records {
		record.Canonical[len(record.Canonical)/2] ^= 1
		memory.records[key] = record
	}
	if _, _, err := store.Recover(t.Context(), command.Case, receipt.IdempotencyDigest); CodeOf(err) != Denied {
		t.Fatalf("tamper code=%s err=%v", CodeOf(err), err)
	}
}

func trackReceiptObjects(t *testing.T, store *RepositoryStore, command Command, intent string, receipt Receipt) {
	t.Helper()
	values := []PendingObject{
		{Role: ArtifactPublication, Case: receipt.Case, PlaintextDigest: receipt.Artifact.Digest,
			PlaintextLength: receipt.Artifact.Length, MediaType: receipt.Artifact.MediaType,
			Classification:          receipt.Artifact.Classification,
			EncryptionContextDigest: receipt.EncryptedArtifact.EncryptionContextDigest,
			LocatorDigest:           receipt.EncryptedArtifact.LocatorDigest, CreatedAt: receipt.CreatedAt},
		{Role: ManifestPublication, Case: receipt.Case, PlaintextDigest: receipt.Manifest.Digest,
			PlaintextLength: receipt.Manifest.Length, MediaType: receipt.Manifest.MediaType,
			Classification:          receipt.Manifest.Classification,
			EncryptionContextDigest: receipt.EncryptedManifest.EncryptionContextDigest,
			LocatorDigest:           receipt.EncryptedManifest.LocatorDigest, CreatedAt: receipt.CreatedAt},
	}
	for _, value := range values {
		if err := store.Track(t.Context(), command.IdempotencyKey, intent, value); err != nil {
			t.Fatal(err)
		}
	}
}
