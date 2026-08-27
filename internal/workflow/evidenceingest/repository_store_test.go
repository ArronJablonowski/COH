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
	mutation := transaction.Mutations[0]
	if _, found := memory.records[mutation.Key]; found {
		return workflowbase.CommitResult{}, workflowbase.NewStorageError(workflowbase.StorageConflict,
			"transact", "revision", "already exists", nil)
	}
	memory.records[mutation.Key] = *mutation.Record
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
	stored, replayed, err := store.Commit(t.Context(), command.IdempotencyKey, authorization.IntentDigest, receipt)
	if err != nil || replayed || stored.ReceiptDigest != receipt.ReceiptDigest || len(memory.records) != 1 {
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
