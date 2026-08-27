package sqlite_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

type evidenceLifecycleLostResponseStore struct{ workflow.MetadataStore }

func (store evidenceLifecycleLostResponseStore) Transact(ctx context.Context,
	transaction workflow.Transaction) (workflow.CommitResult, error) {
	if _, err := store.MetadataStore.Transact(ctx, transaction); err != nil {
		return workflow.CommitResult{}, err
	}
	return workflow.CommitResult{}, workflow.NewStorageError(workflow.StorageUnavailable,
		"transact", "driver", "commit response lost", nil)
}

type evidenceLifecycleTamperStore struct {
	workflow.MetadataStore
	from []byte
	to   []byte
}

func (store evidenceLifecycleTamperStore) Get(ctx context.Context,
	key workflow.RecordKey) (workflow.MetadataRecord, error) {
	record, err := store.MetadataStore.Get(ctx, key)
	if err == nil {
		record.Canonical = bytes.ReplaceAll(append([]byte(nil), record.Canonical...), store.from, store.to)
	}
	return record, err
}

func TestEvidenceLifecycleProgressAndReceiptSurviveSQLiteRestartAndLostResponse(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	path, backup := filepath.Join(root, "coh.sqlite3"), filepath.Join(root, "backups")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := openCaseSQLite(t, path, backup, now)
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	idempotencyKey, phases, record, receipt := evidenceLifecycleSQLiteFixture(t, now)
	store, _ := evidencelifecycle.NewRepositoryStore(guarded)
	advanceEvidenceLifecyclePhases(t, store, idempotencyKey, phases[:len(phases)-1])
	lostResponse, _ := evidencelifecycle.NewRepositoryStore(
		evidenceLifecycleLostResponseStore{MetadataStore: guarded})
	committed, replayed, err := lostResponse.Commit(context.Background(), idempotencyKey,
		record.IntentDigest, phases[len(phases)-1], record, receipt)
	if err != nil || !replayed || committed.ReceiptDigest != receipt.ReceiptDigest {
		t.Fatalf("lost response commit=%+v replayed=%v err=%v", committed, replayed, err)
	}
	if err = driver.Close(); err != nil {
		t.Fatal(err)
	}

	driver = openCaseSQLite(t, path, backup, now)
	defer driver.Close()
	guarded, err = workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	restarted, _ := evidencelifecycle.NewRepositoryStore(guarded)
	recovered, found, err := restarted.Recover(context.Background(), record.Case, receipt.IdempotencyDigest)
	if err != nil || !found || recovered.ReceiptDigest != receipt.ReceiptDigest ||
		recovered.RecordDigest != record.RecordDigest {
		t.Fatalf("recovered=%+v found=%v err=%v", recovered, found, err)
	}
	progress, found, err := restarted.LoadProgress(context.Background(), record.Case, receipt.IdempotencyDigest)
	if err != nil || !found || progress.Phase != evidencelifecycle.Completed || progress.Revision != 4 ||
		progress.ProgressDigest != phases[3].ProgressDigest {
		t.Fatalf("progress=%+v found=%v err=%v", progress, found, err)
	}
	deliveries, err := guarded.ClaimOutbox(context.Background(), workflow.OutboxClaim{
		OrganizationID: record.Case.OrganizationID, TenantID: record.Case.TenantID,
		WorkerID: "evidence-lifecycle-restart", Limit: 2, LeaseUntil: now.Add(time.Minute)})
	if err != nil || len(deliveries) != 1 || deliveries[0].Message.Topic != "evidence.lifecycle.commit" ||
		deliveries[0].Message.PayloadDigest != record.RecordDigest {
		t.Fatalf("outbox=%+v err=%v", deliveries, err)
	}
}

func TestEvidenceLifecycleSQLiteConcurrentExactProgressAndCommitConverge(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := openCaseSQLite(t, filepath.Join(root, "coh.sqlite3"), backup, now)
	defer driver.Close()
	guarded, _ := workflow.GuardStorage(driver)
	store, _ := evidencelifecycle.NewRepositoryStore(guarded)
	idempotencyKey, phases, record, receipt := evidenceLifecycleSQLiteFixture(t, now)

	for _, phase := range phases[:len(phases)-1] {
		phase := phase
		concurrentEvidenceLifecycle(t, 8, func() error {
			value, _, err := store.Advance(context.Background(), idempotencyKey, record.IntentDigest, phase)
			if err == nil && value.ProgressDigest != phase.ProgressDigest {
				t.Errorf("advance progress=%+v want=%+v", value, phase)
			}
			return err
		})
	}

	type outcome struct {
		receipt evidencelifecycle.Receipt
		err     error
	}
	outcomes := make(chan outcome, 8)
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, _, err := store.Commit(context.Background(), idempotencyKey, record.IntentDigest,
				phases[len(phases)-1], record, receipt)
			outcomes <- outcome{value, err}
		}()
	}
	wait.Wait()
	close(outcomes)
	for result := range outcomes {
		if result.err != nil || result.receipt.ReceiptDigest != receipt.ReceiptDigest {
			t.Fatalf("concurrent commit=%+v err=%v", result.receipt, result.err)
		}
	}

	changed := phases[0]
	changed.IntentDigest = caseDigest("evidence-lifecycle-changed-intent")
	changed.ProgressDigest = ""
	changed.ProgressDigest, _ = evidencelifecycle.ProgressBindingDigest(changed)
	if _, _, err := store.Advance(context.Background(), idempotencyKey, changed.IntentDigest, changed); evidencelifecycle.CodeOf(err) != evidencelifecycle.Denied {
		t.Fatalf("changed replay err=%v", err)
	}
	changedRecord, changedReceipt := record, receipt
	changedRecord.PreviousProvenanceDigest = caseDigest("evidence-lifecycle-changed-provenance")
	changedRecord.ProvenanceDigest, _ = evidencelifecycle.RecordProvenanceDigest(changedRecord)
	changedRecord.RecordDigest, _ = evidencelifecycle.RecordBindingDigest(changedRecord)
	changedReceipt.RecordDigest, changedReceipt.ProvenanceDigest = changedRecord.RecordDigest, changedRecord.ProvenanceDigest
	changedReceipt.ReceiptDigest = ""
	changedReceipt.ReceiptDigest, _ = evidencelifecycle.ReceiptBindingDigest(changedReceipt)
	if _, _, err := store.Commit(context.Background(), idempotencyKey, record.IntentDigest,
		phases[len(phases)-1], changedRecord, changedReceipt); evidencelifecycle.CodeOf(err) != evidencelifecycle.Denied {
		t.Fatalf("changed result replay err=%v", err)
	}
}

func TestEvidenceLifecycleSQLiteRejectsTamperedDurableReceipt(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := openCaseSQLite(t, filepath.Join(root, "coh.sqlite3"), backup, now)
	defer driver.Close()
	guarded, _ := workflow.GuardStorage(driver)
	store, _ := evidencelifecycle.NewRepositoryStore(guarded)
	idempotencyKey, phases, record, receipt := evidenceLifecycleSQLiteFixture(t, now)
	advanceEvidenceLifecyclePhases(t, store, idempotencyKey, phases[:len(phases)-1])
	if _, _, err := store.Commit(context.Background(), idempotencyKey, record.IntentDigest,
		phases[len(phases)-1], record, receipt); err != nil {
		t.Fatal(err)
	}
	tampered, _ := evidencelifecycle.NewRepositoryStore(evidenceLifecycleTamperStore{
		MetadataStore: guarded, from: []byte(receipt.ReceiptDigest), to: []byte(caseDigest("tampered-receipt"))})
	if _, found, err := tampered.Recover(context.Background(), record.Case, receipt.IdempotencyDigest); found || evidencelifecycle.CodeOf(err) != evidencelifecycle.Denied {
		t.Fatalf("tampered receipt found=%v err=%v", found, err)
	}
}

func advanceEvidenceLifecyclePhases(t *testing.T, store evidencelifecycle.Store,
	idempotencyKey string, phases []evidencelifecycle.Progress) {
	t.Helper()
	for _, phase := range phases {
		if _, _, err := store.Advance(context.Background(), idempotencyKey, phase.IntentDigest, phase); err != nil {
			t.Fatalf("advance %s: %v", phase.Phase, err)
		}
	}
}

func concurrentEvidenceLifecycle(t *testing.T, count int, run func() error) {
	t.Helper()
	errors := make(chan error, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errors <- run()
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func evidenceLifecycleSQLiteFixture(t *testing.T, now time.Time) (string,
	[]evidencelifecycle.Progress, evidencelifecycle.Record, evidencelifecycle.Receipt) {
	t.Helper()
	idempotencyKey := "sqlite-evidence-lifecycle"
	idempotency, err := evidencelifecycle.IdempotencyBindingDigest(idempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	scope := domain.CaseRef{OrganizationID: caseUUID("evidence-lifecycle-org"),
		TenantID: caseUUID("evidence-lifecycle-tenant"), CaseID: caseUUID("evidence-lifecycle-case")}
	operationID := caseUUID("evidence-lifecycle-operation")
	commandDigest, intent := caseDigest("evidence-lifecycle-command"), caseDigest("evidence-lifecycle-intent")
	decision, revocation := caseDigest("evidence-lifecycle-decision"), caseDigest("evidence-lifecycle-revocation")
	artifactSet, lifecycleReceipt := caseDigest("evidence-lifecycle-artifact-set"), caseDigest("evidence-lifecycle-receipt")
	completionCustody := caseDigest("evidence-lifecycle-completion-custody")
	base := evidencelifecycle.Progress{SchemaVersion: evidencelifecycle.ProgressSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion, OperationID: operationID, Case: scope,
		Operation: evidencelifecycle.PlaceHold, CommandDigest: commandDigest, IntentDigest: intent,
		Artifacts: []evidencelifecycle.ArtifactProgress{}, UpdatedAt: now, Revision: 1}
	phases := []evidencelifecycle.Progress{base, base, base, base}
	phases[0].Phase = evidencelifecycle.Planned
	phases[1].Phase, phases[1].Revision, phases[1].UpdatedAt = evidencelifecycle.CaseRecorded, 2, now.Add(time.Nanosecond)
	phases[1].DecisionDigest, phases[1].RevocationDigest = &decision, &revocation
	phases[1].LifecycleReceiptDigest = &lifecycleReceipt
	phases[2] = phases[1]
	phases[2].Phase, phases[2].Revision, phases[2].UpdatedAt = evidencelifecycle.Custodied, 3, now.Add(2*time.Nanosecond)
	phases[2].CompletionCustodyReceiptDigest = &completionCustody
	phases[3] = phases[2]
	phases[3].Phase, phases[3].Revision, phases[3].UpdatedAt = evidencelifecycle.Completed, 4, now.Add(3*time.Nanosecond)
	for index := range phases {
		phases[index].ProgressDigest, err = evidencelifecycle.ProgressBindingDigest(phases[index])
		if err != nil {
			t.Fatalf("progress %d: %v", index, err)
		}
	}
	record := evidencelifecycle.Record{SchemaVersion: evidencelifecycle.RecordSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion, OperationID: operationID, Case: scope,
		Operation: evidencelifecycle.PlaceHold, CommandDigest: commandDigest, IntentDigest: intent,
		DecisionDigest: decision, RevocationDigest: revocation, Artifacts: []evidencelifecycle.EvidenceReference{},
		ArtifactSetDigest: &artifactSet, LifecycleReceiptDigest: &lifecycleReceipt,
		CompletionCustodyReceiptDigest: &completionCustody, AuditEventDigest: caseDigest("evidence-lifecycle-audit"),
		CompletedAt: phases[3].UpdatedAt, PreviousProvenanceDigest: caseDigest("evidence-lifecycle-previous")}
	record.ProvenanceDigest, err = evidencelifecycle.RecordProvenanceDigest(record)
	if err != nil {
		t.Fatal(err)
	}
	record.RecordDigest, err = evidencelifecycle.RecordBindingDigest(record)
	if err != nil {
		t.Fatal(err)
	}
	receipt := evidencelifecycle.Receipt{SchemaVersion: evidencelifecycle.ReceiptSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion, RequestID: caseUUID("evidence-lifecycle-request"),
		OperationID: operationID, Case: scope, Operation: evidencelifecycle.PlaceHold,
		IdempotencyDigest: idempotency, IntentDigest: intent, DecisionDigest: decision,
		RecordDigest: record.RecordDigest, Artifacts: []evidencelifecycle.EvidenceReference{},
		ArtifactSetDigest: &artifactSet, LifecycleReceiptDigest: &lifecycleReceipt,
		CompletionCustodyReceiptDigest: &completionCustody, AuditEventDigest: record.AuditEventDigest,
		ProvenanceDigest: record.ProvenanceDigest, CreatedAt: record.CompletedAt}
	receipt.ReceiptDigest, err = evidencelifecycle.ReceiptBindingDigest(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return idempotencyKey, phases, record, receipt
}
