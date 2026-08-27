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
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

type redactionLostResponseStore struct{ workflow.MetadataStore }

type redactionTamperStore struct {
	workflow.MetadataStore
	from []byte
	to   []byte
}

func (store redactionTamperStore) Get(ctx context.Context,
	key workflow.RecordKey) (workflow.MetadataRecord, error) {
	record, err := store.MetadataStore.Get(ctx, key)
	if err == nil {
		record.Canonical = bytes.ReplaceAll(append([]byte(nil), record.Canonical...), store.from, store.to)
	}
	return record, err
}

func (store redactionLostResponseStore) Transact(ctx context.Context,
	transaction workflow.Transaction) (workflow.CommitResult, error) {
	if _, err := store.MetadataStore.Transact(ctx, transaction); err != nil {
		return workflow.CommitResult{}, err
	}
	return workflow.CommitResult{}, workflow.NewStorageError(workflow.StorageUnavailable,
		"transact", "driver", "commit response lost", nil)
}

func TestRedactionProgressAndReceiptSurviveSQLiteRestartAndLostResponse(t *testing.T) {
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
	command, phases, record, receipt := redactionSQLiteFixture(t, now)
	store, _ := redaction.NewRepositoryStore(guarded)
	advanceRedactionPhases(t, store, command.IdempotencyKey, phases)
	lostResponseStore, _ := redaction.NewRepositoryStore(redactionLostResponseStore{MetadataStore: guarded})
	committed, replayed, err := lostResponseStore.Commit(context.Background(), command.IdempotencyKey,
		record.IntentDigest, record, receipt)
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
	restarted, _ := redaction.NewRepositoryStore(guarded)
	recovered, found, err := restarted.Recover(context.Background(), command.Case, receipt.IdempotencyDigest)
	if err != nil || !found || recovered.ReceiptDigest != receipt.ReceiptDigest || recovered.RecordDigest != record.RecordDigest {
		t.Fatalf("recovered=%+v found=%v err=%v", recovered, found, err)
	}
	resolved, found, err := restarted.ResolveReceipt(context.Background(), command.Case, receipt.ReceiptDigest)
	if err != nil || !found || resolved != recovered {
		t.Fatalf("resolved=%+v found=%v err=%v", resolved, found, err)
	}
	resolvedRecord, found, err := restarted.ResolveRecord(context.Background(), command.Case, receipt.RedactionID)
	if err != nil || !found || resolvedRecord.RecordDigest != record.RecordDigest ||
		resolvedRecord.Command.Source != record.Command.Source {
		t.Fatalf("resolved record=%+v found=%v err=%v", resolvedRecord, found, err)
	}
	progress, found, err := restarted.LoadProgress(context.Background(), command.Case, receipt.IdempotencyDigest)
	if err != nil || !found || progress.Phase != redaction.PhaseCustodied || progress.Revision != 3 ||
		progress.Custody == nil || progress.Custody.ReceiptDigest != record.CustodyReceiptDigest {
		t.Fatalf("progress=%+v found=%v err=%v", progress, found, err)
	}
	deliveries, err := guarded.ClaimOutbox(context.Background(), workflow.OutboxClaim{
		OrganizationID: command.Case.OrganizationID, TenantID: command.Case.TenantID,
		WorkerID: "redaction-restart", Limit: 2, LeaseUntil: now.Add(time.Minute)})
	if err != nil || len(deliveries) != 1 || deliveries[0].Message.Topic != "evidence.redaction.commit" ||
		deliveries[0].Message.PayloadDigest != record.RecordDigest {
		t.Fatalf("outbox=%+v err=%v", deliveries, err)
	}
}

func TestRedactionSQLiteConcurrentExactProgressAndCommitConverge(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := openCaseSQLite(t, filepath.Join(root, "coh.sqlite3"), backup, now)
	defer driver.Close()
	guarded, _ := workflow.GuardStorage(driver)
	store, _ := redaction.NewRepositoryStore(guarded)
	command, phases, record, receipt := redactionSQLiteFixture(t, now)

	concurrentAdvance(t, 8, func() error {
		progress, _, err := store.Advance(context.Background(), command.IdempotencyKey, 0, phases[0])
		if err == nil && (progress.Phase != redaction.PhasePlanned || progress.IntentDigest != phases[0].IntentDigest) {
			t.Errorf("planned progress=%+v", progress)
		}
		return err
	})
	concurrentAdvance(t, 8, func() error {
		progress, _, err := store.Advance(context.Background(), command.IdempotencyKey, 1, phases[1])
		if err == nil && (progress.Phase != redaction.PhasePublished || progress.MappingDigest == nil) {
			t.Errorf("published progress=%+v", progress)
		}
		return err
	})
	if _, _, err := store.Advance(context.Background(), command.IdempotencyKey, 2, phases[2]); err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		receipt redaction.Receipt
		err     error
	}
	outcomes := make(chan outcome, 8)
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, _, err := store.Commit(context.Background(), command.IdempotencyKey,
				record.IntentDigest, record, receipt)
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
	changed.IntentDigest = caseDigest("redaction-changed-intent")
	if _, _, err := store.Advance(context.Background(), command.IdempotencyKey, 0, changed); redaction.CodeOf(err) != redaction.Denied {
		t.Fatalf("changed replay err=%v", err)
	}
}

func TestRedactionSQLiteRejectsTamperedMappingInDurableReceipt(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := openCaseSQLite(t, filepath.Join(root, "coh.sqlite3"), backup, now)
	defer driver.Close()
	guarded, _ := workflow.GuardStorage(driver)
	store, _ := redaction.NewRepositoryStore(guarded)
	command, phases, record, receipt := redactionSQLiteFixture(t, now)
	advanceRedactionPhases(t, store, command.IdempotencyKey, phases)
	if _, _, err := store.Commit(context.Background(), command.IdempotencyKey,
		record.IntentDigest, record, receipt); err != nil {
		t.Fatal(err)
	}
	tampered, _ := redaction.NewRepositoryStore(redactionTamperStore{MetadataStore: guarded,
		from: []byte(receipt.MappingDigest), to: []byte(caseDigest("redaction-mapping-tampered"))})
	if _, found, err := tampered.Recover(context.Background(), command.Case, receipt.IdempotencyDigest); found || redaction.CodeOf(err) != redaction.Denied {
		t.Fatalf("tampered mapping found=%v err=%v", found, err)
	}
}

func concurrentAdvance(t *testing.T, count int, run func() error) {
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

func advanceRedactionPhases(t *testing.T, store redaction.Store, idempotencyKey string,
	phases []redaction.Progress) {
	t.Helper()
	for index, phase := range phases {
		if _, _, err := store.Advance(context.Background(), idempotencyKey, uint64(index), phase); err != nil {
			t.Fatalf("advance %s: %v", phase.Phase, err)
		}
	}
}

func redactionSQLiteFixture(t *testing.T, now time.Time) (redaction.Command, []redaction.Progress,
	redaction.Record, redaction.Receipt) {
	t.Helper()
	scope := domain.CaseRef{OrganizationID: caseUUID("redaction-org"), TenantID: caseUUID("redaction-tenant"),
		CaseID: caseUUID("redaction-case")}
	source := redactionEvidence("redaction-source", "text/plain", "restricted", 100)
	derived := redactionEvidence("redaction-derived", "text/plain", "confidential", 80)
	mapping := redactionEvidence("redaction-mapping", "application/vnd.coh.redaction-mapping+json", "restricted", 512)
	command := redaction.Command{SchemaVersion: redaction.CommandSchemaVersion, ContractVersion: redaction.ContractVersion,
		RequestID: caseUUID("redaction-request"), IdempotencyKey: "sqlite-redaction", Case: scope,
		ActorID: caseUUID("redaction-actor"), ActorRevision: 2, Source: source,
		RuleDigest: caseDigest("redaction-rule"), PlanDigest: caseDigest("redaction-plan"),
		ReasonDigest: caseDigest("redaction-reason"), OutputMediaType: "text/plain",
		OutputClassification: "confidential", KeyProfile: "case-evidence",
		KeyProfileDigest: caseDigest("redaction-key-profile"), PolicyDigest: caseDigest("redaction-policy"),
		ExpectedCaseRevision: 3, ExpectedCustodyHead: redaction.CustodyHead{Case: scope,
			ChainHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		Deadline: now.Add(time.Hour)}
	intent, err := redaction.IntentBindingDigest(command)
	if err != nil {
		t.Fatal(err)
	}
	idempotency, err := redaction.IdempotencyBindingDigest(command.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	decision, approval, mappingDigest := caseDigest("redaction-decision"),
		caseDigest("redaction-approval-use"), caseDigest("redaction-mapping-digest")
	publishedDerived := redaction.PublishedEvidence{Reference: derived, ReceiptDigest: derived.IngestionReceiptDigest}
	publishedMapping := redaction.PublishedEvidence{Reference: mapping, ReceiptDigest: mapping.IngestionReceiptDigest}
	custodyProof := redaction.CustodyProof{ReceiptDigest: caseDigest("redaction-custody-receipt"),
		RecordDigest: caseDigest("redaction-custody-record"), ChainHash: caseDigest("redaction-custody-chain"),
		Sequence: 1, AuditDigest: caseDigest("redaction-custody-audit")}
	phases := []redaction.Progress{
		{Case: scope, IdempotencyDigest: idempotency, IntentDigest: intent, Phase: redaction.PhasePlanned,
			Revision: 1, PlanDigest: command.PlanDigest, DecisionDigest: decision, ApprovalUseDigest: approval, UpdatedAt: now},
		{Case: scope, IdempotencyDigest: idempotency, IntentDigest: intent, Phase: redaction.PhasePublished,
			Revision: 2, PlanDigest: command.PlanDigest, DecisionDigest: decision, ApprovalUseDigest: approval,
			Derived: &publishedDerived, Mapping: &publishedMapping, MappingDigest: &mappingDigest, UpdatedAt: now.Add(time.Nanosecond)},
		{Case: scope, IdempotencyDigest: idempotency, IntentDigest: intent, Phase: redaction.PhaseCustodied,
			Revision: 3, PlanDigest: command.PlanDigest, DecisionDigest: decision, ApprovalUseDigest: approval,
			Derived: &publishedDerived, Mapping: &publishedMapping, MappingDigest: &mappingDigest,
			Custody: &custodyProof, UpdatedAt: now.Add(2 * time.Nanosecond)},
	}
	record := redaction.Record{SchemaVersion: redaction.RecordSchemaVersion, ContractVersion: redaction.ContractVersion,
		RedactionID: caseUUID("redaction-record"), Case: scope, Command: command, IntentDigest: intent,
		PlanDigest: command.PlanDigest, DecisionDigest: decision, RevocationDigest: caseDigest("redaction-revocation"),
		ApprovalUseDigest: approval, SourceVerificationDigest: caseDigest("redaction-source-verification"),
		Derived: derived, DerivedIngestionReceiptDigest: derived.IngestionReceiptDigest, MappingReference: mapping,
		MappingDigest: mappingDigest, MappingIngestionReceiptDigest: mapping.IngestionReceiptDigest,
		CustodyReceiptDigest: custodyProof.ReceiptDigest, CreatedAt: phases[2].UpdatedAt,
		PreviousProvenanceDigest: source.ManifestProvenanceDigest}
	record.ProvenanceDigest, err = redaction.RecordProvenanceDigest(record)
	if err != nil {
		t.Fatal(err)
	}
	record.AuditEventDigest = caseDigest("redaction-audit")
	record.RecordDigest, err = redaction.RecordBindingDigest(record)
	if err != nil || redaction.ValidateRecord(record) != nil {
		t.Fatalf("record fixture: %v", err)
	}
	receipt := redaction.Receipt{SchemaVersion: redaction.ReceiptSchemaVersion, ContractVersion: redaction.ContractVersion,
		RequestID: command.RequestID, Case: scope, IdempotencyDigest: idempotency, IntentDigest: intent,
		RedactionID: record.RedactionID, RecordDigest: record.RecordDigest, Derived: derived,
		MappingReference: mapping, MappingDigest: mappingDigest, CustodyReceiptDigest: record.CustodyReceiptDigest,
		AuditEventDigest: record.AuditEventDigest, ProvenanceDigest: record.ProvenanceDigest, CreatedAt: record.CreatedAt}
	receipt.ReceiptDigest, err = redaction.ReceiptBindingDigest(receipt)
	if err != nil || redaction.ValidateReceipt(receipt) != nil {
		t.Fatalf("receipt fixture: %v", err)
	}
	return command, phases, record, receipt
}

func redactionEvidence(seed, mediaType, classification string, length int64) redaction.EvidenceReference {
	return redaction.EvidenceReference{
		Artifact: domain.ArtifactRef{Digest: caseDigest(seed + "-artifact"), MediaType: mediaType,
			Classification: classification, Length: length},
		Manifest: domain.ArtifactRef{Digest: caseDigest(seed + "-manifest"),
			MediaType: "application/vnd.coh.artifact-manifest+json", Classification: classification, Length: 256},
		ManifestProvenanceDigest: caseDigest(seed + "-provenance"),
		IngestionReceiptDigest:   caseDigest(seed + "-receipt"),
	}
}
