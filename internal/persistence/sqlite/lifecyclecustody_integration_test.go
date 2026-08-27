package sqlite_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/persistence/sqlite"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/auditlog"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow/lifecyclecustody"
)

type lifecycleCustodyEvidence struct {
	verified map[custody.EvidenceReference]custody.VerifiedEvidence
}

func (resolver lifecycleCustodyEvidence) ResolveEvidence(_ context.Context, _ domain.CaseRef,
	reference custody.EvidenceReference) (custody.VerifiedEvidence, error) {
	verified, found := resolver.verified[reference]
	if !found {
		return custody.VerifiedEvidence{}, errors.New("evidence not found")
	}
	return verified, nil
}

type lifecycleCustodyCheckpoint struct {
	scope domain.CaseRef
	proof auditlog.CheckpointProof
}

func (resolver lifecycleCustodyCheckpoint) ResolveCheckpointProof(_ context.Context,
	organizationID, tenantID, checkpointID, checkpointDigest string,
	minimumSequence uint64) (auditlog.CheckpointProof, error) {
	if organizationID != resolver.scope.OrganizationID || tenantID != resolver.scope.TenantID ||
		checkpointID != resolver.proof.CheckpointID || checkpointDigest != resolver.proof.CheckpointDigest ||
		resolver.proof.Sequence < minimumSequence {
		return auditlog.CheckpointProof{}, errors.New("checkpoint proof mismatch")
	}
	return resolver.proof, nil
}

type lifecycleCustodyFailOnceStore struct {
	workflow.MetadataStore
	failed bool
}

type lifecycleCustodyTamperStore struct {
	workflow.MetadataStore
	from []byte
	to   []byte
}

func (store lifecycleCustodyTamperStore) Get(ctx context.Context,
	key workflow.RecordKey) (workflow.MetadataRecord, error) {
	record, err := store.MetadataStore.Get(ctx, key)
	if err == nil {
		record.Canonical = bytes.Replace(record.Canonical, store.from, store.to, 1)
	}
	return record, err
}

func (store *lifecycleCustodyFailOnceStore) Transact(ctx context.Context,
	transaction workflow.Transaction) (workflow.CommitResult, error) {
	if !store.failed {
		store.failed = true
		return workflow.CommitResult{}, workflow.NewStorageError(workflow.StorageUnavailable,
			"transact", "test", "injected lifecycle set failure", nil)
	}
	return store.MetadataStore.Transact(ctx, transaction)
}

func TestLifecycleCustodyRecoversOrderedSetAcrossFailureAndSQLiteRestart(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	path, backup := filepath.Join(root, "coh.sqlite3"), filepath.Join(root, "backups")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	command, current, first := custodySQLiteFixture(now)
	second := secondLifecycleCustodyEvidence(first)
	evidence := lifecycleCustodyEvidence{verified: map[custody.EvidenceReference]custody.VerifiedEvidence{
		first.Reference: first, second.Reference: second,
	}}
	auditor := &custodySQLiteAuditor{proofs: make(map[string]custody.AuditProof)}
	checkpointID, checkpointDigest := caseUUID("lifecycle-custody-checkpoint"), caseDigest("lifecycle-custody-checkpoint")
	checkpoint := lifecycleCustodyCheckpoint{scope: command.Case, proof: auditlog.CheckpointProof{
		CheckpointID: checkpointID, CheckpointDigest: checkpointDigest, Sequence: 20,
		SigningKeyRevision: 4, ProofDigest: caseDigest("lifecycle-custody-checkpoint-proof"),
	}}

	driver := openCaseSQLite(t, path, backup, now)
	controller, ledger, verifier, guarded := composeLifecycleCustodySQLite(t, driver, now, current, evidence, auditor)
	failing := &lifecycleCustodyFailOnceStore{MetadataStore: guarded}
	adapter, err := lifecyclecustody.New(controller, ledger, verifier, checkpoint, failing)
	if err != nil {
		t.Fatal(err)
	}
	request := lifecycleCustodyRequest(command, first.Reference, second.Reference)
	if _, err = adapter.RecordLifecycle(context.Background(), request); err == nil ||
		evidencelifecycle.CodeOf(err) != evidencelifecycle.Unavailable {
		t.Fatalf("first record error=%v", err)
	}
	if records, readErr := ledger.Read(context.Background(), command.Case, 0, 3); readErr != nil || len(records) != 2 {
		t.Fatalf("records after interrupted set commit=%+v err=%v", records, readErr)
	}

	created, err := adapter.RecordLifecycle(context.Background(), request)
	if err != nil || len(created.Proofs) != 2 || created.Proofs[0].Head.Sequence != 1 ||
		created.Proofs[1].Head.Sequence != 2 || created.Head.Sequence != 2 {
		t.Fatalf("recovered set=%+v err=%v", created, err)
	}
	replayed, err := adapter.RecordLifecycle(context.Background(), request)
	if err != nil || replayed.ReceiptSetDigest != created.ReceiptSetDigest ||
		replayed.Proofs[0].ReceiptDigest != created.Proofs[0].ReceiptDigest ||
		replayed.Proofs[1].ReceiptDigest != created.Proofs[1].ReceiptDigest {
		t.Fatalf("replayed set=%+v err=%v", replayed, err)
	}
	if records, readErr := ledger.Read(context.Background(), command.Case, 0, 4); readErr != nil || len(records) != 2 {
		t.Fatalf("records after replay=%+v err=%v", records, readErr)
	}
	tampered, err := lifecyclecustody.New(controller, ledger, verifier, checkpoint,
		lifecycleCustodyTamperStore{MetadataStore: guarded, from: []byte(created.ReceiptSetDigest),
			to: []byte(caseDigest("substituted-lifecycle-custody-set"))})
	if err != nil {
		t.Fatal(err)
	}
	if _, found, recoverErr := tampered.RecoverLifecycle(context.Background(), command.Case,
		created.ReceiptSetDigest); recoverErr == nil || found ||
		evidencelifecycle.CodeOf(recoverErr) != evidencelifecycle.Denied {
		t.Fatalf("tampered recovery found=%v err=%v", found, recoverErr)
	}
	if err = driver.Close(); err != nil {
		t.Fatal(err)
	}

	driver = openCaseSQLite(t, path, backup, now)
	defer driver.Close()
	controller, ledger, verifier, guarded = composeLifecycleCustodySQLite(t, driver, now, current, evidence, auditor)
	restarted, err := lifecyclecustody.New(controller, ledger, verifier, checkpoint, guarded)
	if err != nil {
		t.Fatal(err)
	}
	recovered, found, err := restarted.RecoverLifecycle(context.Background(), command.Case, created.ReceiptSetDigest)
	if err != nil || !found || recovered.ReceiptSetDigest != created.ReceiptSetDigest ||
		len(recovered.Proofs) != 2 || recovered.Proofs[1].ReceiptDigest != created.Proofs[1].ReceiptDigest {
		t.Fatalf("restart recovery=%+v found=%v err=%v", recovered, found, err)
	}

	advance := lifecycleCustodyRequest(command, first.Reference)
	advance.ExpectedHead = recovered.Head
	advance.ActorRevision++
	advanced, err := restarted.RecordLifecycle(context.Background(), advance)
	if err != nil || advanced.Head.Sequence != 3 {
		t.Fatalf("advanced set=%+v err=%v", advanced, err)
	}
	markLifecycleCustodyCheckpoint(t, auditor, ledger, command.Case, 2, checkpointID, checkpointDigest)
	verification, err := restarted.VerifyLifecycle(context.Background(), command.Case, 1, 2)
	if err != nil || verification.ToSequence != 2 || verification.Head.Sequence != 2 ||
		verification.Head.ChainHash != recovered.Head.ChainHash || verification.CheckpointID != checkpointID ||
		verification.CheckpointDigest != checkpointDigest || verification.CheckpointSequence != checkpoint.proof.Sequence ||
		verification.CheckpointProofDigest != checkpoint.proof.ProofDigest {
		t.Fatalf("historical verification=%+v err=%v", verification, err)
	}
}

func TestLifecycleCustodyRejectsDuplicateAndSubstitutedRequests(t *testing.T) {
	command, _, verified := custodySQLiteFixture(time.Now().UTC().Add(time.Hour).Truncate(time.Second))
	request := lifecycleCustodyRequest(command, verified.Reference, verified.Reference)
	adapter, err := lifecyclecustody.New(lifecycleCustodyControllerStub{}, lifecycleCustodyLedgerStub{},
		lifecycleCustodyVerifierStub{}, lifecycleCustodyCheckpoint{}, lifecycleCustodyMetadataStub{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = adapter.RecordLifecycle(context.Background(), request); err == nil ||
		evidencelifecycle.CodeOf(err) != evidencelifecycle.InvalidInput {
		t.Fatalf("duplicate subjects error=%v", err)
	}
	request.Subjects = request.Subjects[:1]
	lastRecordAt := command.Deadline.Add(-time.Minute)
	request.ExpectedHead.Sequence = 1
	request.ExpectedHead.ChainHash = caseDigest("substituted-head")
	request.ExpectedHead.LastRecordAt = &lastRecordAt
	if _, err = adapter.RecordLifecycle(context.Background(), request); err == nil ||
		evidencelifecycle.CodeOf(err) != evidencelifecycle.Conflict {
		t.Fatalf("substituted expected head error=%v", err)
	}
}

func TestLifecycleCustodyBindsOrderedExportAuthorizationAncestry(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	command, current, first := custodySQLiteFixture(now)
	second := secondLifecycleCustodyEvidence(first)
	evidence := lifecycleCustodyEvidence{verified: map[custody.EvidenceReference]custody.VerifiedEvidence{
		first.Reference: first, second.Reference: second,
	}}
	auditor := &custodySQLiteAuditor{proofs: make(map[string]custody.AuditProof)}
	checkpointID, checkpointDigest := caseUUID("lifecycle-export-checkpoint"), caseDigest("lifecycle-export-checkpoint")
	checkpoint := lifecycleCustodyCheckpoint{scope: command.Case, proof: auditlog.CheckpointProof{
		CheckpointID: checkpointID, CheckpointDigest: checkpointDigest, Sequence: 30,
		SigningKeyRevision: 5, ProofDigest: caseDigest("lifecycle-export-checkpoint-proof"),
	}}
	driver := openCaseSQLite(t, filepath.Join(root, "coh.sqlite3"), backup, now)
	defer driver.Close()
	controller, ledger, verifier, guarded := composeLifecycleCustodySQLite(t, driver, now, current, evidence, auditor)
	adapter, err := lifecyclecustody.New(controller, ledger, verifier, checkpoint, guarded)
	if err != nil {
		t.Fatal(err)
	}

	purpose, destination := caseDigest("lifecycle-export-purpose"), caseDigest("lifecycle-export-destination")
	authorizedRequest := lifecycleCustodyRequest(command, first.Reference, second.Reference)
	authorizedRequest.Operation, authorizedRequest.Phase = evidencelifecycle.Export, evidencelifecycle.Authorized
	authorizedRequest.SourceDigest = nil
	authorizedRequest.PurposeDigest, authorizedRequest.DestinationDigest = &purpose, &destination
	authorized, err := adapter.RecordLifecycle(context.Background(), authorizedRequest)
	if err != nil || len(authorized.Proofs) != 2 || authorized.Head.Sequence != 2 {
		t.Fatalf("authorized set=%+v err=%v", authorized, err)
	}

	packageDigest := caseDigest("lifecycle-export-package")
	completedRequest := authorizedRequest
	completedRequest.Phase = evidencelifecycle.Completed
	completedRequest.PackageDigest = &packageDigest
	completedRequest.PriorAuthorizationDigest = &authorized.ReceiptSetDigest
	completedRequest.ExpectedHead = authorized.Head
	completed, err := adapter.RecordLifecycle(context.Background(), completedRequest)
	if err != nil || len(completed.Proofs) != 2 || completed.Proofs[0].Head.Sequence != 3 ||
		completed.Proofs[1].Head.Sequence != 4 || completed.Head.Sequence != 4 {
		t.Fatalf("completed set=%+v err=%v", completed, err)
	}
	records, err := ledger.Read(context.Background(), command.Case, 0, 5)
	if err != nil || len(records) != 4 || records[2].Command.PriorAuthorizationDigest == nil ||
		records[3].Command.PriorAuthorizationDigest == nil ||
		*records[2].Command.PriorAuthorizationDigest != authorized.Proofs[0].ReceiptDigest ||
		*records[3].Command.PriorAuthorizationDigest != authorized.Proofs[1].ReceiptDigest {
		t.Fatalf("export ancestry records=%+v err=%v", records, err)
	}
	markLifecycleCustodyCheckpoint(t, auditor, ledger, command.Case, 4, checkpointID, checkpointDigest)
	verified, err := adapter.VerifyLifecycle(context.Background(), command.Case, 1, 4)
	if err != nil || verified.ToSequence != 4 || verified.Head.ChainHash != completed.Head.ChainHash ||
		verified.CheckpointProofDigest != checkpoint.proof.ProofDigest {
		t.Fatalf("export verification=%+v err=%v", verified, err)
	}
}

func composeLifecycleCustodySQLite(t *testing.T, driver *sqlite.Store, now time.Time,
	current custody.CaseSnapshot, evidence lifecycleCustodyEvidence, auditor *custodySQLiteAuditor) (
	*custody.Controller, *custody.RepositoryStore, *custody.Verifier, workflow.Repository) {
	t.Helper()
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := custody.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := custody.New(custodySQLiteAuthority{now: now}, custodySQLiteCases{current: current},
		evidence, ledger, auditor, custodySQLiteClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := custody.NewVerifier(ledger, evidence, auditor, custodySQLiteClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	return controller, ledger, verifier, guarded
}

func lifecycleCustodyRequest(command custody.Command,
	references ...custody.EvidenceReference) evidencelifecycle.CustodyRequest {
	subjects := make([]evidencelifecycle.EvidenceReference, len(references))
	for index, reference := range references {
		subjects[index] = evidencelifecycle.EvidenceReference{Artifact: reference.Artifact,
			Manifest: reference.Manifest, ManifestProvenanceDigest: reference.ManifestProvenanceDigest,
			IngestionReceiptDigest: reference.IngestionReceiptDigest}
	}
	return evidencelifecycle.CustodyRequest{Operation: evidencelifecycle.Import,
		Phase: evidencelifecycle.Completed, Case: command.Case, ActorID: command.ActorID,
		ActorRevision: command.ActorRevision, ArtifactSetDigest: caseDigest("lifecycle-custody-artifact-set"),
		Subjects: subjects, SourceDigest: command.SourceIdentityDigest, PolicyDigest: command.PolicyDigest,
		ExpectedCaseRevision: command.ExpectedCaseRevision,
		ExpectedHead:         evidencelifecycle.CustodyHead{Case: command.Case, ChainHash: custody.GenesisHash},
		Deadline:             command.Deadline}
}

func secondLifecycleCustodyEvidence(first custody.VerifiedEvidence) custody.VerifiedEvidence {
	second := first
	second.Reference.Artifact.Digest = caseDigest("lifecycle-custody-second-artifact")
	second.Reference.Manifest.Digest = caseDigest("lifecycle-custody-second-manifest")
	second.Reference.ManifestProvenanceDigest = caseDigest("lifecycle-custody-second-provenance")
	second.Reference.IngestionReceiptDigest = caseDigest("lifecycle-custody-second-ingestion")
	second.VerificationDigest = caseDigest("lifecycle-custody-second-verified")
	return second
}

func markLifecycleCustodyCheckpoint(t *testing.T, auditor *custodySQLiteAuditor,
	ledger *custody.RepositoryStore, scope domain.CaseRef, sequence uint64, checkpointID, checkpointDigest string) {
	t.Helper()
	records, err := ledger.Read(context.Background(), scope, sequence-1, 1)
	if err != nil || len(records) != 1 {
		t.Fatalf("checkpoint record=%+v err=%v", records, err)
	}
	auditor.mu.Lock()
	defer auditor.mu.Unlock()
	proof, found := auditor.proofs[records[0].AuditEventDigest]
	if !found {
		t.Fatal("checkpoint audit proof not found")
	}
	proof.CheckpointID, proof.CheckpointDigest = &checkpointID, &checkpointDigest
	auditor.proofs[records[0].AuditEventDigest] = proof
}

type lifecycleCustodyControllerStub struct{}

func (lifecycleCustodyControllerStub) Execute(context.Context, custody.Command) (custody.Result, error) {
	return custody.Result{}, errors.New("unexpected execute")
}
func (lifecycleCustodyControllerStub) VerifyReceipt(context.Context, custody.Command, custody.Receipt) error {
	return errors.New("unexpected verify")
}

type lifecycleCustodyLedgerStub struct{}

func (lifecycleCustodyLedgerStub) LoadHead(_ context.Context, scope domain.CaseRef) (custody.Head, error) {
	return custody.Head{Case: scope, ChainHash: custody.GenesisHash}, nil
}
func (lifecycleCustodyLedgerStub) Recover(context.Context, domain.CaseRef, string) (custody.Receipt, bool, error) {
	return custody.Receipt{}, false, nil
}
func (lifecycleCustodyLedgerStub) ResolveReceipt(context.Context, domain.CaseRef, string) (custody.Receipt, bool, error) {
	return custody.Receipt{}, false, nil
}
func (lifecycleCustodyLedgerStub) Read(context.Context, domain.CaseRef, uint64, uint16) ([]custody.Record, error) {
	return nil, nil
}

type lifecycleCustodyVerifierStub struct{}

func (lifecycleCustodyVerifierStub) VerifyInterval(context.Context, domain.CaseRef,
	uint64, uint64) (custody.VerificationReport, error) {
	return custody.VerificationReport{}, errors.New("unexpected verify")
}

type lifecycleCustodyMetadataStub struct{}

func (lifecycleCustodyMetadataStub) Get(context.Context, workflow.RecordKey) (workflow.MetadataRecord, error) {
	return workflow.MetadataRecord{}, workflow.NewStorageError(workflow.StorageNotFound,
		"get", "test", "not found", nil)
}
func (lifecycleCustodyMetadataStub) Transact(context.Context,
	workflow.Transaction) (workflow.CommitResult, error) {
	return workflow.CommitResult{}, errors.New("unexpected transact")
}
