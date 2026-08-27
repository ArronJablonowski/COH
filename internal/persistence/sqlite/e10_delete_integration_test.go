package sqlite_test

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/persistence/encryptedcas"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/auditlog"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
	"github.com/ArronJablonowski/COH/internal/workflow/custodycase"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencecatalog"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow/lifecyclecase"
	"github.com/ArronJablonowski/COH/internal/workflow/lifecyclecustody"
	"github.com/ArronJablonowski/COH/internal/workflow/lifecycledisposition"
)

func TestCOHE10GovernedDeletionOrdersTombstoneDispositionCustodyAndRecovery(t *testing.T) {
	ingestNow := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	deleteNow := ingestNow.Add(48 * time.Hour)
	root := t.TempDir()
	databasePath, backupPath := filepath.Join(root, "coh.sqlite3"), filepath.Join(root, "backups")
	casRoot := filepath.Join(root, "encrypted-cas")
	for _, directory := range []string{backupPath, casRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	driver := openCaseSQLite(t, databasePath, backupPath, ingestNow)
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	caseController, caseRepository := composeCaseController(t, driver, ingestNow, &caseAuditor{})
	create := caseCreateCommand(ingestNow)
	if _, err = caseController.Execute(t.Context(), create); err != nil {
		t.Fatal(err)
	}

	wrappingKey := sha256.Sum256([]byte("coh-e10-delete-wrapping-key"))
	ingestion, _ := composeEvidenceController(t, driver, caseRepository, casRoot, wrappingKey[:], ingestNow)
	payload := []byte("COH-E10 evidence governed for exact encrypted deletion\n")
	ingestCommand := evidenceCommand(create, payload, ingestNow)
	ingested, err := ingestion.Execute(t.Context(), ingestCommand, &evidenceSource{value: payload})
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := evidenceingest.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	nativeCAS := openEvidenceCAS(t, casRoot, wrappingKey[:], deleteNow)
	catalog, err := evidencecatalog.New(guarded, receipts, nativeCAS)
	if err != nil {
		t.Fatal(err)
	}
	entry := evidencelifecycle.ManifestArtifact{Ordinal: 1, Role: evidencelifecycle.SourceArtifact,
		Reference: evidencelifecycle.EvidenceReference{Artifact: ingested.Artifact, Manifest: ingested.Manifest,
			ManifestProvenanceDigest: ingested.Receipt.ManifestProvenanceDigest,
			IngestionReceiptDigest:   ingested.Receipt.ReceiptDigest},
		ParentArtifactDigests: []string{}, ParentManifestDigests: []string{}}
	evidenceSet, replayed, err := catalog.Register(t.Context(), evidencecatalog.Registration{
		Case: create.Case, Artifacts: []evidencelifecycle.ManifestArtifact{entry}})
	if err != nil || replayed {
		t.Fatalf("catalog registration replayed=%v err=%v", replayed, err)
	}

	deleteController, deleteRepository := composeCaseController(t, driver, deleteNow, &caseAuditor{})
	lifecycleCases := composeLifecycleCaseAdapter(t, driver, deleteController, deleteRepository)
	custodyCases, err := custodycase.New(deleteRepository)
	if err != nil {
		t.Fatal(err)
	}
	custodyReference := toCustodyReference(entry.Reference)
	custodyEvidence := lifecycleCustodyEvidence{verified: map[custody.EvidenceReference]custody.VerifiedEvidence{
		custodyReference: {Reference: custodyReference, SourceIdentityDigest: ingestCommand.Source.IdentityDigest,
			VerificationDigest: caseDigest("e10-delete-custody-evidence")},
	}}
	checkpointID, checkpointDigest := caseUUID("e10-delete-checkpoint"), caseDigest("e10-delete-checkpoint")
	custodyAuditor := &custodySQLiteAuditor{proofs: make(map[string]custody.AuditProof),
		checkpointID: &checkpointID, checkpointDigest: &checkpointDigest}
	ledger, err := custody.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	custodyController, err := custody.New(custodySQLiteAuthority{now: deleteNow}, custodyCases,
		custodyEvidence, ledger, custodyAuditor, custodySQLiteClock{now: deleteNow})
	if err != nil {
		t.Fatal(err)
	}
	custodyVerifier, err := custody.NewVerifier(ledger, custodyEvidence, custodyAuditor,
		custodySQLiteClock{now: deleteNow})
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := lifecycleCustodyCheckpoint{scope: create.Case, proof: auditlog.CheckpointProof{
		CheckpointID: checkpointID, CheckpointDigest: checkpointDigest, Sequence: 100,
		SigningKeyRevision: 3, ProofDigest: caseDigest("e10-delete-checkpoint-proof")}}
	baseCustody, err := lifecyclecustody.New(custodyController, ledger, custodyVerifier, checkpoint, guarded)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := baseCustody.RecordLifecycle(t.Context(), evidencelifecycle.CustodyRequest{
		Operation: evidencelifecycle.Import, Phase: evidencelifecycle.Completed, Case: create.Case,
		ActorID: create.ActorID, ActorRevision: create.ActorRevision,
		ArtifactSetDigest: evidenceSet.ArtifactSetDigest, Subjects: []evidencelifecycle.EvidenceReference{entry.Reference},
		SourceDigest: &ingestCommand.Source.IdentityDigest, PolicyDigest: ingestCommand.PolicyDigest,
		ExpectedCaseRevision: 1, ExpectedHead: evidencelifecycle.CustodyHead{
			Case: create.Case, ChainHash: custody.GenesisHash}, Deadline: deleteNow.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	disposer, err := lifecycledisposition.New(receipts, nativeCAS, guarded, evidenceClock{now: deleteNow})
	if err != nil {
		t.Fatal(err)
	}
	lifecycleStore, err := evidencelifecycle.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	order := make([]string, 0, 5)
	trackedCustody := &e10DeleteCustody{Custody: baseCustody, order: &order}
	trackedLifecycle := &e10DeleteCaseLifecycle{CaseLifecycle: lifecycleCases, order: &order}
	trackedDisposer := &e10DeleteDisposer{Disposer: disposer, order: &order}
	trackedStore := &e10DeleteStore{Store: lifecycleStore, order: &order}
	auditor := &e10LifecycleAuditor{}
	service, err := evidencelifecycle.NewDeleteService(e10LifecycleAuthority{now: deleteNow}, lifecycleCases,
		trackedLifecycle, catalog, trackedCustody, trackedDisposer, trackedStore, auditor,
		evidenceClock{now: deleteNow})
	if err != nil {
		t.Fatal(err)
	}
	reason, approval := caseDigest("e10-delete-reason"), caseDigest("e10-delete-approval")
	command := evidencelifecycle.Command{SchemaVersion: evidencelifecycle.CommandSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion, RequestID: caseUUID("e10-delete-request"),
		IdempotencyKey: "coh-e10-governed-delete", Operation: evidencelifecycle.Delete, Case: create.Case,
		ActorID: create.ActorID, ActorRevision: create.ActorRevision,
		ArtifactSetDigest: &evidenceSet.ArtifactSetDigest, ReasonDigest: &reason, ApprovalDigest: &approval,
		PolicyDigest: caseDigest("e10-delete-policy"), ExpectedCaseRevision: 1,
		ExpectedCustodyHead: initial.Head, Limits: evidencelifecycle.PackageLimits{
			MaximumManifestBytes: 1 << 20, MaximumSignatureBytes: 1 << 12, MaximumArtifacts: 8,
			MaximumArtifactBytes: 1 << 20, MaximumPackageBytes: 2 << 20}, Deadline: deleteNow.Add(time.Hour)}
	result, err := service.Execute(t.Context(), command)
	if err != nil || result.Replayed {
		t.Fatalf("delete=%+v err=%v", result, err)
	}
	wantOrder := []string{"custody.authorized", "case.tombstone", "disposition", "custody.completed", "commit"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("governed deletion order=%v want=%v", order, wantOrder)
	}
	assertE10DeleteResult(t, result, create.Case, ingested, evidenceSet, lifecycleCases, disposer,
		baseCustody, receipts, catalog, nativeCAS)

	order = order[:0]
	replayedResult, err := service.Execute(t.Context(), command)
	if err != nil || !replayedResult.Replayed || replayedResult.Receipt.ReceiptDigest != result.Receipt.ReceiptDigest {
		t.Fatalf("delete replay=%+v err=%v", replayedResult, err)
	}
	if len(order) != 0 {
		t.Fatalf("completed replay repeated mutation steps: %v", order)
	}
	if err = driver.Close(); err != nil {
		t.Fatal(err)
	}

	driver = openCaseSQLite(t, databasePath, backupPath, deleteNow)
	defer driver.Close()
	guarded, err = workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	receipts, _ = evidenceingest.NewRepositoryStore(guarded)
	nativeCAS = openEvidenceCAS(t, casRoot, wrappingKey[:], deleteNow)
	restartedDisposer, _ := lifecycledisposition.New(receipts, nativeCAS, guarded, evidenceClock{now: deleteNow})
	restartedStore, _ := evidencelifecycle.NewRepositoryStore(guarded)
	_, restartedRepository := composeCaseController(t, driver, deleteNow, &caseAuditor{})
	caseRecord, found, err := restartedRepository.Load(t.Context(), create.Case)
	if err != nil || !found || caseRecord.State != "deleted" || caseRecord.Revision != 2 {
		t.Fatalf("restarted case=%+v found=%v err=%v", caseRecord, found, err)
	}
	idempotency, _ := evidencelifecycle.IdempotencyBindingDigest(command.IdempotencyKey)
	recovered, found, err := restartedStore.Recover(t.Context(), create.Case, idempotency)
	if err != nil || !found || recovered.ReceiptDigest != result.Receipt.ReceiptDigest {
		t.Fatalf("restarted delete receipt=%+v found=%v err=%v", recovered, found, err)
	}
	attestation, found, err := restartedDisposer.RecoverDisposition(t.Context(), create.Case,
		*result.Receipt.DispositionAttestationDigest)
	if err != nil || !found || attestation.AttestationDigest != *result.Receipt.DispositionAttestationDigest {
		t.Fatalf("restarted disposition=%+v found=%v err=%v", attestation, found, err)
	}
}

func assertE10DeleteResult(t *testing.T, result evidencelifecycle.Result, scope domain.CaseRef,
	ingested evidenceingest.Result, evidenceSet evidencelifecycle.VerifiedEvidenceSet,
	cases *lifecyclecase.Adapter, disposer *lifecycledisposition.Adapter, lifecycleCustody *lifecyclecustody.Adapter,
	receipts *evidenceingest.RepositoryStore, catalog *evidencecatalog.Catalog, nativeCAS *encryptedcas.Store) {
	t.Helper()
	if result.Receipt.ArtifactSetDigest == nil || *result.Receipt.ArtifactSetDigest != evidenceSet.ArtifactSetDigest ||
		result.Receipt.AuthorizationCustodyReceiptDigest == nil || result.Receipt.LifecycleReceiptDigest == nil ||
		result.Receipt.DispositionAttestationDigest == nil || result.Receipt.CompletionCustodyReceiptDigest == nil {
		t.Fatalf("delete receipt omitted required proof: %+v", result.Receipt)
	}
	current, found, err := cases.LoadCase(t.Context(), scope)
	if err != nil || !found || current.State != "deleted" || current.Revision != 2 {
		t.Fatalf("tombstone=%+v found=%v err=%v", current, found, err)
	}
	lifecycle, found, err := cases.ResolveLifecycleReceipt(t.Context(), scope,
		*result.Receipt.LifecycleReceiptDigest)
	if err != nil || !found || lifecycle.Operation != evidencelifecycle.Delete || lifecycle.Revision != 2 {
		t.Fatalf("lifecycle proof=%+v found=%v err=%v", lifecycle, found, err)
	}
	attestation, found, err := disposer.RecoverDisposition(t.Context(), scope,
		*result.Receipt.DispositionAttestationDigest)
	if err != nil || !found || len(attestation.Objects) != 1 ||
		attestation.Objects[0].Outcome != evidencelifecycle.DispositionRemoved {
		t.Fatalf("disposition=%+v found=%v err=%v", attestation, found, err)
	}
	completion, found, err := lifecycleCustody.RecoverLifecycle(t.Context(), scope,
		*result.Receipt.CompletionCustodyReceiptDigest)
	if err != nil || !found || completion.Head.Sequence != 3 {
		t.Fatalf("completion custody=%+v found=%v err=%v", completion, found, err)
	}
	if _, err = nativeCAS.Resolve(t.Context(), ingested.Receipt.EncryptedArtifact); err == nil ||
		(encryptedcas.CodeOf(err) != encryptedcas.Unavailable && encryptedcas.CodeOf(err) != encryptedcas.Denied) {
		t.Fatalf("disposed artifact remained resolvable: %v", err)
	}
	if _, err = nativeCAS.Resolve(t.Context(), ingested.Receipt.EncryptedManifest); err != nil {
		t.Fatalf("immutable manifest was removed: %v", err)
	}
	if recovered, found, err := receipts.ResolveReceipt(t.Context(), scope,
		ingested.Receipt.ReceiptDigest); err != nil || !found || recovered.ReceiptDigest != ingested.Receipt.ReceiptDigest {
		t.Fatalf("ingestion receipt lost recovered=%+v found=%v err=%v", recovered, found, err)
	}
	if recovered, err := catalog.ResolveEvidenceSet(t.Context(), scope,
		evidenceSet.ArtifactSetDigest); err != nil || recovered.ArtifactSetDigest != evidenceSet.ArtifactSetDigest {
		t.Fatalf("catalog metadata lost recovered=%+v err=%v", recovered, err)
	}
}

type e10DeleteCustody struct {
	evidencelifecycle.Custody
	order *[]string
}

func (tracked *e10DeleteCustody) RecordLifecycle(ctx context.Context,
	request evidencelifecycle.CustodyRequest) (evidencelifecycle.CustodyProofSet, error) {
	if request.Phase == evidencelifecycle.Authorized {
		*tracked.order = append(*tracked.order, "custody.authorized")
	} else if request.Phase == evidencelifecycle.Completed {
		*tracked.order = append(*tracked.order, "custody.completed")
	}
	return tracked.Custody.RecordLifecycle(ctx, request)
}

type e10DeleteCaseLifecycle struct {
	evidencelifecycle.CaseLifecycle
	order *[]string
}

func (tracked *e10DeleteCaseLifecycle) ApplyCaseOperation(ctx context.Context,
	request evidencelifecycle.LifecycleRequest) (evidencelifecycle.LifecycleProof, error) {
	*tracked.order = append(*tracked.order, "case.tombstone")
	return tracked.CaseLifecycle.ApplyCaseOperation(ctx, request)
}

type e10DeleteDisposer struct {
	evidencelifecycle.Disposer
	order *[]string
}

func (tracked *e10DeleteDisposer) DisposeEvidence(ctx context.Context,
	request evidencelifecycle.DispositionRequest) (evidencelifecycle.DispositionAttestation, error) {
	*tracked.order = append(*tracked.order, "disposition")
	return tracked.Disposer.DisposeEvidence(ctx, request)
}

type e10DeleteStore struct {
	evidencelifecycle.Store
	order *[]string
}

func (tracked *e10DeleteStore) Commit(ctx context.Context, idempotencyKey, intent string,
	progress evidencelifecycle.Progress, record evidencelifecycle.Record,
	receipt evidencelifecycle.Receipt) (evidencelifecycle.Receipt, bool, error) {
	*tracked.order = append(*tracked.order, "commit")
	return tracked.Store.Commit(ctx, idempotencyKey, intent, progress, record, receipt)
}
