package sqlite_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/persistence/encryptedcas"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencecatalog"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow/lifecycledisposition"
)

type lostDispositionResponseCAS struct {
	lifecycledisposition.EncryptedCAS
	lost bool
}

type lostDispositionCommitResponse struct {
	workflow.MetadataStore
	lost bool
}

func (store *lostDispositionCommitResponse) Transact(ctx context.Context,
	transaction workflow.Transaction) (workflow.CommitResult, error) {
	result, err := store.MetadataStore.Transact(ctx, transaction)
	if err == nil && !store.lost {
		store.lost = true
		return workflow.CommitResult{}, workflow.NewStorageError(workflow.StorageUnavailable,
			"transact", "test", "injected disposition commit response loss", nil)
	}
	return result, err
}

func (store *lostDispositionResponseCAS) DisposePublished(ctx context.Context,
	reference evidenceingest.PublishedObject, digest string, revision uint64) (bool, error) {
	removed, err := store.EncryptedCAS.DisposePublished(ctx, reference, digest, revision)
	if err == nil && !store.lost {
		store.lost = true
		return false, errors.New("injected disposition response loss")
	}
	return removed, err
}

func TestLifecycleDispositionRemovesExactBytesAndPreservesMetadataAcrossRestart(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	databasePath, backupPath := filepath.Join(root, "coh.sqlite3"), filepath.Join(root, "backups")
	casRoot := filepath.Join(root, "encrypted-cas")
	for _, directory := range []string{backupPath, casRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	wrappingKey := sha256.Sum256([]byte("sqlite-disposition-wrapping-key"))
	driver := openCaseSQLite(t, databasePath, backupPath, now)
	caseController, caseRepository := composeCaseController(t, driver, now, &caseAuditor{})
	create := caseCreateCommand(now)
	if _, err := caseController.Execute(t.Context(), create); err != nil {
		t.Fatal(err)
	}
	controller, _ := composeEvidenceController(t, driver, caseRepository, casRoot, wrappingKey[:], now)
	plaintext := []byte("physically disposed evidence bytes")
	command := evidenceCommand(create, plaintext, now)
	result, err := controller.Execute(t.Context(), command, &evidenceSource{value: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := evidenceingest.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	nativeCAS := openEvidenceCAS(t, casRoot, wrappingKey[:], now)
	catalog, err := evidencecatalog.New(guarded, receipts, nativeCAS)
	if err != nil {
		t.Fatal(err)
	}
	entry := evidencelifecycle.ManifestArtifact{Ordinal: 1, Role: evidencelifecycle.SourceArtifact,
		Reference: evidencelifecycle.EvidenceReference{Artifact: result.Artifact, Manifest: result.Manifest,
			ManifestProvenanceDigest: result.Receipt.ManifestProvenanceDigest,
			IngestionReceiptDigest:   result.Receipt.ReceiptDigest},
		ParentArtifactDigests: []string{}, ParentManifestDigests: []string{}}
	verified, _, err := catalog.Register(t.Context(), evidencecatalog.Registration{Case: command.Case,
		Artifacts: []evidencelifecycle.ManifestArtifact{entry}})
	if err != nil {
		t.Fatal(err)
	}
	request := evidencelifecycle.DispositionRequest{Case: command.Case,
		OperationID: caseUUID("lifecycle-disposition-operation"), ArtifactSetDigest: verified.ArtifactSetDigest,
		Evidence: verified, AuthorizationCustodyReceiptDigest: caseDigest("disposition-authorization-custody"),
		LifecycleReceiptDigest: caseDigest("disposition-lifecycle-receipt"), Deadline: now.Add(time.Hour)}
	lostCAS := &lostDispositionResponseCAS{EncryptedCAS: nativeCAS}
	adapter, err := lifecycledisposition.New(receipts, lostCAS, guarded, evidenceClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = adapter.DisposeEvidence(t.Context(), request); err == nil ||
		evidencelifecycle.CodeOf(err) != evidencelifecycle.Unavailable {
		t.Fatalf("lost disposition response err=%v", err)
	}
	if _, err = nativeCAS.Resolve(t.Context(), result.Receipt.EncryptedArtifact); encryptedcas.CodeOf(err) != encryptedcas.Unavailable &&
		encryptedcas.CodeOf(err) != encryptedcas.Denied {
		t.Fatalf("disposed artifact remained resolvable: %v", err)
	}
	if _, err = nativeCAS.Resolve(t.Context(), result.Receipt.EncryptedManifest); err != nil {
		t.Fatalf("immutable manifest was removed: %v", err)
	}
	if resolved, found, resolveErr := receipts.ResolveReceipt(t.Context(), command.Case,
		result.Receipt.ReceiptDigest); resolveErr != nil || !found || resolved.ReceiptDigest != result.Receipt.ReceiptDigest {
		t.Fatalf("ingestion metadata lost resolved=%+v found=%v err=%v", resolved, found, resolveErr)
	}
	if resolvedSet, resolveErr := catalog.ResolveEvidenceSet(t.Context(), command.Case,
		verified.ArtifactSetDigest); resolveErr != nil || resolvedSet.ArtifactSetDigest != verified.ArtifactSetDigest {
		t.Fatalf("artifact-set metadata lost set=%+v err=%v", resolvedSet, resolveErr)
	}

	lostCommit := &lostDispositionCommitResponse{MetadataStore: guarded}
	adapter, err = lifecycledisposition.New(receipts, lostCAS, lostCommit, evidenceClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := adapter.DisposeEvidence(t.Context(), request)
	if err != nil || len(attestation.Objects) != 1 ||
		attestation.Objects[0].ArtifactDigest != result.Artifact.Digest ||
		attestation.Objects[0].Outcome != evidencelifecycle.DispositionRemoved ||
		attestation.Objects[0].EncryptedObjectDigest == "" || attestation.Objects[0].KeyRevision == 0 {
		t.Fatalf("attestation=%+v err=%v", attestation, err)
	}
	adapter, err = lifecycledisposition.New(receipts, nativeCAS, guarded, evidenceClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := adapter.DisposeEvidence(t.Context(), request)
	if err != nil || replayed.AttestationDigest != attestation.AttestationDigest {
		t.Fatalf("replayed attestation=%+v err=%v", replayed, err)
	}
	changed := request
	changed.LifecycleReceiptDigest = caseDigest("changed-lifecycle-receipt")
	if _, err = adapter.DisposeEvidence(t.Context(), changed); err == nil ||
		evidencelifecycle.CodeOf(err) != evidencelifecycle.Denied {
		t.Fatalf("changed replay err=%v", err)
	}
	if err = driver.Close(); err != nil {
		t.Fatal(err)
	}

	driver = openCaseSQLite(t, databasePath, backupPath, now)
	defer driver.Close()
	guarded, err = workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err = evidenceingest.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	nativeCAS = openEvidenceCAS(t, casRoot, wrappingKey[:], now)
	restarted, err := lifecycledisposition.New(receipts, nativeCAS, guarded, evidenceClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	recovered, found, err := restarted.RecoverDisposition(t.Context(), command.Case,
		attestation.AttestationDigest)
	if err != nil || !found || recovered.AttestationDigest != attestation.AttestationDigest ||
		recovered.Objects[0].OutcomeDigest != attestation.Objects[0].OutcomeDigest {
		t.Fatalf("recovered attestation=%+v found=%v err=%v", recovered, found, err)
	}
	if resolved, found, resolveErr := receipts.ResolveReceipt(t.Context(), command.Case,
		result.Receipt.ReceiptDigest); resolveErr != nil || !found || resolved.ReceiptDigest != result.Receipt.ReceiptDigest {
		t.Fatalf("restart metadata lost resolved=%+v found=%v err=%v", resolved, found, resolveErr)
	}
}
