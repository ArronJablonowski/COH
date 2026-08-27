package sqlite_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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

type interruptedMultiObjectCAS struct {
	lifecycledisposition.EncryptedCAS
	calls  int
	failed bool
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

func (store *interruptedMultiObjectCAS) DisposePublished(ctx context.Context,
	reference evidenceingest.PublishedObject, digest string, revision uint64) (bool, error) {
	store.calls++
	if store.calls == 2 && !store.failed {
		store.failed = true
		return false, errors.New("injected interruption after first object removal")
	}
	return store.EncryptedCAS.DisposePublished(ctx, reference, digest, revision)
}

func TestCOHE10PartialDeletionResumesExactPlanWithoutMetadataLoss(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	databasePath, backupPath := filepath.Join(root, "coh.sqlite3"), filepath.Join(root, "backups")
	casRoot := filepath.Join(root, "encrypted-cas")
	for _, directory := range []string{backupPath, casRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	driver := openCaseSQLite(t, databasePath, backupPath, now)
	defer driver.Close()
	caseController, caseRepository := composeCaseController(t, driver, now, &caseAuditor{})
	create := caseCreateCommand(now)
	if _, err := caseController.Execute(t.Context(), create); err != nil {
		t.Fatal(err)
	}
	wrappingKey := sha256.Sum256([]byte("coh-e10-partial-delete-wrapping-key"))
	ingestion, _ := composeEvidenceController(t, driver, caseRepository, casRoot, wrappingKey[:], now)
	results := make([]evidenceingest.Result, 2)
	entries := make([]evidencelifecycle.ManifestArtifact, 2)
	for index, payload := range [][]byte{[]byte("first governed deletion object"), []byte("second governed deletion object")} {
		command := evidenceCommand(create, payload, now)
		command.RequestID = caseUUID(fmt.Sprintf("e10-partial-delete-request-%d", index))
		command.IdempotencyKey = fmt.Sprintf("e10-partial-delete-%d", index)
		command.Source.Identity = fmt.Sprintf("e10-partial-delete-source-%d", index)
		command.Source.IdentityDigest = evidenceingest.SourceIdentityDigest(command.Source.Identity)
		result, err := ingestion.Execute(t.Context(), command, &evidenceSource{value: payload})
		if err != nil {
			t.Fatal(err)
		}
		results[index] = result
		entries[index] = evidencelifecycle.ManifestArtifact{Ordinal: uint16(index + 1),
			Role: evidencelifecycle.SourceArtifact, Reference: evidencelifecycle.EvidenceReference{
				Artifact: result.Artifact, Manifest: result.Manifest,
				ManifestProvenanceDigest: result.Receipt.ManifestProvenanceDigest,
				IngestionReceiptDigest:   result.Receipt.ReceiptDigest},
			ParentArtifactDigests: []string{}, ParentManifestDigests: []string{}}
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
	evidenceSet, _, err := catalog.Register(t.Context(), evidencecatalog.Registration{
		Case: create.Case, Artifacts: entries})
	if err != nil {
		t.Fatal(err)
	}
	request := evidencelifecycle.DispositionRequest{Case: create.Case,
		OperationID: caseUUID("e10-partial-delete-operation"), ArtifactSetDigest: evidenceSet.ArtifactSetDigest,
		Evidence: evidenceSet, AuthorizationCustodyReceiptDigest: caseDigest("e10-partial-delete-authorization"),
		LifecycleReceiptDigest: caseDigest("e10-partial-delete-lifecycle"), Deadline: now.Add(time.Hour)}
	interrupted := &interruptedMultiObjectCAS{EncryptedCAS: nativeCAS}
	disposer, err := lifecycledisposition.New(receipts, interrupted, guarded, evidenceClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = disposer.DisposeEvidence(t.Context(), request); err == nil ||
		evidencelifecycle.CodeOf(err) != evidencelifecycle.Unavailable {
		t.Fatalf("partial deletion did not fail closed: %v", err)
	}
	missing, remaining := 0, 0
	for _, result := range results {
		if _, resolveErr := nativeCAS.Resolve(t.Context(), result.Receipt.EncryptedArtifact); resolveErr == nil {
			remaining++
		} else {
			missing++
		}
		if _, manifestErr := nativeCAS.Resolve(t.Context(), result.Receipt.EncryptedManifest); manifestErr != nil {
			t.Fatalf("partial deletion removed immutable manifest: %v", manifestErr)
		}
		if recovered, found, receiptErr := receipts.ResolveReceipt(t.Context(), create.Case,
			result.Receipt.ReceiptDigest); receiptErr != nil || !found ||
			recovered.ReceiptDigest != result.Receipt.ReceiptDigest {
			t.Fatalf("partial deletion lost receipt found=%v err=%v", found, receiptErr)
		}
	}
	if missing != 1 || remaining != 1 {
		t.Fatalf("partial deletion removed=%d remaining=%d", missing, remaining)
	}
	if recovered, resolveErr := catalog.ResolveEvidenceSet(t.Context(), create.Case,
		evidenceSet.ArtifactSetDigest); resolveErr != nil || recovered.ArtifactSetDigest != evidenceSet.ArtifactSetDigest {
		t.Fatalf("partial deletion lost catalog metadata: %+v err=%v", recovered, resolveErr)
	}
	attestation, err := disposer.DisposeEvidence(t.Context(), request)
	if err != nil || len(attestation.Objects) != 2 {
		t.Fatalf("resumed disposition=%+v err=%v", attestation, err)
	}
	for _, object := range attestation.Objects {
		if object.Outcome != evidencelifecycle.DispositionRemoved {
			t.Fatalf("resumed object outcome=%+v", object)
		}
	}
	for _, result := range results {
		if _, resolveErr := nativeCAS.Resolve(t.Context(), result.Receipt.EncryptedArtifact); resolveErr == nil {
			t.Fatal("resumed disposition left artifact ciphertext resolvable")
		}
	}
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
