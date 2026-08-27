package sqlite_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/persistence/encryptedcas"
	"github.com/ArronJablonowski/COH/internal/persistence/sqlite"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/caselifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

type evidenceClock struct{ now time.Time }

func (clock evidenceClock) Now() time.Time { return clock.now }

type evidenceAuthority struct{ now time.Time }

func (authority evidenceAuthority) AuthorizeIngestion(_ context.Context,
	request evidenceingest.AuthorizationRequest) (evidenceingest.Decision, error) {
	transportDigest, _ := evidenceingest.TransportBindingDigest(request.Command.Transport)
	value := evidenceingest.Decision{SchemaVersion: evidenceingest.DecisionSchemaVersion,
		ContractVersion: evidenceingest.ContractVersion, DecisionID: caseUUID("evidence-decision"),
		AuthorizationDigest: request.AuthorizationDigest, IntentDigest: request.IntentDigest,
		Case: request.Command.Case, ActorID: request.Command.ActorID, ActorRevision: request.Command.ActorRevision,
		ArtifactDigest: request.Command.ExpectedDigest, ArtifactLength: request.Command.ExpectedLength,
		PolicyDigest: request.Command.PolicyDigest, KeyProfileDigest: request.Command.KeyProfileDigest,
		TransportDigest: transportDigest, RevocationDigest: caseDigest("evidence-revocation"), Outcome: "allow",
		ReasonCode: "ingestion_allowed", IssuedAt: authority.now, ExpiresAt: authority.now.Add(time.Minute), Revision: 1}
	value.DecisionDigest, _ = evidenceingest.DecisionBindingDigest(value)
	return value, nil
}

type evidenceTransport struct{}

func (evidenceTransport) VerifyTransport(context.Context, evidenceingest.TransportContext) error {
	return nil
}

type evidenceAuditor struct{ events []tamperaudit.Event }

func (auditor *evidenceAuditor) AppendAuditEvent(_ context.Context, event tamperaudit.Event) error {
	auditor.events = append(auditor.events, event)
	return nil
}

type evidenceSource struct {
	value  []byte
	offset int
}

type failStageCAS struct {
	evidenceingest.EncryptedCAS
	count  int
	failAt int
}

func (store *failStageCAS) Stage(ctx context.Context, request evidenceingest.StageRequest,
	source evidenceingest.Source) (evidenceingest.EncryptedObject, error) {
	store.count++
	if store.count == store.failAt {
		return evidenceingest.EncryptedObject{}, errors.New("injected stage failure")
	}
	return store.EncryptedCAS.Stage(ctx, request, source)
}

func (source *evidenceSource) ReadContext(ctx context.Context, output []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if source.offset == len(source.value) {
		return 0, io.EOF
	}
	count := copy(output, source.value[source.offset:])
	source.offset += count
	return count, nil
}

func TestEvidenceReceiptAndEncryptedObjectsSurviveSQLiteRestart(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	databasePath := filepath.Join(root, "coh.sqlite3")
	backupPath := filepath.Join(root, "backups")
	casRoot := filepath.Join(root, "encrypted-cas")
	if err := os.MkdirAll(backupPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(casRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	wrappingKey := sha256.Sum256([]byte("sqlite-evidence-wrapping-key"))
	driver := openCaseSQLite(t, databasePath, backupPath, now)
	caseAudit := &caseAuditor{}
	caseController, caseRepository := composeCaseController(t, driver, now, caseAudit)
	create := caseCreateCommand(now)
	if _, err := caseController.Execute(t.Context(), create); err != nil {
		t.Fatal(err)
	}
	controller, auditor := composeEvidenceController(t, driver, caseRepository, casRoot, wrappingKey[:], now)
	plaintext := []byte("sqlite restart evidence must remain encrypted")
	command := evidenceCommand(create, plaintext, now)
	result, err := controller.Execute(t.Context(), command, &evidenceSource{value: plaintext})
	if err != nil || result.Replayed || len(auditor.events) != 1 {
		t.Fatalf("ingest=%+v audit=%d err=%v", result, len(auditor.events), err)
	}
	if err = driver.Close(); err != nil {
		t.Fatal(err)
	}
	assertSensitiveBytesAbsent(t, databasePath, casRoot, plaintext, []byte(command.Source.Identity))

	driver = openCaseSQLite(t, databasePath, backupPath, now)
	defer driver.Close()
	_, restartedCaseRepository := composeCaseController(t, driver, now, &caseAuditor{})
	restarted, restartedAuditor := composeEvidenceController(t, driver, restartedCaseRepository,
		casRoot, wrappingKey[:], now)
	replayed, err := restarted.Execute(t.Context(), command, nil)
	if err != nil || !replayed.Replayed || replayed.Receipt.ReceiptDigest != result.Receipt.ReceiptDigest ||
		len(restartedAuditor.events) != 2 {
		t.Fatalf("replay=%+v audit=%d err=%v", replayed, len(restartedAuditor.events), err)
	}
}

func TestEvidencePendingPublicationIdentifiesUnreferencedObjectAfterRestart(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	databasePath := filepath.Join(root, "coh.sqlite3")
	backupPath := filepath.Join(root, "backups")
	casRoot := filepath.Join(root, "encrypted-cas")
	if err := os.MkdirAll(backupPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(casRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	wrappingKey := sha256.Sum256([]byte("sqlite-pending-wrapping-key"))
	driver := openCaseSQLite(t, databasePath, backupPath, now)
	caseController, caseRepository := composeCaseController(t, driver, now, &caseAuditor{})
	create := caseCreateCommand(now)
	if _, err := caseController.Execute(t.Context(), create); err != nil {
		t.Fatal(err)
	}
	nativeCAS := openEvidenceCAS(t, casRoot, wrappingKey[:], now)
	failedCAS := &failStageCAS{EncryptedCAS: nativeCAS, failAt: 2}
	controller, _ := composeEvidenceControllerWithCAS(t, driver, caseRepository, failedCAS, now)
	plaintext := []byte("published artifact with interrupted manifest")
	command := evidenceCommand(create, plaintext, now)
	if _, err := controller.Execute(t.Context(), command, &evidenceSource{value: plaintext}); evidenceingest.CodeOf(err) != evidenceingest.Unavailable {
		t.Fatalf("failure code=%s err=%v", evidenceingest.CodeOf(err), err)
	}
	if err := driver.Close(); err != nil {
		t.Fatal(err)
	}

	driver = openCaseSQLite(t, databasePath, backupPath, now)
	defer driver.Close()
	_, restartedCases := composeCaseController(t, driver, now, &caseAuditor{})
	restarted, _ := composeEvidenceController(t, driver, restartedCases, casRoot, wrappingKey[:], now)
	candidates, err := restarted.IdentifyPending(t.Context(), command.Case, command.IdempotencyKey)
	if err != nil || len(candidates) != 1 ||
		candidates[0].Status != evidenceingest.PendingUnreferenced || candidates[0].Published == nil ||
		candidates[0].Pending.Role != evidenceingest.ArtifactPublication {
		t.Fatalf("candidates=%+v err=%v", candidates, err)
	}
}

func composeEvidenceController(t *testing.T, driver *sqlite.Store, caseRepository *caselifecycle.RepositoryStore,
	casRoot string, wrappingKey []byte, now time.Time) (*evidenceingest.Controller, *evidenceAuditor) {
	t.Helper()
	return composeEvidenceControllerWithCAS(t, driver, caseRepository,
		openEvidenceCAS(t, casRoot, wrappingKey, now), now)
}

func composeEvidenceControllerWithCAS(t *testing.T, driver *sqlite.Store,
	caseRepository *caselifecycle.RepositoryStore, cas evidenceingest.EncryptedCAS,
	now time.Time) (*evidenceingest.Controller, *evidenceAuditor) {
	t.Helper()
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	receipts, err := evidenceingest.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	cases, err := evidenceingest.NewCaseLifecycleStore(caseRepository)
	if err != nil {
		t.Fatal(err)
	}
	auditor := &evidenceAuditor{}
	controller, err := evidenceingest.New(evidenceAuthority{now: now}, evidenceTransport{}, cases, cas,
		receipts, auditor, evidenceClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	return controller, auditor
}

func openEvidenceCAS(t *testing.T, root string, wrappingKey []byte, now time.Time) *encryptedcas.Store {
	t.Helper()
	keys, err := encryptedcas.NewAESKeyManager("operator_evidence_key", 1, wrappingKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	store, err := encryptedcas.Open(encryptedcas.Config{Root: root, Keys: keys,
		Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func evidenceCommand(createCommand caselifecycle.Command, plaintext []byte, now time.Time) evidenceingest.Command {
	identity := "sensor://restricted/sqlite-restart/security-events"
	return evidenceingest.Command{SchemaVersion: evidenceingest.CommandSchemaVersion,
		ContractVersion: evidenceingest.ContractVersion, RequestID: caseUUID("evidence-request"),
		IdempotencyKey: "sqlite-evidence-ingest", Case: createCommand.Case,
		ActorID: createCommand.ActorID, ActorRevision: createCommand.ActorRevision,
		ExpectedDigest: evidenceDigest(plaintext), ExpectedLength: int64(len(plaintext)),
		MediaType: "application/octet-stream", Classification: "restricted",
		Source: evidenceingest.SourceInput{Kind: evidenceingest.UploadSource, Identity: identity,
			IdentityDigest: evidenceingest.SourceIdentityDigest(identity), CollectionMethod: "secure_upload",
			CollectionMethodVersion: "1.0.0", CollectedAt: now},
		ParentArtifacts: []domain.ArtifactRef{}, ParentManifestDigests: []string{},
		Components: []evidenceingest.ComponentVersion{}, KeyProfile: "operator_evidence",
		KeyProfileDigest: caseDigest("evidence-key-profile"), PolicyDigest: caseDigest("evidence-policy"),
		Transport: evidenceingest.TransportContext{Mode: evidenceingest.InProcess,
			PeerIdentityDigest: caseDigest("evidence-peer"), ChannelBindingDigest: caseDigest("evidence-channel")},
		Deadline: now.Add(time.Hour)}
}

func assertSensitiveBytesAbsent(t *testing.T, databasePath, casRoot string, values ...[]byte) {
	t.Helper()
	database, err := os.ReadFile(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if bytes.Contains(database, value) {
			t.Fatalf("sensitive value appeared in SQLite storage: %q", value)
		}
	}
	err = filepath.WalkDir(casRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, value := range values {
			if bytes.Contains(content, value) {
				t.Fatalf("sensitive value appeared in encrypted CAS file %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func evidenceDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
