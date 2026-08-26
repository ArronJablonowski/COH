package sqlite_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/persistence/sqlite"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/caselifecycle"
)

type caseClock struct{ now time.Time }

func (clock caseClock) Now() time.Time { return clock.now }

type caseAuthority struct{ now time.Time }

func (authority caseAuthority) AuthorizeCase(_ context.Context,
	request caselifecycle.AuthorizationRequest) (caselifecycle.Decision, error) {
	value := caselifecycle.Decision{SchemaVersion: caselifecycle.DecisionSchemaVersion,
		ContractVersion: caselifecycle.ContractVersion, DecisionID: caseUUID("decision-" + request.Command.RequestID),
		AuthorizationDigest: request.AuthorizationDigest, IntentDigest: request.IntentDigest,
		Operation: request.Command.Operation, Case: request.Command.Case, ActorID: request.Command.ActorID,
		ActorRevision: request.Command.ActorRevision, ExpectedRevision: request.Command.ExpectedRevision,
		PolicyDigest: request.Command.PolicyDigest, RevocationDigest: caseDigest("revocation"),
		Outcome: "allow", ReasonCode: "case_allowed", IssuedAt: authority.now,
		ExpiresAt: authority.now.Add(time.Minute), Revision: 1}
	value.DecisionDigest, _ = caselifecycle.DecisionBindingDigest(value)
	return value, nil
}

type caseAuditor struct{ events []tamperaudit.Event }

func (auditor *caseAuditor) AppendAuditEvent(_ context.Context, event tamperaudit.Event) error {
	auditor.events = append(auditor.events, event)
	return nil
}

func TestCaseLifecycleCurrentAndReceiptsSurviveSQLiteRestart(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	path := filepath.Join(root, "coh.sqlite3")
	backup := filepath.Join(root, "backups")
	if err := os.MkdirAll(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	driver := openCaseSQLite(t, path, backup, now)
	auditor := &caseAuditor{}
	controller, repository := composeCaseController(t, driver, now, auditor)
	create := caseCreateCommand(now)
	created, err := controller.Execute(context.Background(), create)
	if err != nil || created.Record.Revision != 1 || created.Replayed {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	closeCommand := caselifecycle.Command{SchemaVersion: caselifecycle.CommandSchemaVersion,
		ContractVersion: caselifecycle.ContractVersion, RequestID: caseUUID("close-request"),
		IdempotencyKey: "sqlite-case-close", Operation: caselifecycle.Close, Case: create.Case,
		ActorID: create.ActorID, ActorRevision: create.ActorRevision, PolicyDigest: create.PolicyDigest,
		ExpectedRevision: 1, Deadline: now.Add(time.Hour)}
	closed, err := controller.Execute(context.Background(), closeCommand)
	if err != nil || closed.Record.Revision != 2 || closed.Record.State != caselifecycle.Closed {
		t.Fatalf("close=%+v err=%v", closed, err)
	}
	if current, found, loadErr := repository.Load(context.Background(), create.Case); loadErr != nil ||
		!found || current.Revision != 2 {
		t.Fatalf("pre-restart current=%+v found=%v err=%v", current, found, loadErr)
	}
	if err = driver.Close(); err != nil {
		t.Fatal(err)
	}

	driver = openCaseSQLite(t, path, backup, now)
	defer driver.Close()
	restartedAuditor := &caseAuditor{}
	restarted, restartedRepository := composeCaseController(t, driver, now, restartedAuditor)
	current, found, err := restartedRepository.Load(context.Background(), create.Case)
	if err != nil || !found || current.State != caselifecycle.Closed || current.Revision != 2 {
		t.Fatalf("restarted current=%+v found=%v err=%v", current, found, err)
	}
	replayed, err := restarted.Execute(context.Background(), create)
	if err != nil || !replayed.Replayed || replayed.Record.Revision != 1 ||
		replayed.Receipt.ReceiptDigest != created.Receipt.ReceiptDigest {
		t.Fatalf("restarted replay=%+v err=%v", replayed, err)
	}
	if len(restartedAuditor.events) != 2 {
		t.Fatalf("replay did not repair original audit and record fresh authority: %d", len(restartedAuditor.events))
	}
}

func composeCaseController(t *testing.T, driver *sqlite.Store, now time.Time,
	auditor *caseAuditor) (*caselifecycle.Controller, *caselifecycle.RepositoryStore) {
	t.Helper()
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := caselifecycle.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	controller, err := caselifecycle.New(caseAuthority{now: now}, auditor, repository, caseClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	return controller, repository
}

func openCaseSQLite(t *testing.T, path, backup string, now time.Time) *sqlite.Store {
	t.Helper()
	driver, err := sqlite.Open(context.Background(), sqlite.Config{Path: path, BackupDirectory: backup,
		Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func caseCreateCommand(now time.Time) caselifecycle.Command {
	classification := caselifecycle.Restricted
	assignee, retention := caseUUID("assignee"), caseUUID("retention")
	retainUntil := now.Add(24 * time.Hour)
	return caselifecycle.Command{SchemaVersion: caselifecycle.CommandSchemaVersion,
		ContractVersion: caselifecycle.ContractVersion, RequestID: caseUUID("create-request"),
		IdempotencyKey: "sqlite-case-create", Operation: caselifecycle.Create,
		Case:    domain.CaseRef{OrganizationID: caseUUID("org"), TenantID: caseUUID("tenant"), CaseID: caseUUID("case")},
		ActorID: caseUUID("actor"), ActorRevision: 2, TargetClassification: &classification,
		AssigneeActorID: &assignee, RetentionPolicyID: &retention, RetainUntil: &retainUntil,
		PolicyDigest: caseDigest("policy"), Deadline: now.Add(time.Hour)}
}

func caseDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func caseUUID(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
