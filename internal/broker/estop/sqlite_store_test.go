package estop

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
	_ "modernc.org/sqlite"
)

func TestSQLiteStoreSurvivesRestartWithActiveStopEpochAndAuditOutbox(t *testing.T) {
	path := filepath.Join(t.TempDir(), "estop.db")
	database := openStopDatabase(t, path)
	store, err := NewSQLiteStore(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	audit := &fakeAudit{fail: true}
	controls := sqliteControls()
	controller := newSQLiteController(t, store, audit, controls)
	command, authority := fixture(true)
	result, decision, err := controller.Activate(context.Background(), command, authority)
	if stopcontract.Reason(err) != "audit_delivery_pending" || !result.AuditPending || decision.Outcome != "allowed" || result.State.Epoch != 1 {
		t.Fatalf("result=%+v decision=%+v err=%v", result, decision, err)
	}
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}

	database = openStopDatabase(t, path)
	defer database.Close()
	restartedStore, err := NewSQLiteStore(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	restartedAudit := &fakeAudit{}
	restarted := newSQLiteController(t, restartedStore, restartedAudit, sqliteControls())
	state, err := restarted.Check(context.Background(), testOrg, testTenant, testCase)
	if stopcontract.Code(err) != stopcontract.Denied || state.Epoch != 1 || state.RequestDigest == "" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	replay, replayDecision, err := restarted.Activate(context.Background(), command, authority)
	if err != nil || replay.State != state || len(replay.Acknowledgements) != 0 || replayDecision.DecisionDigest != decision.DecisionDigest {
		t.Fatalf("replay=%+v decision=%+v err=%v", replay, replayDecision, err)
	}
	delivered, err := restarted.RecoverAudit(context.Background(), 32)
	if err != nil || delivered != 6 || len(restartedAudit.decisions) != 6 {
		t.Fatalf("delivered=%d decisions=%d err=%v", delivered, len(restartedAudit.decisions), err)
	}
	if again, err := restarted.RecoverAudit(context.Background(), 32); err != nil || again != 0 {
		t.Fatalf("second recovery=%d err=%v", again, err)
	}

	otherCommand, otherAuthority := fixture(true)
	otherCommand.RequestID = "018f47a6-4b2c-7a1e-8a12-123456789ac9"
	otherCommand.IdempotencyKey = "stop-other-case"
	otherCommand.Scope.CaseID = testOther
	otherAuthority.Scope = otherCommand.Scope
	other, _, err := restarted.Activate(context.Background(), otherCommand, otherAuthority)
	if err != nil || other.State.Epoch != 2 {
		t.Fatalf("other=%+v err=%v", other, err)
	}
}

func TestSQLiteStoreRejectsCorruptPersistedState(t *testing.T) {
	database := openStopDatabase(t, filepath.Join(t.TempDir(), "corrupt.db"))
	defer database.Close()
	store, err := NewSQLiteStore(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.Exec(`INSERT INTO coh_estop_states(scope_key, state_json) VALUES (?, ?)`,
		scopeKey(stopcontract.Scope{Kind: "global", OrganizationID: testOrg, TenantID: testTenant}), []byte(`{"active":true}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.Effective(context.Background(), testOrg, testTenant, testCase); stopcontract.Reason(err) != "stop_state_corrupt" {
		t.Fatalf("err=%v", err)
	}
}

func TestSQLiteStoreRejectsUnsafeDurabilityConfiguration(t *testing.T) {
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "unsafe.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err = NewSQLiteStore(context.Background(), database); stopcontract.Code(err) != stopcontract.Denied ||
		stopcontract.Reason(err) != "sqlite_durability_configuration_invalid" {
		t.Fatalf("err=%v", err)
	}
}

func openStopDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	database.SetMaxOpenConns(1)
	for _, statement := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA busy_timeout=5000"} {
		if _, err = database.Exec(statement); err != nil {
			database.Close()
			t.Fatal(err)
		}
	}
	return database
}

func sqliteControls() []Control {
	values := []*fakeControl{{id: "credential-sqlite", kind: "credential"}, {id: "egress-sqlite", kind: "egress"},
		{id: "remote-jobs-sqlite", kind: "remote_job"}, {id: "workflow-sqlite", kind: "workflow"},
		{id: "cooperative-sqlite", kind: "cooperative"}}
	controls := make([]Control, len(values))
	for index := range values {
		controls[index] = values[index]
	}
	return controls
}

func newSQLiteController(t *testing.T, store Store, audit AuditSink, controls []Control) *Controller {
	t.Helper()
	controller, err := NewWithDependencies(store, audit,
		&fixedClock{now: time.Date(2026, 8, 26, 5, 0, 0, 0, time.UTC)}, controls...)
	if err != nil {
		t.Fatal(err)
	}
	return controller
}
