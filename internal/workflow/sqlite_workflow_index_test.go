package workflow

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	stopcontract "github.com/ArronJablonowski/COH/internal/domain/estop"
	_ "modernc.org/sqlite"
)

func TestSQLiteWorkflowIndexSignalsDurableTargetAfterEngineRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workflows.db")
	database := openWorkflowIndexDatabase(t, path)
	index, err := NewSQLiteWorkflowIndex(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	firstDriver := &workflowDriverStub{}
	first, err := GuardEngine(firstDriver, &mutableWorkflowStopGuard{}, index)
	if err != nil {
		t.Fatal(err)
	}
	startWorkflowForStop(t, first, stopTestCase, "0198d6c4-5555-7555-8555-555555555555")
	if err = database.Close(); err != nil {
		t.Fatal(err)
	}

	database = openWorkflowIndexDatabase(t, path)
	defer database.Close()
	restartedIndex, err := NewSQLiteWorkflowIndex(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	restartedDriver := &workflowDriverStub{}
	restarted, err := GuardEngine(restartedDriver, &mutableWorkflowStopGuard{}, restartedIndex)
	if err != nil {
		t.Fatal(err)
	}
	request := stopcontract.ControlRequest{Scope: stopcontract.Scope{Kind: "case", OrganizationID: stopTestOrg,
		TenantID: stopTestTenant, CaseID: stopTestCase}, Epoch: 21}
	if evidence, applyErr := restarted.Apply(context.Background(), request); applyErr != nil || evidence == "" {
		t.Fatalf("evidence=%q err=%v", evidence, applyErr)
	}
	if len(restartedDriver.signals) != 1 || len(restartedDriver.cancels) != 1 ||
		restartedDriver.signals[0].Target.WorkflowID != "0198d6c4-5555-7555-8555-555555555555" {
		t.Fatalf("signals=%+v cancels=%+v", restartedDriver.signals, restartedDriver.cancels)
	}
	remaining, err := restartedIndex.List(context.Background(), request.Scope)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("remaining=%+v err=%v", remaining, err)
	}
}

func TestSQLiteWorkflowIndexRejectsUnsafeDurabilityConfiguration(t *testing.T) {
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "unsafe.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err = NewSQLiteWorkflowIndex(context.Background(), database); EngineCode(err) != EngineDenied {
		t.Fatalf("err=%v", err)
	}
}

func openWorkflowIndexDatabase(t *testing.T, path string) *sql.DB {
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
