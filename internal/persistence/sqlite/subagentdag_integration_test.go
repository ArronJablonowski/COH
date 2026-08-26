package sqlite_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/persistence/sqlite"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/runbudget"
	"github.com/ArronJablonowski/COH/internal/workflow/subagentdag"
)

type dagClock struct{ now time.Time }

func (clock dagClock) Now() time.Time { return clock.now }

type dagAuthority struct{ now time.Time }

func (authority dagAuthority) AuthorizeDelegation(_ context.Context, request subagentdag.AuthorizationRequest) (subagentdag.Decision, error) {
	decision := subagentdag.Decision{SchemaVersion: subagentdag.DecisionSchemaVersion,
		ContractVersion: subagentdag.ContractVersion, DecisionID: dagUUID("decision-" + string(request.Operation)),
		IntentDigest: request.IntentDigest, Operation: request.Operation, GraphID: request.GraphID,
		TaskID: request.TaskID, Case: request.Case, ActorID: request.ActorID,
		ActorRevision: request.ActorRevision, PolicyDigest: request.PolicyDigest,
		RevocationDigest: dagDigest("revocation"), Outcome: "allow", ReasonCode: "delegation_allowed",
		IssuedAt: authority.now.Add(-time.Minute), ExpiresAt: authority.now.Add(time.Minute), Revision: 1}
	decision.DecisionDigest, _ = subagentdag.DecisionBindingDigest(decision)
	return decision, nil
}

type dagRuntime struct{ calls int }

func (runtime *dagRuntime) RunChild(_ context.Context, request subagentdag.ExecutionRequest) (subagentdag.StructuredResult, error) {
	runtime.calls++
	result := subagentdag.StructuredResult{TaskID: request.TaskID, Role: request.Role,
		Artifact: domain.ArtifactRef{Digest: dagDigest("result-artifact"), MediaType: "application/json",
			Classification: "internal", Length: 128},
		Claims: []subagentdag.Claim{{ClaimID: dagUUID("claim"), StatementDigest: dagDigest("statement"),
			EvidenceRefs: []string{dagDigest("evidence")}, CounterevidenceRefs: []string{},
			ConfidenceBasisPoints: 8700, UnknownDigests: []string{},
			RecommendedNextStepDigests: []string{dagDigest("next-step")}}},
		Findings: []subagentdag.Finding{}, Completeness: subagentdag.Complete,
		RuntimeDigest: dagDigest("runtime")}
	result.ResultDigest, _ = subagentdag.ResultBindingDigest(result)
	return result, nil
}

type blockingDAGRuntime struct{ started chan struct{} }

func (runtime blockingDAGRuntime) RunChild(ctx context.Context, _ subagentdag.ExecutionRequest) (subagentdag.StructuredResult, error) {
	close(runtime.started)
	<-ctx.Done()
	return subagentdag.StructuredResult{}, ctx.Err()
}

type dagCanceler struct{}

func (dagCanceler) CancelChild(context.Context, subagentdag.ExecutionRequest, string) (subagentdag.CancellationAck, error) {
	return subagentdag.CancellationAck{}, errors.New("unused")
}

type dagBudgetStore struct {
	ledger runbudget.Ledger
	found  bool
}

func (store *dagBudgetStore) Load(_ context.Context, scope domain.CaseRef, runID string) (runbudget.Ledger, bool, error) {
	if !store.found {
		return runbudget.Ledger{}, false, nil
	}
	if store.ledger.Case != scope || store.ledger.RunID != runID {
		return runbudget.Ledger{}, false, errors.New("budget scope mismatch")
	}
	return cloneDAGLedger(store.ledger), true, nil
}

func (store *dagBudgetStore) Begin(_ context.Context, _ string, next runbudget.Ledger) (runbudget.Ledger, bool, error) {
	if store.found {
		return cloneDAGLedger(store.ledger), true, nil
	}
	store.ledger, store.found = cloneDAGLedger(next), true
	return cloneDAGLedger(next), false, nil
}

func (store *dagBudgetStore) Save(_ context.Context, _ string, prior, next runbudget.Ledger) (runbudget.Ledger, error) {
	if !store.found || store.ledger.Revision != prior.Revision ||
		store.ledger.ProvenanceDigest != prior.ProvenanceDigest {
		return runbudget.Ledger{}, errors.New("budget revision conflict")
	}
	store.ledger = cloneDAGLedger(next)
	return cloneDAGLedger(next), nil
}

func TestSubagentDAGSurvivesSQLiteRestartWithoutRedispatch(t *testing.T) {
	now := time.Date(2026, 8, 26, 22, 30, 0, 0, time.UTC)
	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "coh.sqlite3")
	driver := openDAGSQLite(t, path, backup, now)
	budgets := &dagBudgetStore{}
	runtime := &dagRuntime{}
	controller := composeDAGController(t, driver, budgets, runtime, now)
	create := dagCreateRequest(now)
	created, err := controller.Create(context.Background(), create)
	if err != nil {
		t.Fatal(err)
	}
	overBudget := dagDelegateRequest(now, create, created.Task.TaskID)
	overBudget.RequestID = dagUUID("over-budget-request")
	overBudget.IdempotencyKey = "sqlite-dag-over-budget"
	overBudget.TaskID = dagUUID("over-budget-child")
	overBudget.TaskBudget.Tokens = 10_001
	if _, err = controller.Delegate(context.Background(), overBudget); subagentdag.CodeOf(err) != subagentdag.Denied {
		t.Fatalf("over-budget delegation err=%v", err)
	}
	delegate := dagDelegateRequest(now, create, created.Task.TaskID)
	delegated, err := controller.Delegate(context.Background(), delegate)
	if err != nil {
		t.Fatal(err)
	}
	execute := subagentdag.ExecuteRequest{RequestID: dagUUID("execute-request"),
		IdempotencyKey: "sqlite-dag-execute", GraphID: create.GraphID, TaskID: delegated.Task.TaskID,
		Case: create.Case, ActorID: create.ActorID, ActorRevision: create.ActorRevision,
		PolicyDigest: create.PolicyDigest}
	completed, err := controller.Execute(context.Background(), execute)
	if err != nil || completed.Task.Status != subagentdag.TaskSucceeded || runtime.calls != 1 {
		t.Fatalf("completed=%+v calls=%d err=%v", completed, runtime.calls, err)
	}
	if err = driver.Close(); err != nil {
		t.Fatal(err)
	}

	driver = openDAGSQLite(t, path, backup, now)
	restartedRuntime := &dagRuntime{}
	restarted := composeDAGController(t, driver, budgets, restartedRuntime, now)
	replayed, err := restarted.Execute(context.Background(), execute)
	if err != nil || !replayed.Replayed || replayed.Task.Status != subagentdag.TaskSucceeded ||
		replayed.Task.Result == nil || restartedRuntime.calls != 0 {
		t.Fatalf("replayed=%+v calls=%d err=%v", replayed, restartedRuntime.calls, err)
	}
	createReplay, err := restarted.Create(context.Background(), create)
	if err != nil || !createReplay.Replayed || createReplay.Graph.Revision != replayed.Graph.Revision {
		t.Fatalf("create replay=%+v err=%v", createReplay, err)
	}

	crashDelegate := dagDelegateRequest(now, create, created.Task.TaskID)
	crashDelegate.RequestID = dagUUID("crash-delegate-request")
	crashDelegate.IdempotencyKey = "sqlite-dag-crash-delegate"
	crashDelegate.TaskID = dagUUID("crash-child")
	crashChild, err := restarted.Delegate(context.Background(), crashDelegate)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	crashing := composeDAGController(t, driver, budgets, blockingDAGRuntime{started: started}, now)
	crashCtx, cancelCrash := context.WithCancel(context.Background())
	crashDone := make(chan error, 1)
	go func() {
		_, executeErr := crashing.Execute(crashCtx, subagentdag.ExecuteRequest{
			RequestID: dagUUID("crash-execute-request"), IdempotencyKey: "sqlite-dag-crash-execute",
			GraphID: create.GraphID, TaskID: crashChild.Task.TaskID, Case: create.Case,
			ActorID: create.ActorID, ActorRevision: create.ActorRevision, PolicyDigest: create.PolicyDigest})
		crashDone <- executeErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("crash runtime did not start")
	}
	if err = driver.Close(); err != nil {
		t.Fatal(err)
	}
	cancelCrash()
	select {
	case err = <-crashDone:
		if err == nil {
			t.Fatal("simulated crash unexpectedly persisted a terminal result")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("simulated crash execution did not return")
	}

	driver = openDAGSQLite(t, path, backup, now)
	defer driver.Close()
	recoveryRuntime := &dagRuntime{}
	recovery := composeDAGController(t, driver, budgets, recoveryRuntime, now)
	recovered, err := recovery.Recover(context.Background(), subagentdag.RecoverRequest{
		RequestID: dagUUID("recover-request"), IdempotencyKey: "sqlite-dag-recover",
		GraphID: create.GraphID, TaskID: crashChild.Task.TaskID, Case: create.Case,
		ActorID: create.ActorID, ActorRevision: create.ActorRevision, PolicyDigest: create.PolicyDigest})
	if err != nil || recovered.Task.Status != subagentdag.TaskUncertain ||
		recovered.Task.BudgetSettlementDigest == "" || recoveryRuntime.calls != 0 {
		t.Fatalf("recovered=%+v runtime calls=%d err=%v", recovered, recoveryRuntime.calls, err)
	}
}

func composeDAGController(t *testing.T, driver *sqlite.Store, budgetStore runbudget.Store,
	runtime subagentdag.Runtime, now time.Time) *subagentdag.Controller {
	t.Helper()
	guarded, err := workflow.GuardStorage(driver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := subagentdag.NewRepositoryStore(guarded)
	if err != nil {
		t.Fatal(err)
	}
	budgets, err := runbudget.New(budgetStore, dagClock{now})
	if err != nil {
		t.Fatal(err)
	}
	controller, err := subagentdag.New(store, dagAuthority{now}, runtime, dagCanceler{}, budgets, dagClock{now})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func openDAGSQLite(t *testing.T, path, backup string, now time.Time) *sqlite.Store {
	t.Helper()
	driver, err := sqlite.Open(context.Background(), sqlite.Config{Path: path, BackupDirectory: backup,
		Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return driver
}

func dagCreateRequest(now time.Time) subagentdag.CreateRequest {
	limits := runbudget.Vector{Tokens: 10_000, CostMicros: 100_000,
		WallTimeNanoseconds: uint64(time.Hour), ToolCalls: 20, QueryRows: 10_000,
		EvidenceBytes: 1 << 20, DelegationDepth: 4, Fanout: 4, Concurrency: 4}
	scope := domain.CaseRef{OrganizationID: dagUUID("organization"), TenantID: dagUUID("tenant"),
		CaseID: dagUUID("case")}
	return subagentdag.CreateRequest{RequestID: dagUUID("create-request"), IdempotencyKey: "sqlite-dag-create",
		GraphID: dagUUID("graph"), RunID: dagUUID("run"), RootTaskID: dagUUID("root"), Case: scope,
		ActorID: dagUUID("actor"), ActorRevision: 3, PolicyDigest: dagDigest("policy"),
		ProviderRoute: "connected", Limits: subagentdag.Limits{MaximumDepth: 4, MaximumFanout: 4,
			MaximumConcurrency: 4, MaximumTasks: 32}, InputRefs: []string{dagDigest("root-input")},
		Deadline: now.Add(time.Hour), BudgetPlan: runbudget.Plan{SchemaVersion: runbudget.SchemaVersion,
			ContractVersion: runbudget.ContractVersion, RunID: dagUUID("run"), Case: scope,
			PolicyDigest: dagDigest("policy"), ProviderRoute: "connected", Limits: limits,
			CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(2 * time.Hour)}, TaskBudget: limits,
		BudgetClaim: runbudget.Vector{Tokens: 100, CostMicros: 10,
			WallTimeNanoseconds: uint64(time.Hour), DelegationDepth: 0, Fanout: 4, Concurrency: 1}}
}

func dagDelegateRequest(now time.Time, create subagentdag.CreateRequest, parentID string) subagentdag.DelegateRequest {
	return subagentdag.DelegateRequest{RequestID: dagUUID("delegate-request"),
		IdempotencyKey: "sqlite-dag-delegate", GraphID: create.GraphID, TaskID: dagUUID("child"),
		ParentTaskIDs: []string{parentID}, Case: create.Case, ActorID: create.ActorID,
		ActorRevision: create.ActorRevision, Role: subagentdag.AlertTriageRole,
		InputRefs: []string{dagDigest("child-input")}, PolicyDigest: create.PolicyDigest,
		Deadline: now.Add(30 * time.Minute), TaskBudget: runbudget.Vector{Tokens: 1_000,
			CostMicros: 1_000, WallTimeNanoseconds: uint64(time.Hour), ToolCalls: 5, QueryRows: 1_000,
			EvidenceBytes: 1 << 18, DelegationDepth: 4, Fanout: 4, Concurrency: 1},
		BudgetClaim: runbudget.Vector{Tokens: 50, CostMicros: 5,
			WallTimeNanoseconds: uint64(30 * time.Minute), ToolCalls: 1, QueryRows: 10,
			EvidenceBytes: 1_024, DelegationDepth: 1, Fanout: 1, Concurrency: 1}}
}

func cloneDAGLedger(value runbudget.Ledger) runbudget.Ledger {
	value.Reservations = append([]runbudget.ReservationRecord{}, value.Reservations...)
	return value
}

func dagDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func dagUUID(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
