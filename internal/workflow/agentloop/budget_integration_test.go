package agentloop

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/runbudget"
)

type loopBudgetStore struct {
	mu      sync.Mutex
	current runbudget.Ledger
}

func (store *loopBudgetStore) Load(_ context.Context, scope domain.CaseRef,
	runID string) (runbudget.Ledger, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current.RunID == "" {
		return runbudget.Ledger{}, false, nil
	}
	if store.current.RunID != runID || store.current.Case != scope {
		return runbudget.Ledger{}, false, errors.New("budget scope mismatch")
	}
	return copyBudgetLedger(store.current), true, nil
}

func (store *loopBudgetStore) Begin(_ context.Context, _ string,
	next runbudget.Ledger) (runbudget.Ledger, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current.RunID != "" {
		return copyBudgetLedger(store.current), true, nil
	}
	store.current = copyBudgetLedger(next)
	return copyBudgetLedger(next), false, nil
}

func (store *loopBudgetStore) Save(_ context.Context, _ string, prior,
	next runbudget.Ledger) (runbudget.Ledger, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if prior.Revision != store.current.Revision || prior.ProvenanceDigest != store.current.ProvenanceDigest {
		return runbudget.Ledger{}, errors.New("budget revision conflict")
	}
	store.current = copyBudgetLedger(next)
	return copyBudgetLedger(next), nil
}

func TestAgentLoopChargesBeforeSchedulingAndSettlesBeforeSuccessor(t *testing.T) {
	loop, state, model, action, budgetStore := newBudgetedTestLoop(t)
	start := budgetedStartRequest(t, 20)
	started, err := loop.Start(context.Background(), start)
	if err != nil || state.createCalls != 1 || budgetStore.current.Charged.Tokens != 10 ||
		budgetStore.current.ActiveConcurrency != 1 || started.Step.BudgetReservationDigest == "" {
		t.Fatalf("started=%+v budget=%+v err=%v", started, budgetStore.current, err)
	}
	planned, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan-budgeted",
		Case: testScope(), RunID: testRun, StepID: testPlanStep})
	if err != nil || model.calls != 1 || planned.Step.BudgetSettlementDigest == "" ||
		budgetStore.current.ActiveConcurrency != 0 {
		t.Fatalf("planned=%+v budget=%+v calls=%d err=%v", planned, budgetStore.current, model.calls, err)
	}
	_, intentDigest := testIntent(t)
	exhausted := scheduleBudgetRequest(t, intentDigest, 11, "schedule-exhausted")
	if _, err := loop.Schedule(context.Background(), exhausted); Code(err) != Denied ||
		Reason(err) != "budget_tokens_exhausted" || state.current.Step.StepID != testPlanStep ||
		len(budgetStore.current.Reservations) != 1 {
		t.Fatalf("state=%+v budget=%+v err=%v", state.current, budgetStore.current, err)
	}
	allowed := scheduleBudgetRequest(t, intentDigest, 10, "schedule-allowed")
	scheduled, err := loop.Schedule(context.Background(), allowed)
	if err != nil || scheduled.Step.StepID != testActionStep || budgetStore.current.Charged.Tokens != 20 ||
		budgetStore.current.ActiveConcurrency != 1 {
		t.Fatalf("scheduled=%+v budget=%+v err=%v", scheduled, budgetStore.current, err)
	}
	replayed, err := loop.Schedule(context.Background(), allowed)
	if err != nil || !replayed.Replayed || replayed.Step.BudgetReservationDigest != scheduled.Step.BudgetReservationDigest ||
		budgetStore.current.Charged.Tokens != 20 || len(budgetStore.current.Reservations) != 2 {
		t.Fatalf("replayed=%+v budget=%+v err=%v", replayed, budgetStore.current, err)
	}
	changed := allowed
	changed.BudgetClaim.CostMicros++
	if _, err := loop.Schedule(context.Background(), changed); Code(err) != Denied ||
		Reason(err) != "budget_task_replay_binding" {
		t.Fatalf("changed schedule replay err=%v", err)
	}
	intent, _ := testIntent(t)
	action.receipt = domain.ActionReceipt{IntentDigest: intentDigest, Outcome: "succeeded",
		Evidence: domain.ArtifactRef{Digest: testDigestThree, MediaType: "application/json", Classification: "internal", Length: 1}}
	acted, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "action-budgeted",
		Case: testScope(), RunID: testRun, StepID: testActionStep, Intent: &intent})
	if err != nil || acted.Step.BudgetSettlementDigest == "" || action.calls != 1 ||
		budgetStore.current.ActiveConcurrency != 0 || len(budgetStore.current.Reservations) != 2 {
		t.Fatalf("acted=%+v budget=%+v calls=%d err=%v", acted, budgetStore.current, action.calls, err)
	}
}

func TestBudgetSettlementBindingRecoversWithoutRepeatingActivity(t *testing.T) {
	loop, state, model, _, budgetStore := newBudgetedTestLoop(t)
	if _, err := loop.Start(context.Background(), budgetedStartRequest(t, 20)); err != nil {
		t.Fatal(err)
	}
	state.failSave = 3
	if _, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan-crash",
		Case: testScope(), RunID: testRun, StepID: testPlanStep}); Code(err) != Unavailable ||
		model.calls != 1 || state.current.Step.Status != StepSucceeded ||
		state.current.Step.BudgetSettlementDigest != "" || budgetStore.current.ActiveConcurrency != 0 {
		t.Fatalf("state=%+v budget=%+v calls=%d err=%v", state.current, budgetStore.current, model.calls, err)
	}
	recovered, err := loop.Resume(context.Background(), ResumeRequest{IdempotencyKey: "resume-budget",
		Case: testScope(), RunID: testRun})
	if err != nil || recovered.Step.BudgetSettlementDigest == "" || model.calls != 1 ||
		budgetStore.current.ActiveConcurrency != 0 {
		t.Fatalf("recovered=%+v budget=%+v calls=%d err=%v", recovered, budgetStore.current, model.calls, err)
	}
}

func TestInitialBudgetDenialCreatesNoWorkflowState(t *testing.T) {
	loop, state, model, _, _ := newBudgetedTestLoop(t)
	request := budgetedStartRequest(t, 5)
	if _, err := loop.Start(context.Background(), request); Code(err) != InvalidInput ||
		state.createCalls != 0 || model.calls != 0 {
		t.Fatalf("state=%+v creates=%d calls=%d err=%v", state.current, state.createCalls, model.calls, err)
	}
}

func newBudgetedTestLoop(t *testing.T) (*Loop, *memoryStore, *modelStub, *actionStub, *loopBudgetStore) {
	t.Helper()
	state := &memoryStore{}
	model := &modelStub{store: state, ref: domain.ArtifactRef{Digest: testDigestTwo,
		MediaType: "application/json", Classification: "internal", Length: 12}}
	action := &actionStub{store: state}
	clock := &fixedClock{value: mustTime(t, "2026-08-26T16:10:00.000000000Z")}
	budgetStore := &loopBudgetStore{}
	budgets, err := runbudget.New(budgetStore, clock)
	if err != nil {
		t.Fatal(err)
	}
	loop, err := New(state, model, action, budgets, clock)
	if err != nil {
		t.Fatal(err)
	}
	return loop, state, model, action, budgetStore
}

func budgetedStartRequest(t *testing.T, tokenLimit uint64) StartRequest {
	t.Helper()
	limits := budgetLimits(tokenLimit)
	return StartRequest{IdempotencyKey: "start-budgeted", RunID: testRun, StepID: testPlanStep,
		Case: testScope(), ActorID: testActor, PolicyDigest: testDigestOne, ProviderRoute: "connected",
		Activity: PlanningActivity, InputRefs: []string{testDigestOne},
		Deadline: mustTime(t, "2026-08-26T17:00:00.000000000Z"),
		BudgetPlan: &runbudget.Plan{SchemaVersion: runbudget.SchemaVersion,
			ContractVersion: runbudget.ContractVersion, RunID: testRun, Case: testScope(),
			PolicyDigest: testDigestOne, ProviderRoute: "connected", Limits: limits,
			CreatedAt: mustTime(t, "2026-08-26T16:00:00.000000000Z"),
			ExpiresAt: mustTime(t, "2026-08-26T17:10:00.000000000Z")},
		TaskBudget: limits, BudgetClaim: budgetClaim(10)}
}

func scheduleBudgetRequest(t *testing.T, intentDigest string, tokens uint64,
	idempotency string) ScheduleRequest {
	t.Helper()
	return ScheduleRequest{IdempotencyKey: idempotency, Case: testScope(), RunID: testRun,
		StepID: testActionStep, Activity: AuthorizedActionActivity, InputRefs: []string{testDigestTwo},
		IntentDigest: intentDigest, Deadline: mustTime(t, "2026-08-26T17:00:00.000000000Z"),
		TaskBudget: budgetLimits(20), BudgetClaim: budgetClaim(tokens)}
}

func budgetLimits(tokens uint64) runbudget.Vector {
	return runbudget.Vector{Tokens: tokens, CostMicros: 1000, WallTimeNanoseconds: uint64(time.Hour),
		ToolCalls: 10, QueryRows: 1000, EvidenceBytes: 1_000_000, DelegationDepth: 4, Fanout: 8, Concurrency: 1}
}

func budgetClaim(tokens uint64) runbudget.Vector {
	return runbudget.Vector{Tokens: tokens, CostMicros: 10, WallTimeNanoseconds: uint64(time.Hour),
		ToolCalls: 1, QueryRows: 1, EvidenceBytes: 1, DelegationDepth: 0, Fanout: 1, Concurrency: 1}
}

func copyBudgetLedger(value runbudget.Ledger) runbudget.Ledger {
	value.Reservations = append([]runbudget.ReservationRecord{}, value.Reservations...)
	return value
}
