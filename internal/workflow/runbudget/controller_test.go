package runbudget

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	testRun    = "0199a213-1111-7111-8111-111111111111"
	testTask   = "0199a213-2222-7222-8222-222222222222"
	testTask2  = "0199a213-3333-7333-8333-333333333333"
	testTask3  = "0199a213-7777-7777-8777-777777777777"
	testOrg    = "0199a213-4444-7444-8444-444444444444"
	testTenant = "0199a213-5555-7555-8555-555555555555"
	testCase   = "0199a213-6666-7666-8666-666666666666"
	testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var testNow = time.Date(2026, 8, 26, 18, 0, 0, 0, time.UTC)

type testClock struct{ now time.Time }

func (clock *testClock) Now() time.Time { return clock.now }

type memoryLedgerStore struct {
	mu                     sync.Mutex
	current                Ledger
	beginErrorAfterPersist bool
	saveErrorAfterPersist  bool
	loadError              error
}

func (store *memoryLedgerStore) Load(_ context.Context, scope domain.CaseRef,
	runID string) (Ledger, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadError != nil {
		return Ledger{}, false, store.loadError
	}
	if store.current.RunID == "" {
		return Ledger{}, false, nil
	}
	if store.current.RunID != runID || store.current.Case != scope {
		return Ledger{}, false, newError(Denied, "store_scope_mismatch", false, nil)
	}
	return cloneLedger(store.current), true, nil
}

func (store *memoryLedgerStore) Begin(_ context.Context, _ string,
	candidate Ledger) (Ledger, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current.RunID != "" {
		return cloneLedger(store.current), true, nil
	}
	store.current = cloneLedger(candidate)
	if store.beginErrorAfterPersist {
		store.beginErrorAfterPersist = false
		return Ledger{}, false, errors.New("commit response lost")
	}
	return cloneLedger(candidate), false, nil
}

func (store *memoryLedgerStore) Save(_ context.Context, _ string, prior,
	next Ledger) (Ledger, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if prior.Revision != store.current.Revision || prior.ProvenanceDigest != store.current.ProvenanceDigest {
		return Ledger{}, newError(Conflict, "store_revision_conflict", true, nil)
	}
	store.current = cloneLedger(next)
	if store.saveErrorAfterPersist {
		store.saveErrorAfterPersist = false
		return Ledger{}, errors.New("commit response lost")
	}
	return cloneLedger(next), nil
}

func TestReserveSettleReplayAndRestartPreserveWorstCaseCharge(t *testing.T) {
	store := &memoryLedgerStore{}
	clock := &testClock{now: testNow}
	controller := newTestController(t, store, clock)
	request := validReservation(testTask)
	reservation, err := controller.Reserve(context.Background(), request)
	if err != nil || reservation.Replayed || store.current.ActiveConcurrency != 1 ||
		store.current.Charged.Tokens != request.Claim.Tokens || len(store.current.Reservations) != 1 {
		t.Fatalf("reservation=%+v ledger=%+v err=%v", reservation, store.current, err)
	}
	actual := request.Claim
	actual.Tokens /= 2
	settled, err := controller.Settle(context.Background(), SettlementRequest{IdempotencyKey: "settle-one",
		RunID: testRun, TaskID: testTask, Case: testScope(), ReservationDigest: reservation.ReservationDigest,
		Actual: &actual, Outcome: "succeeded"})
	if err != nil || settled.Replayed || store.current.ActiveConcurrency != 0 ||
		store.current.Charged.Tokens != request.Claim.Tokens || store.current.Reservations[0].Actual != actual {
		t.Fatalf("settlement=%+v ledger=%+v err=%v", settled, store.current, err)
	}
	restarted := newTestController(t, store, clock)
	replayed, err := restarted.Reserve(context.Background(), request)
	if err != nil || !replayed.Replayed || replayed.ReservationDigest != reservation.ReservationDigest {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}
	replayedSettlement, err := restarted.Settle(context.Background(), SettlementRequest{IdempotencyKey: "settle-one",
		RunID: testRun, TaskID: testTask, Case: testScope(), ReservationDigest: reservation.ReservationDigest,
		Actual: &actual, Outcome: "succeeded"})
	if err != nil || !replayedSettlement.Replayed {
		t.Fatalf("settlement replay=%+v err=%v", replayedSettlement, err)
	}
	if _, err := restarted.Settle(context.Background(), SettlementRequest{IdempotencyKey: "changed-settlement-key",
		RunID: testRun, TaskID: testTask, Case: testScope(), ReservationDigest: reservation.ReservationDigest,
		Actual: &actual, Outcome: "succeeded"}); ErrorCode(err) != Denied ||
		ErrorReason(err) != "budget_settlement_replay_binding" {
		t.Fatalf("changed settlement replay err=%v", err)
	}
}

func TestConcurrentReservationsNeverExceedConcurrency(t *testing.T) {
	store := &memoryLedgerStore{}
	clock := &testClock{now: testNow}
	controller := newTestController(t, store, clock)
	requests := []ReservationRequest{validReservation(testTask), validReservation(testTask2)}
	requests[0].Plan.Limits.Concurrency, requests[0].TaskLimits.Concurrency = 1, 1
	requests[1].Plan = requests[0].Plan
	requests[1].TaskLimits = requests[0].TaskLimits
	requests[1].IdempotencyKey = "reserve-concurrent-two"

	start := make(chan struct{})
	type result struct{ err error }
	results := make(chan result, len(requests))
	for _, request := range requests {
		request := request
		go func() {
			<-start
			_, err := controller.Reserve(context.Background(), request)
			results <- result{err: err}
		}()
	}
	close(start)
	succeeded, denied := 0, 0
	for range requests {
		result := <-results
		switch {
		case result.err == nil:
			succeeded++
		case ErrorCode(result.err) == Denied && ErrorReason(result.err) == "budget_concurrency_exhausted":
			denied++
		default:
			t.Fatalf("unexpected concurrent result: %v", result.err)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if succeeded != 1 || denied != 1 || store.current.ActiveConcurrency != 1 || len(store.current.Reservations) != 1 {
		t.Fatalf("succeeded=%d denied=%d active=%d reservations=%d", succeeded, denied,
			store.current.ActiveConcurrency, len(store.current.Reservations))
	}
}

func TestEveryCumulativeDimensionDeniesBeforeSecondTask(t *testing.T) {
	tests := []struct {
		name, reason string
		setLimit     func(*Vector)
		setClaim     func(*Vector)
	}{
		{"tokens", "budget_tokens_exhausted", func(v *Vector) { v.Tokens = 10 }, func(v *Vector) { v.Tokens = 6 }},
		{"cost", "budget_cost_exhausted", func(v *Vector) { v.CostMicros = 10 }, func(v *Vector) { v.CostMicros = 6 }},
		{"tool_calls", "budget_tool_calls_exhausted", func(v *Vector) { v.ToolCalls = 1 }, func(v *Vector) { v.ToolCalls = 1 }},
		{"query_rows", "budget_query_rows_exhausted", func(v *Vector) { v.QueryRows = 10 }, func(v *Vector) { v.QueryRows = 6 }},
		{"evidence_bytes", "budget_evidence_bytes_exhausted", func(v *Vector) { v.EvidenceBytes = 10 }, func(v *Vector) { v.EvidenceBytes = 6 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &memoryLedgerStore{}
			controller := newTestController(t, store, &testClock{now: testNow})
			first := validReservation(testTask)
			test.setLimit(&first.Plan.Limits)
			first.TaskLimits = first.Plan.Limits
			test.setClaim(&first.Claim)
			if _, err := controller.Reserve(context.Background(), first); err != nil {
				t.Fatal(err)
			}
			second := first
			second.IdempotencyKey, second.TaskID, second.ParentTaskID, second.Plan = "reserve-two", testTask2, "", nil
			if _, err := controller.Reserve(context.Background(), second); ErrorCode(err) != Denied || ErrorReason(err) != test.reason {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestElapsedDepthFanoutAndConcurrencyDenyBeforeScheduling(t *testing.T) {
	store := &memoryLedgerStore{}
	clock := &testClock{now: testNow}
	controller := newTestController(t, store, clock)
	first := validReservation(testTask)
	first.Plan.Limits.Concurrency = 1
	first.TaskLimits.Concurrency = 1
	if _, err := controller.Reserve(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.IdempotencyKey, second.TaskID, second.ParentTaskID, second.Plan = "reserve-two", testTask2, "", nil
	if _, err := controller.Reserve(context.Background(), second); ErrorCode(err) != Denied ||
		ErrorReason(err) != "budget_concurrency_exhausted" {
		t.Fatalf("concurrency err=%v", err)
	}

	if _, err := controller.Settle(context.Background(), SettlementRequest{IdempotencyKey: "settle-root",
		RunID: testRun, TaskID: testTask, Case: testScope(),
		ReservationDigest: store.current.Reservations[0].ReservationDigest, Outcome: "succeeded"}); err != nil {
		t.Fatal(err)
	}
	depth := second
	depth.IdempotencyKey, depth.ParentTaskID, depth.Claim.DelegationDepth = "depth", testTask, 2
	if _, err := controller.Reserve(context.Background(), depth); ErrorCode(err) != Denied ||
		ErrorReason(err) != "budget_delegation_depth_invalid" {
		t.Fatalf("depth err=%v", err)
	}
	child := second
	child.IdempotencyKey, child.ParentTaskID, child.Claim.DelegationDepth = "child-one", testTask, 1
	if _, err := controller.Reserve(context.Background(), child); err != nil {
		t.Fatal(err)
	}
	secondChild := child
	secondChild.IdempotencyKey, secondChild.TaskID = "child-two", testTask3
	if _, err := controller.Reserve(context.Background(), secondChild); ErrorCode(err) != Denied ||
		ErrorReason(err) != "budget_fanout_exhausted" {
		t.Fatalf("fanout err=%v", err)
	}
	clock.now = first.Plan.ExpiresAt
	second.TaskID = "0199a213-8888-7888-8888-888888888888"
	second.IdempotencyKey = "elapsed"
	second.Deadline = clock.now.Add(time.Minute)
	if _, err := controller.Reserve(context.Background(), second); ErrorCode(err) != Denied ||
		ErrorReason(err) != "budget_elapsed_exhausted" {
		t.Fatalf("elapsed err=%v", err)
	}
}

func TestTamperScopeReplayOverflowAndActualOverrunFailClosed(t *testing.T) {
	store := &memoryLedgerStore{}
	controller := newTestController(t, store, &testClock{now: testNow})
	request := validReservation(testTask)
	reservation, err := controller.Reserve(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}

	tampered := request
	tampered.Claim.Tokens++
	if _, err := controller.Reserve(context.Background(), tampered); ErrorCode(err) != Denied ||
		ErrorReason(err) != "budget_task_replay_binding" {
		t.Fatalf("tamper err=%v", err)
	}
	scopeDrift := request
	scopeDrift.Case.CaseID = "0199a213-8888-7888-8888-888888888888"
	scopeDrift.Plan = nil
	if _, err := controller.Reserve(context.Background(), scopeDrift); ErrorCode(err) != Denied {
		t.Fatalf("scope err=%v", err)
	}
	overrun := request.Claim
	overrun.Tokens++
	if _, err := controller.Settle(context.Background(), SettlementRequest{IdempotencyKey: "overrun",
		RunID: testRun, TaskID: testTask, Case: testScope(), ReservationDigest: reservation.ReservationDigest,
		Actual: &overrun, Outcome: "succeeded"}); ErrorCode(err) != Denied {
		t.Fatalf("overrun err=%v", err)
	}

	store.current.Charged.Tokens++
	second := request
	second.IdempotencyKey, second.TaskID, second.Plan = "corrupt", testTask2, nil
	if _, err := controller.Reserve(context.Background(), second); ErrorCode(err) != Denied ||
		ErrorReason(err) != "budget_ledger_totals_invalid" {
		t.Fatalf("corrupt err=%v", err)
	}

	invalid := validReservation(testTask)
	invalid.Plan.Limits.Tokens = ^uint64(0)
	if _, err := newTestController(t, &memoryLedgerStore{}, &testClock{now: testNow}).Reserve(context.Background(), invalid); ErrorCode(err) != InvalidInput {
		t.Fatalf("overflow err=%v", err)
	}
	invalid = validReservation(testTask)
	invalid.IdempotencyKey = "bad\nkey"
	if _, err := newTestController(t, &memoryLedgerStore{}, &testClock{now: testNow}).Reserve(context.Background(), invalid); ErrorCode(err) != InvalidInput {
		t.Fatalf("opaque identity err=%v", err)
	}
}

func TestCrashRecoveryAndContextOutcomesRemainTyped(t *testing.T) {
	store := &memoryLedgerStore{beginErrorAfterPersist: true}
	clock := &testClock{now: testNow}
	request := validReservation(testTask)
	controller := newTestController(t, store, clock)
	if _, err := controller.Reserve(context.Background(), request); ErrorCode(err) != Unavailable {
		t.Fatalf("lost begin err=%v", err)
	}
	restarted := newTestController(t, store, clock)
	reservation, err := restarted.Reserve(context.Background(), request)
	if err != nil || !reservation.Replayed {
		t.Fatalf("restart reservation=%+v err=%v", reservation, err)
	}
	store.saveErrorAfterPersist = true
	settlementRequest := SettlementRequest{IdempotencyKey: "settle", RunID: testRun, TaskID: testTask,
		Case: testScope(), ReservationDigest: reservation.ReservationDigest, Outcome: "canceled"}
	if _, err := restarted.Settle(context.Background(), settlementRequest); ErrorCode(err) != Unavailable {
		t.Fatalf("lost settle err=%v", err)
	}
	settled, err := newTestController(t, store, clock).Settle(context.Background(), settlementRequest)
	if err != nil || !settled.Replayed || store.current.ActiveConcurrency != 0 {
		t.Fatalf("restart settlement=%+v err=%v", settled, err)
	}

	for name, makeContext := range map[string]func() context.Context{
		"canceled": func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx
		},
		"timeout": func() context.Context {
			ctx, cancel := context.WithDeadline(context.Background(), testNow.Add(-time.Second))
			cancel()
			return ctx
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := restarted.Reserve(makeContext(), request)
			if name == "canceled" && ErrorCode(err) != Canceled || name == "timeout" && ErrorCode(err) != Timeout {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func validReservation(taskID string) ReservationRequest {
	limits := Vector{Tokens: 100, CostMicros: 1000, WallTimeNanoseconds: uint64(time.Hour), ToolCalls: 10,
		QueryRows: 1000, EvidenceBytes: 1_000_000, DelegationDepth: 4, Fanout: 8, Concurrency: 2}
	return ReservationRequest{IdempotencyKey: "reserve-one", RunID: testRun, TaskID: taskID,
		Case: testScope(), Activity: "planning", PolicyDigest: testDigest, ProviderRoute: "ollama.local",
		Deadline: testNow.Add(5 * time.Minute), Plan: &Plan{SchemaVersion: SchemaVersion,
			ContractVersion: ContractVersion, RunID: testRun, Case: testScope(), PolicyDigest: testDigest,
			ProviderRoute: "ollama.local", Limits: limits, CreatedAt: testNow.Add(-time.Minute),
			ExpiresAt: testNow.Add(time.Hour)}, TaskLimits: limits,
		Claim: Vector{Tokens: 10, CostMicros: 100, WallTimeNanoseconds: uint64(10 * time.Minute), ToolCalls: 1,
			QueryRows: 100, EvidenceBytes: 1000, DelegationDepth: 0, Fanout: 1, Concurrency: 1}}
}

func testScope() domain.CaseRef {
	return domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase}
}

func newTestController(t *testing.T, store Store, clock Clock) *Controller {
	t.Helper()
	controller, err := New(store, clock)
	if err != nil {
		t.Fatal(err)
	}
	return controller
}
