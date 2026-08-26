package subagentdag

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/runbudget"
)

var testNow = time.Date(2026, 8, 26, 22, 30, 0, 0, time.UTC)

const (
	testOrg   = "0199a213-1001-7001-8001-000000000001"
	testTen   = "0199a213-1002-7002-8002-000000000002"
	testCase  = "0199a213-1003-7003-8003-000000000003"
	testActor = "0199a213-1004-7004-8004-000000000004"
	testGraph = "0199a213-1005-7005-8005-000000000005"
	testRun   = "0199a213-1006-7006-8006-000000000006"
	testRoot  = "0199a213-1007-7007-8007-000000000007"
)

type testClock struct{ now time.Time }

func (clock *testClock) Now() time.Time { return clock.now }

type authorityStub struct {
	mu    sync.Mutex
	clock *testClock
	allow bool
	calls int
	last  AuthorizationRequest
}

func (stub *authorityStub) AuthorizeDelegation(_ context.Context, request AuthorizationRequest) (Decision, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.calls++
	stub.last = request
	outcome, reason := "deny", "policy_denied"
	if stub.allow {
		outcome, reason = "allow", "delegation_allowed"
	}
	value := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID: testUUID("decision-" + string(request.Operation) + request.TaskID), IntentDigest: request.IntentDigest,
		Operation: request.Operation, GraphID: request.GraphID, TaskID: request.TaskID, Case: request.Case,
		ActorID: request.ActorID, ActorRevision: request.ActorRevision, PolicyDigest: request.PolicyDigest,
		RevocationDigest: testDigest("revocation"), Outcome: outcome, ReasonCode: reason,
		IssuedAt: stub.clock.now.Add(-time.Minute), ExpiresAt: stub.clock.now.Add(time.Minute), Revision: 1}
	value.DecisionDigest, _ = DecisionBindingDigest(value)
	return value, nil
}

type runtimeStub struct{}

func (runtimeStub) RunChild(context.Context, ExecutionRequest) (StructuredResult, error) {
	return StructuredResult{}, errors.New("unused")
}

type cancelerStub struct{}

func (cancelerStub) CancelChild(context.Context, ExecutionRequest, string) (CancellationAck, error) {
	return CancellationAck{}, errors.New("unused")
}

type budgetStub struct {
	mu           sync.Mutex
	planDigest   string
	reservations map[string]runbudget.Reservation
	calls        int
	settles      int
}

func (stub *budgetStub) Reserve(_ context.Context, request runbudget.ReservationRequest) (runbudget.Reservation, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.calls++
	if existing, found := stub.reservations[request.TaskID]; found {
		existing.Replayed = true
		return existing, nil
	}
	if request.Plan != nil {
		canonical, err := runbudget.CanonicalPlan(*request.Plan)
		if err != nil {
			return runbudget.Reservation{}, err
		}
		stub.planDigest = testDigest(string(canonical))
	}
	value := runbudget.Reservation{ReservationDigest: testDigest("reservation-" + request.TaskID),
		PlanDigest: stub.planDigest, ClaimDigest: testDigest("claim-" + request.TaskID),
		LedgerDigest: testDigest("ledger-" + request.TaskID)}
	stub.reservations[request.TaskID] = value
	return value, nil
}
func (stub *budgetStub) Settle(_ context.Context, request runbudget.SettlementRequest) (runbudget.Settlement, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.settles++
	return runbudget.Settlement{ReservationDigest: request.ReservationDigest,
		SettlementDigest: testDigest("settlement-" + request.TaskID), LedgerDigest: testDigest("settled-ledger")}, nil
}

type memoryStore struct {
	mu      sync.Mutex
	current Graph
	found   bool
}

func (store *memoryStore) Load(_ context.Context, scope domain.CaseRef, graphID string) (Graph, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.found || store.current.Case != scope || store.current.GraphID != graphID {
		return Graph{}, false, nil
	}
	return cloneGraph(store.current), true, nil
}
func (store *memoryStore) Begin(_ context.Context, _ string, value Graph) (Graph, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.found {
		return cloneGraph(store.current), true, nil
	}
	store.current, store.found = cloneGraph(value), true
	return cloneGraph(value), false, nil
}
func (store *memoryStore) Save(_ context.Context, _ string, prior, next Graph) (Graph, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.found || store.current.Revision != prior.Revision || store.current.ProvenanceDigest != prior.ProvenanceDigest {
		return Graph{}, false, newError(Conflict, "store_conflict", true, nil)
	}
	if store.current.Revision == next.Revision && reflect.DeepEqual(store.current, next) {
		return cloneGraph(store.current), true, nil
	}
	store.current = cloneGraph(next)
	return cloneGraph(next), false, nil
}

func newFixture(t interface{ Fatal(...any) }) (*Controller, *testClock, *authorityStub, *budgetStub, *memoryStore) {
	clock := &testClock{testNow}
	authority := &authorityStub{clock: clock, allow: true}
	budgets := &budgetStub{reservations: map[string]runbudget.Reservation{}}
	store := &memoryStore{}
	controller, err := New(store, authority, runtimeStub{}, cancelerStub{}, budgets, clock)
	if err != nil {
		t.Fatal(err)
	}
	return controller, clock, authority, budgets, store
}

func createRequest() CreateRequest {
	limits := runbudget.Vector{Tokens: 10000, CostMicros: 100000, WallTimeNanoseconds: uint64(time.Hour),
		ToolCalls: 10, QueryRows: 10000, EvidenceBytes: 1 << 20, DelegationDepth: 8, Fanout: 16, Concurrency: 16}
	return CreateRequest{RequestID: testUUID("create"), IdempotencyKey: "graph-create", GraphID: testGraph,
		RunID: testRun, RootTaskID: testRoot, Case: domain.CaseRef{OrganizationID: testOrg, TenantID: testTen, CaseID: testCase},
		ActorID: testActor, ActorRevision: 3, PolicyDigest: testDigest("policy"), ProviderRoute: "connected",
		Limits:    Limits{MaximumDepth: 8, MaximumFanout: 16, MaximumConcurrency: 16, MaximumTasks: 64},
		InputRefs: []string{testDigest("root-input")}, Deadline: testNow.Add(time.Hour),
		BudgetPlan: runbudget.Plan{SchemaVersion: runbudget.SchemaVersion, ContractVersion: runbudget.ContractVersion,
			RunID: testRun, Case: domain.CaseRef{OrganizationID: testOrg, TenantID: testTen, CaseID: testCase},
			PolicyDigest: testDigest("policy"), ProviderRoute: "connected", Limits: limits,
			CreatedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(2 * time.Hour)},
		TaskBudget: limits, BudgetClaim: runbudget.Vector{Tokens: 100, CostMicros: 10,
			WallTimeNanoseconds: uint64(time.Hour), DelegationDepth: 0, Fanout: 16, Concurrency: 1}}
}

func delegateRequest(name string, role Role, parents ...string) DelegateRequest {
	return DelegateRequest{RequestID: testUUID("request-" + name), IdempotencyKey: "delegate-" + name,
		GraphID: testGraph, TaskID: testUUID("task-" + name), ParentTaskIDs: append([]string{}, parents...),
		Case: domain.CaseRef{OrganizationID: testOrg, TenantID: testTen, CaseID: testCase}, ActorID: testActor,
		ActorRevision: 3, Role: role, InputRefs: []string{testDigest("input-" + name)},
		PolicyDigest: testDigest("policy"), Deadline: testNow.Add(30 * time.Minute),
		TaskBudget:  runbudget.Vector{Tokens: 1000, WallTimeNanoseconds: uint64(time.Hour), DelegationDepth: 8, Fanout: 16, Concurrency: 1},
		BudgetClaim: runbudget.Vector{Tokens: 10, WallTimeNanoseconds: uint64(30 * time.Minute), DelegationDepth: 1, Fanout: 1, Concurrency: 1}}
}

func testDigest(value string) string { return rawDigest([]byte(value)) }
func testUUID(value string) string {
	encoded := testDigest(value)[7:39]
	return encoded[:8] + "-" + encoded[8:12] + "-7" + encoded[13:16] + "-8" + encoded[17:20] + "-" + encoded[20:32]
}
