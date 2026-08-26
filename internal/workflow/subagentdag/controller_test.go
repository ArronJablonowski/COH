package subagentdag

import (
	"context"
	"sort"
	"sync"
	"testing"

	"github.com/ArronJablonowski/COH/internal/workflow/runbudget"
)

type concurrentBudget struct {
	mu           sync.Mutex
	planDigest   string
	reservations map[string]runbudget.Reservation
	arrived      chan struct{}
	release      chan struct{}
	settles      int
}

func (budget *concurrentBudget) Reserve(_ context.Context, request runbudget.ReservationRequest) (runbudget.Reservation, error) {
	budget.mu.Lock()
	if request.Plan != nil {
		canonical, err := runbudget.CanonicalPlan(*request.Plan)
		if err != nil {
			budget.mu.Unlock()
			return runbudget.Reservation{}, err
		}
		budget.planDigest = testDigest(string(canonical))
	}
	if existing, found := budget.reservations[request.TaskID]; found {
		budget.mu.Unlock()
		existing.Replayed = true
		return existing, nil
	}
	value := runbudget.Reservation{ReservationDigest: testDigest("reservation-" + request.TaskID),
		PlanDigest: budget.planDigest, ClaimDigest: testDigest("claim-" + request.TaskID),
		LedgerDigest: testDigest("ledger-" + request.TaskID)}
	budget.reservations[request.TaskID] = value
	child := request.Plan == nil
	budget.mu.Unlock()
	if child {
		budget.arrived <- struct{}{}
		<-budget.release
	}
	return value, nil
}

func (budget *concurrentBudget) Settle(_ context.Context, request runbudget.SettlementRequest) (runbudget.Settlement, error) {
	budget.mu.Lock()
	defer budget.mu.Unlock()
	budget.settles++
	return runbudget.Settlement{ReservationDigest: request.ReservationDigest,
		SettlementDigest: testDigest("settlement-" + request.TaskID), LedgerDigest: testDigest("ledger-settled")}, nil
}

func TestCreateAndExactReplayBindAuthorityBudgetAndDurableGraph(t *testing.T) {
	controller, _, authority, budgets, _ := newFixture(t)
	request := createRequest()
	first, err := controller.Create(context.Background(), request)
	if err != nil || first.Replayed || first.Task.Role != CoordinatorRole || first.Task.Status != TaskPending {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	replay, err := controller.Create(context.Background(), request)
	if err != nil || !replay.Replayed || replay.Graph.ProvenanceDigest != first.Graph.ProvenanceDigest {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	if authority.calls != 2 || budgets.calls != 2 || authority.last.Operation != CreateGraph || authority.last.Role != CoordinatorRole {
		t.Fatalf("authority=%+v calls=%d budget=%d", authority.last, authority.calls, budgets.calls)
	}
}

func TestEverySpecializedRoleDelegatesAsOneBoundedChild(t *testing.T) {
	roles := []Role{AlertTriageRole, SIEMQueryRole, TimelineCorrelationRole, HuntingRole, CTIAttackRole,
		DetectionRole, VulnerabilityRole, ValidationRole, IRPlannerRole, ReviewerRole, ReportWriterRole}
	controller, _, authority, _, _ := newFixture(t)
	if _, err := controller.Create(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		request := delegateRequest(string(role), role, testRoot)
		result, err := controller.Delegate(context.Background(), request)
		if err != nil || result.Task.Role != role || result.Task.Depth != 1 || result.Task.Status != TaskPending ||
			authority.last.Role != role || authority.last.ParentTaskIDs[0] != testRoot {
			t.Fatalf("role=%s result=%+v authority=%+v err=%v", role, result, authority.last, err)
		}
	}
	if authority.calls != len(roles)+1 {
		t.Fatalf("authority calls=%d", authority.calls)
	}
}

func TestMultiParentDAGDepthFanoutAndChangedReplayFailClosed(t *testing.T) {
	controller, _, _, _, store := newFixture(t)
	if _, err := controller.Create(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	left := delegateRequest("left", HuntingRole, testRoot)
	right := delegateRequest("right", CTIAttackRole, testRoot)
	if _, err := controller.Delegate(context.Background(), left); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Delegate(context.Background(), right); err != nil {
		t.Fatal(err)
	}
	parents := []string{left.TaskID, right.TaskID}
	sort.Strings(parents)
	joined := delegateRequest("joined", ReviewerRole, parents...)
	result, err := controller.Delegate(context.Background(), joined)
	if err != nil || result.Task.Depth != 2 || len(result.Task.ParentTaskIDs) != 2 || len(result.Graph.Edges) != 4 {
		t.Fatalf("joined=%+v err=%v", result, err)
	}
	changed := joined
	changed.Role = ReportWriterRole
	if _, err = controller.Delegate(context.Background(), changed); CodeOf(err) != Denied {
		t.Fatalf("changed replay=%v", err)
	}
	store.mu.Lock()
	store.current.Limits.MaximumFanout = 1
	store.current.ProvenanceDigest, _ = graphProvenanceDigest(store.current)
	store.mu.Unlock()
	if _, err = controller.Delegate(context.Background(), delegateRequest("overflow", DetectionRole, testRoot)); CodeOf(err) != Denied {
		t.Fatalf("fanout err=%v", err)
	}
}

func TestPolicyDenialCreatesNoBudgetOrGraph(t *testing.T) {
	controller, _, authority, budgets, store := newFixture(t)
	authority.allow = false
	if _, err := controller.Create(context.Background(), createRequest()); CodeOf(err) != Denied || Reason(err) != "policy_denied" {
		t.Fatalf("err=%v", err)
	}
	if budgets.calls != 0 || store.found {
		t.Fatalf("budget=%d stored=%v", budgets.calls, store.found)
	}
}

func TestDelegationDenialAndMissingParentCreateNoReservation(t *testing.T) {
	controller, _, authority, budgets, store := newFixture(t)
	if _, err := controller.Create(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	budgetCalls := budgets.calls
	colliding := delegateRequest("colliding-idempotency", HuntingRole, testRoot)
	colliding.IdempotencyKey = createRequest().IdempotencyKey
	if _, err := controller.Delegate(context.Background(), colliding); CodeOf(err) != Denied ||
		Reason(err) != "changed_replay" || budgets.calls != budgetCalls {
		t.Fatalf("cross-operation replay err=%v budget calls=%d", err, budgets.calls)
	}
	authority.allow = false
	request := delegateRequest("unauthorized", HuntingRole, testRoot)
	if _, err := controller.Delegate(context.Background(), request); CodeOf(err) != Denied ||
		Reason(err) != "policy_denied" || budgets.calls != budgetCalls {
		t.Fatalf("unauthorized err=%v budget calls=%d", err, budgets.calls)
	}
	authority.allow = true
	request = delegateRequest("missing-parent", HuntingRole, testUUID("foreign-parent"))
	if _, err := controller.Delegate(context.Background(), request); CodeOf(err) != Denied ||
		Reason(err) != "parent_invalid" || budgets.calls != budgetCalls {
		t.Fatalf("missing parent err=%v budget calls=%d", err, budgets.calls)
	}
	stored, found, err := store.Load(context.Background(), createRequest().Case, testGraph)
	if err != nil || !found || len(stored.Tasks) != 1 {
		t.Fatalf("stored=%+v found=%v err=%v", stored, found, err)
	}
}

func TestDepthFanoutConcurrencyAndCycleBoundsFailClosed(t *testing.T) {
	controller, _, _, budgets, _ := newFixture(t)
	create := createRequest()
	create.Limits = Limits{MaximumDepth: 1, MaximumFanout: 1, MaximumConcurrency: 2, MaximumTasks: 3}
	if _, err := controller.Create(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	child := delegateRequest("bounded-child", HuntingRole, testRoot)
	childResult, err := controller.Delegate(context.Background(), child)
	if err != nil {
		t.Fatal(err)
	}
	budgetCalls := budgets.calls
	if _, err = controller.Delegate(context.Background(), delegateRequest("concurrency-overflow", SIEMQueryRole, testRoot)); CodeOf(err) != Denied || Reason(err) != "graph_capacity_exhausted" || budgets.calls != budgetCalls {
		t.Fatalf("concurrency err=%v budget calls=%d", err, budgets.calls)
	}
	controller.runtime = &executionRuntime{result: validResult(child.TaskID, child.Role)}
	executed, err := controller.Execute(context.Background(), executeRequest(child.TaskID, "execute-bounded-child"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = controller.Delegate(context.Background(), delegateRequest("fanout-overflow", SIEMQueryRole, testRoot)); CodeOf(err) != Denied || Reason(err) != "graph_fanout_exhausted" {
		t.Fatalf("fanout err=%v", err)
	}
	grandchild := delegateRequest("depth-overflow", ReviewerRole, child.TaskID)
	grandchild.BudgetClaim.DelegationDepth = 2
	if _, err = controller.Delegate(context.Background(), grandchild); CodeOf(err) != Denied ||
		Reason(err) != "graph_depth_exhausted" {
		t.Fatalf("depth err=%v", err)
	}
	cycle := cloneGraph(executed.Graph)
	cycle.Edges = append(cycle.Edges, Edge{ParentTaskID: child.TaskID, ChildTaskID: testRoot})
	sort.Slice(cycle.Edges, func(i, j int) bool {
		return cycle.Edges[i].ParentTaskID+"\x00"+cycle.Edges[i].ChildTaskID <
			cycle.Edges[j].ParentTaskID+"\x00"+cycle.Edges[j].ChildTaskID
	})
	cycle.ProvenanceDigest = ""
	cycle.ProvenanceDigest, _ = graphProvenanceDigest(cycle)
	if err = validateGraph(cycle); CodeOf(err) != Denied {
		t.Fatalf("cycle accepted from graph=%+v child=%+v err=%v", childResult.Graph, childResult.Task, err)
	}
}

func TestInvalidRequestsFailBeforeAuthorityBudgetOrStorage(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CreateRequest)
	}{
		{name: "actor", mutate: func(request *CreateRequest) { request.ActorID = "invalid" }},
		{name: "deadline", mutate: func(request *CreateRequest) { request.Deadline = testNow }},
		{name: "role bounds", mutate: func(request *CreateRequest) { request.Limits.MaximumDepth = 33 }},
		{name: "budget bounds", mutate: func(request *CreateRequest) { request.BudgetPlan.Limits.Concurrency = 1 }},
		{name: "scope", mutate: func(request *CreateRequest) { request.Case.TenantID = testUUID("other-tenant") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			controller, _, authority, budgets, store := newFixture(t)
			request := createRequest()
			test.mutate(&request)
			if _, err := controller.Create(context.Background(), request); CodeOf(err) != InvalidInput ||
				authority.calls != 0 || budgets.calls != 0 || store.found {
				t.Fatalf("err=%v authority=%d budget=%d stored=%v", err, authority.calls, budgets.calls, store.found)
			}
		})
	}
}

func TestConcurrentDelegationConflictNeverRefundsUnpersistedReservation(t *testing.T) {
	clock := &testClock{testNow}
	authority := &authorityStub{clock: clock, allow: true}
	budget := &concurrentBudget{reservations: map[string]runbudget.Reservation{},
		arrived: make(chan struct{}, 2), release: make(chan struct{})}
	store := &memoryStore{}
	controller, err := New(store, authority, runtimeStub{}, cancelerStub{}, budget, clock)
	if err != nil {
		t.Fatal(err)
	}
	create := createRequest()
	create.Limits.MaximumConcurrency = 3
	if _, err = controller.Create(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	requests := []DelegateRequest{delegateRequest("concurrent-left", HuntingRole, testRoot),
		delegateRequest("concurrent-right", SIEMQueryRole, testRoot)}
	errorsByCall := make(chan error, 2)
	for _, request := range requests {
		request := request
		go func() {
			_, delegateErr := controller.Delegate(context.Background(), request)
			errorsByCall <- delegateErr
		}()
	}
	<-budget.arrived
	<-budget.arrived
	close(budget.release)
	successes, conflicts := 0, 0
	for range requests {
		err = <-errorsByCall
		if err == nil {
			successes++
		} else if CodeOf(err) == Conflict {
			conflicts++
		} else {
			t.Fatalf("unexpected delegation err=%v", err)
		}
	}
	budget.mu.Lock()
	settles := budget.settles
	budget.mu.Unlock()
	if successes != 1 || conflicts != 1 || settles != 0 {
		t.Fatalf("successes=%d conflicts=%d premature settlements=%d", successes, conflicts, settles)
	}
	stored, found, err := store.Load(context.Background(), create.Case, create.GraphID)
	if err != nil || !found || len(stored.Tasks) != 2 {
		t.Fatalf("stored=%+v found=%v err=%v", stored, found, err)
	}
	for _, request := range requests {
		if _, present := findTask(stored, request.TaskID); present {
			continue
		}
		if _, err = controller.Delegate(context.Background(), request); err != nil {
			t.Fatalf("exact retry of reserved child failed: %v", err)
		}
	}
	stored, found, err = store.Load(context.Background(), create.Case, create.GraphID)
	if err != nil || !found || len(stored.Tasks) != 3 {
		t.Fatalf("retried stored=%+v found=%v err=%v", stored, found, err)
	}
}
