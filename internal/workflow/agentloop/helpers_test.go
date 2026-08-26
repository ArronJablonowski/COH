package agentloop

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/runbudget"
)

const (
	testOrganization = "0199a213-81c0-7800-8aa1-bbab2a035a70"
	testTenant       = "0199a213-81c0-7800-8aa1-bbab2a035a71"
	testCase         = "0199a213-81c0-7800-8aa1-bbab2a035a72"
	testActor        = "0199a213-81c0-7800-8aa1-bbab2a035a73"
	testRun          = "0199a213-81c0-7800-8aa1-bbab2a035a74"
	testPlanStep     = "0199a213-81c0-7800-8aa1-bbab2a035a75"
	testActionStep   = "0199a213-81c0-7800-8aa1-bbab2a035a76"
	testDigestOne    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testDigestTwo    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testDigestThree  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

type fixedClock struct{ value time.Time }

func (clock *fixedClock) Now() time.Time {
	value := clock.value
	clock.value = clock.value.Add(time.Nanosecond)
	return value
}

type memoryStore struct {
	mu          sync.Mutex
	current     Snapshot
	history     []Snapshot
	failSave    int
	failCreate  bool
	saveCalls   int
	createCalls int
}

func (store *memoryStore) Create(_ context.Context, _ string, next Snapshot) (Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.createCalls++
	if store.failCreate {
		return Snapshot{}, newError(Unavailable, "create", "injected_crash", true, nil)
	}
	if store.current.Run.RunID != "" {
		if store.current.Run.RunID == next.Run.RunID {
			result := cloneSnapshot(store.current)
			result.Replayed = true
			return result, nil
		}
		return Snapshot{}, newError(Conflict, "create", "already_exists", false, nil)
	}
	store.current = cloneSnapshot(next)
	store.history = append(store.history, cloneSnapshot(next))
	return cloneSnapshot(next), nil
}

func (store *memoryStore) Load(_ context.Context, scope domain.CaseRef, runID string) (Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current.Run.RunID != runID {
		return Snapshot{}, newError(NotFound, "load", "state_not_found", false, nil)
	}
	if store.current.Run.Case != scope {
		return Snapshot{}, newError(Denied, "load", "scope_mismatch", false, nil)
	}
	return cloneSnapshot(store.current), nil
}

func (store *memoryStore) Save(_ context.Context, _ string, prior, next Snapshot) (Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.saveCalls++
	if store.failSave == store.saveCalls {
		return Snapshot{}, newError(Unavailable, "save", "injected_crash", true, nil)
	}
	if prior.Run.Revision != store.current.Run.Revision || prior.Step.Revision != store.current.Step.Revision || prior.Step.StepID != store.current.Step.StepID {
		return Snapshot{}, newError(Conflict, "save", "revision_conflict", false, nil)
	}
	store.current = cloneSnapshot(next)
	store.history = append(store.history, cloneSnapshot(next))
	return cloneSnapshot(next), nil
}

type modelStub struct {
	store       *memoryStore
	calls       int
	err         error
	ref         domain.ArtifactRef
	lastRequest workflowbase.ModelRequest
}

func (model *modelStub) Invoke(ctx context.Context, request workflowbase.ModelRequest) (domain.ArtifactRef, error) {
	model.calls++
	model.lastRequest = request
	if model.store != nil && model.store.current.Step.Status != StepRunning {
		return domain.ArtifactRef{}, errors.New("planning exposed before durable running state")
	}
	if model.err != nil {
		return domain.ArtifactRef{}, model.err
	}
	select {
	case <-ctx.Done():
		return domain.ArtifactRef{}, ctx.Err()
	default:
		return model.ref, nil
	}
}

type blockingModel struct{ calls int }

func (model *blockingModel) Invoke(ctx context.Context, _ workflowbase.ModelRequest) (domain.ArtifactRef, error) {
	model.calls++
	<-ctx.Done()
	return domain.ArtifactRef{}, ctx.Err()
}

type actionStub struct {
	store   *memoryStore
	calls   int
	err     error
	receipt domain.ActionReceipt
}

type budgetStub struct {
	reserveCalls int
	settleCalls  int
	reserveErr   error
	settleErr    error
}

func (budget *budgetStub) Reserve(_ context.Context,
	_ runbudget.ReservationRequest) (runbudget.Reservation, error) {
	budget.reserveCalls++
	if budget.reserveErr != nil {
		return runbudget.Reservation{}, budget.reserveErr
	}
	return runbudget.Reservation{ReservationDigest: testDigestTwo, PlanDigest: testDigestThree,
		ClaimDigest: testDigestOne, LedgerDigest: testDigestThree}, nil
}

func (budget *budgetStub) Settle(_ context.Context,
	request runbudget.SettlementRequest) (runbudget.Settlement, error) {
	budget.settleCalls++
	if budget.settleErr != nil {
		return runbudget.Settlement{}, budget.settleErr
	}
	return runbudget.Settlement{ReservationDigest: request.ReservationDigest,
		SettlementDigest: testDigestOne, LedgerDigest: testDigestThree}, nil
}

func (action *actionStub) Submit(_ context.Context, _ domain.ToolIntent) (domain.ActionReceipt, error) {
	action.calls++
	if action.store != nil && action.store.current.Step.Status != StepDispatching {
		return domain.ActionReceipt{}, errors.New("action exposed before durable dispatch state")
	}
	return action.receipt, action.err
}

func newTestLoop(t *testing.T) (*Loop, *memoryStore, *modelStub, *actionStub, *fixedClock) {
	t.Helper()
	store := &memoryStore{}
	model := &modelStub{store: store, ref: domain.ArtifactRef{Digest: testDigestTwo, MediaType: "application/json", Classification: "internal", Length: 12}}
	action := &actionStub{store: store}
	clock := &fixedClock{value: mustTime(t, "2026-08-26T16:10:00.000000000Z")}
	loop, err := New(store, model, action, &budgetStub{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	return loop, store, model, action, clock
}

func startPlan(t *testing.T, loop *Loop) Snapshot {
	t.Helper()
	value, err := loop.Start(context.Background(), StartRequest{IdempotencyKey: "start-1", RunID: testRun, StepID: testPlanStep, Case: testScope(), ActorID: testActor, PolicyDigest: testDigestOne, ProviderRoute: "connected", Activity: PlanningActivity, InputRefs: []string{testDigestOne}, Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testIntent(t *testing.T) (domain.ToolIntent, string) {
	t.Helper()
	intent := domain.ToolIntent{OperationID: testActionStep, Case: testScope(), Tool: "query_host", Action: "read", TargetDigest: testDigestOne, ArgumentDigest: testDigestTwo}
	digest, err := toolIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	return intent, digest
}

func testScope() domain.CaseRef {
	return domain.CaseRef{OrganizationID: testOrganization, TenantID: testTenant, CaseID: testCase}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.UTC()
}
