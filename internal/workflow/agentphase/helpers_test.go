package agentphase

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/agentloop"
)

const (
	testOrganization = "0199b301-1111-7111-8111-111111111111"
	testTenant       = "0199b301-2222-7222-8222-222222222222"
	testCase         = "0199b301-3333-7333-8333-333333333333"
	testActor        = "0199b301-4444-7444-8444-444444444444"
	testRun          = "0199b301-5555-7555-8555-555555555555"
	testTrace        = "0199b301-6666-7666-8666-666666666666"
	testClaim        = "0199b301-7777-7777-8777-777777777777"
	testFinding      = "0199b301-8888-7888-8888-888888888888"
	testDigestOne    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testDigestTwo    = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testDigestThree  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	testDigestFour   = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
	testDigestFive   = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
	testDigestSix    = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
	testDigestSeven  = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
)

type phaseClock struct{ value time.Time }

func (clock *phaseClock) Now() time.Time {
	value := clock.value
	clock.value = clock.value.Add(time.Nanosecond)
	return value
}

type phaseStore struct {
	mu       sync.Mutex
	current  agentloop.Snapshot
	history  []agentloop.Snapshot
	failSave int
	saves    int
}

func (store *phaseStore) Create(_ context.Context, _ string, next agentloop.Snapshot) (agentloop.Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current.Run.RunID != "" {
		value := cloneSnapshot(store.current)
		value.Replayed = true
		return value, nil
	}
	store.current = cloneSnapshot(next)
	store.history = append(store.history, cloneSnapshot(next))
	return cloneSnapshot(next), nil
}

func (store *phaseStore) Load(_ context.Context, scope domain.CaseRef, runID string) (agentloop.Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current.Run.RunID != runID || store.current.Run.Case != scope {
		return agentloop.Snapshot{}, errors.New("not found")
	}
	return cloneSnapshot(store.current), nil
}

func (store *phaseStore) Save(_ context.Context, _ string, prior, next agentloop.Snapshot) (agentloop.Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.saves++
	if store.failSave == store.saves {
		return agentloop.Snapshot{}, errors.New("injected save failure")
	}
	if prior.Run.Revision != store.current.Run.Revision || prior.Step.Revision != store.current.Step.Revision ||
		prior.Step.StepID != store.current.Step.StepID {
		return agentloop.Snapshot{}, errors.New("revision conflict")
	}
	store.current = cloneSnapshot(next)
	store.history = append(store.history, cloneSnapshot(next))
	return cloneSnapshot(next), nil
}

type phaseModelStub struct {
	calls     []domain.Operation
	err       error
	block     bool
	artifacts map[string]domain.ArtifactRef
}

func (model *phaseModelStub) Invoke(ctx context.Context, operation domain.Operation) (domain.ArtifactRef, error) {
	model.calls = append(model.calls, operation)
	if model.block {
		<-ctx.Done()
		return domain.ArtifactRef{}, ctx.Err()
	}
	if model.err != nil {
		return domain.ArtifactRef{}, model.err
	}
	select {
	case <-ctx.Done():
		return domain.ArtifactRef{}, ctx.Err()
	default:
	}
	return model.artifacts[operation.Kind], nil
}

type phaseActionStub struct {
	calls   int
	receipt domain.ActionReceipt
	err     error
}

func (action *phaseActionStub) Submit(_ context.Context, _ domain.ToolIntent) (domain.ActionReceipt, error) {
	action.calls++
	return action.receipt, action.err
}

type resolverStub struct {
	outputs map[string]PhaseOutput
	errors  map[string]error
	calls   map[string]int
}

func (resolver *resolverStub) Resolve(_ context.Context, digest string, _ Phase) (PhaseOutput, error) {
	resolver.calls[digest]++
	if err := resolver.errors[digest]; err != nil {
		return PhaseOutput{}, err
	}
	return resolver.outputs[digest], nil
}

type phaseFixture struct {
	coordinator *Coordinator
	store       *phaseStore
	model       *phaseModelStub
	action      *phaseActionStub
	resolver    *resolverStub
}

func newPhaseFixture(t *testing.T) *phaseFixture {
	t.Helper()
	store := &phaseStore{}
	model := &phaseModelStub{artifacts: map[string]domain.ArtifactRef{
		"agent_plan":    artifact(testDigestTwo),
		"agent_observe": artifact(testDigestFour),
		"agent_review":  artifact(testDigestFive),
	}}
	action := &phaseActionStub{}
	resolver := &resolverStub{outputs: map[string]PhaseOutput{}, errors: map[string]error{}, calls: map[string]int{}}
	coordinator, err := New(Dependencies{
		Store: store, Models: model, Actions: action, Results: resolver,
		Clock: &phaseClock{value: mustTime(t, "2026-08-26T16:45:00.000000000Z")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &phaseFixture{coordinator: coordinator, store: store, model: model, action: action, resolver: resolver}
}

func startSession(t *testing.T, fixture *phaseFixture, policy RetryPolicy) Session {
	t.Helper()
	value, err := fixture.coordinator.Start(context.Background(), StartRequest{
		IdempotencyKey: "start", RunID: testRun, TraceID: testTrace, Case: testScope(), ActorID: testActor,
		PolicyDigest: testDigestOne, ProviderRoute: "connected", InputRefs: []string{testDigestOne},
		RetryPolicy: policy, Deadline: mustTime(t, "2026-08-26T17:45:00.000000000Z"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func planOutput(t *testing.T, fixture *phaseFixture, session Session, intentDigest string) PhaseOutput {
	t.Helper()
	input, err := fixture.coordinator.Input(session)
	if err != nil {
		t.Fatal(err)
	}
	return PhaseOutput{
		ContractVersion: ContractVersion, Phase: PlanPhase, TraceID: testTrace, Cycle: session.Cycle,
		InputSetDigest: input.InputSetDigest, ArtifactDigest: testDigestTwo, IntentDigest: intentDigest,
		EvidenceRefs: []string{}, Claims: []Claim{}, Findings: []Finding{},
	}
}

func observeOutput(t *testing.T, fixture *phaseFixture, session Session) PhaseOutput {
	t.Helper()
	input, err := fixture.coordinator.Input(session)
	if err != nil {
		t.Fatal(err)
	}
	return PhaseOutput{
		ContractVersion: ContractVersion, Phase: ObservePhase, TraceID: testTrace, Cycle: session.Cycle,
		InputSetDigest: input.InputSetDigest, ArtifactDigest: testDigestFour,
		EvidenceRefs: []string{testDigestThree, testDigestFour}, Completeness: Complete,
		Claims: []Claim{}, Findings: []Finding{},
	}
}

func reviewOutput(t *testing.T, fixture *phaseFixture, session Session, disposition ReviewDisposition) PhaseOutput {
	t.Helper()
	input, err := fixture.coordinator.Input(session)
	if err != nil {
		t.Fatal(err)
	}
	return PhaseOutput{
		ContractVersion: ContractVersion, Phase: ReviewPhase, TraceID: testTrace, Cycle: session.Cycle,
		InputSetDigest: input.InputSetDigest, ArtifactDigest: testDigestFive,
		EvidenceRefs: []string{testDigestFour}, Completeness: Complete,
		Claims: []Claim{{
			ClaimID: testClaim, StatementDigest: testDigestSix, EvidenceRefs: []string{testDigestFour},
			CounterevidenceRefs: []string{}, ConfidenceBasisPoints: 8500, UnknownDigests: []string{},
			RecommendedNextStepDigests: []string{testDigestSeven},
		}},
		Findings: []Finding{{
			FindingID: testFinding, SummaryDigest: testDigestSix, Status: "confirmed", Severity: "high",
			EvidenceRefs: []string{testDigestFour}, CounterevidenceRefs: []string{},
			ConfidenceBasisPoints: 8500, UnknownDigests: []string{},
			RecommendedNextStepDigests: []string{testDigestSeven},
		}},
		ReviewDisposition: disposition,
	}
}

func advanceToReview(t *testing.T, fixture *phaseFixture, policy RetryPolicy) Session {
	t.Helper()
	session := startSession(t, fixture, policy)
	actionStep, err := phaseStepID(testRun, testTrace, 1, ActPhase)
	if err != nil {
		t.Fatal(err)
	}
	intent := domain.ToolIntent{
		OperationID: actionStep, Case: testScope(), Tool: "query_host", Action: "read",
		TargetDigest: testDigestOne, ArgumentDigest: testDigestSix,
	}
	intentDigest, err := agentloop.ToolIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}
	fixture.resolver.outputs[testDigestTwo] = planOutput(t, fixture, session, intentDigest)
	planned, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "plan", Session: session})
	if err != nil {
		t.Fatal(err)
	}
	session, err = fixture.coordinator.Transition(context.Background(), TransitionRequest{IdempotencyKey: "to-act", Session: planned.Session, Output: planned.Output})
	if err != nil {
		t.Fatal(err)
	}
	fixture.action.receipt = domain.ActionReceipt{IntentDigest: intentDigest, Outcome: "succeeded", Evidence: artifact(testDigestThree)}
	acted, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "act", Session: session, Intent: &intent})
	if err != nil {
		t.Fatal(err)
	}
	session, err = fixture.coordinator.Transition(context.Background(), TransitionRequest{IdempotencyKey: "to-observe", Session: acted.Session, Output: acted.Output})
	if err != nil {
		t.Fatal(err)
	}
	fixture.resolver.outputs[testDigestFour] = observeOutput(t, fixture, session)
	observed, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "observe", Session: session})
	if err != nil {
		t.Fatal(err)
	}
	session, err = fixture.coordinator.Transition(context.Background(), TransitionRequest{IdempotencyKey: "to-review", Session: observed.Session, Output: observed.Output})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func testScope() domain.CaseRef {
	return domain.CaseRef{OrganizationID: testOrganization, TenantID: testTenant, CaseID: testCase}
}

func artifact(digest string) domain.ArtifactRef {
	return domain.ArtifactRef{Digest: digest, MediaType: "application/json", Classification: "internal", Length: 10}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.UTC()
}

func cloneSnapshot(value agentloop.Snapshot) agentloop.Snapshot {
	value.Run.InputRefs = append([]string{}, value.Run.InputRefs...)
	value.Run.OutputRefs = append([]string{}, value.Run.OutputRefs...)
	value.Step.InputRefs = append([]string{}, value.Step.InputRefs...)
	value.Step.OutputRefs = append([]string{}, value.Step.OutputRefs...)
	return value
}
