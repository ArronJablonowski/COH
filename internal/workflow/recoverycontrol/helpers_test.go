package recoverycontrol

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

const (
	testControl  = "0199a213-2000-7000-8000-000000000001"
	testRun      = "0199a213-2000-7000-8000-000000000002"
	testTask     = "0199a213-2000-7000-8000-000000000003"
	testChild    = "0199a213-2000-7000-8000-000000000004"
	testJob      = "0199a213-2000-7000-8000-000000000005"
	testOrg      = "0199a213-2000-7000-8000-000000000006"
	testTenant   = "0199a213-2000-7000-8000-000000000007"
	testCase     = "0199a213-2000-7000-8000-000000000008"
	testDecision = "0199a213-2000-7000-8000-000000000009"
	testDigest1  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testDigest2  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testDigest3  = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

var testNow = time.Date(2026, 8, 26, 19, 0, 0, 0, time.UTC)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	value := clock.now
	clock.now = clock.now.Add(time.Nanosecond)
	return value
}

type memoryStore struct {
	mu                     sync.Mutex
	current                Record
	beginErrorAfterPersist bool
	saveErrorAfterPersist  bool
}

func (store *memoryStore) Load(_ context.Context, scope domain.CaseRef, id string) (Record, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current.ControlID == "" {
		return Record{}, false, nil
	}
	if store.current.ControlID != id || store.current.Case != scope {
		return Record{}, false, newError(DeniedCode, "store_scope_mismatch", false, false, nil)
	}
	return cloneRecord(store.current), true, nil
}

func (store *memoryStore) Begin(_ context.Context, _ string, value Record) (Record, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.current.ControlID != "" {
		return cloneRecord(store.current), true, nil
	}
	store.current = cloneRecord(value)
	if store.beginErrorAfterPersist {
		store.beginErrorAfterPersist = false
		return Record{}, false, errors.New("commit response lost")
	}
	return cloneRecord(value), false, nil
}

func (store *memoryStore) Save(_ context.Context, _ string, prior, next Record) (Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if prior.Revision != store.current.Revision || prior.ProvenanceDigest != store.current.ProvenanceDigest {
		return Record{}, newError(Conflict, "store_revision_conflict", true, false, nil)
	}
	store.current = cloneRecord(next)
	if store.saveErrorAfterPersist {
		store.saveErrorAfterPersist = false
		return Record{}, errors.New("commit response lost")
	}
	return cloneRecord(next), nil
}

type workStub struct {
	inspect WorkSnapshot
	resume  WorkSnapshot
	err     error
	calls   int
}

func (work *workStub) Inspect(context.Context, WorkLookup) (WorkSnapshot, error) {
	return work.inspect, work.err
}

func (work *workStub) Resume(context.Context, WorkResume) (WorkSnapshot, error) {
	work.calls++
	return work.resume, work.err
}

type cancelStub struct {
	store *memoryStore
	acks  map[string]CancellationAck
	errs  map[string]error
	calls []CancelCommand
}

func (cancel *cancelStub) invoke(command CancelCommand) (CancellationAck, error) {
	cancel.calls = append(cancel.calls, command)
	if cancel.store != nil && cancel.store.current.Status != CancellationActive {
		return CancellationAck{}, errors.New("intent was not durable before propagation")
	}
	if err := cancel.errs[command.Target.TargetID]; err != nil {
		return CancellationAck{}, err
	}
	return cancel.acks[command.Target.TargetID], nil
}

func (cancel *cancelStub) CancelChild(_ context.Context, command CancelCommand) (CancellationAck, error) {
	return cancel.invoke(command)
}

func (cancel *cancelStub) CancelJob(_ context.Context, command CancelCommand) (CancellationAck, error) {
	return cancel.invoke(command)
}

type routeStub struct {
	approved ApprovedRoute
	err      error
	calls    int
	requests []RouteApprovalRequest
}

func (route *routeStub) ApproveFallback(_ context.Context, request RouteApprovalRequest) (ApprovedRoute, error) {
	route.calls++
	route.requests = append(route.requests, request)
	return route.approved, route.err
}

type providerOutcome struct {
	receipt AttemptReceipt
	err     error
}

type providerStub struct {
	outcomes []providerOutcome
	requests []AttemptRequest
}

func (provider *providerStub) InvokeProvider(_ context.Context, request AttemptRequest) (AttemptReceipt, error) {
	provider.requests = append(provider.requests, request)
	index := len(provider.requests) - 1
	if index >= len(provider.outcomes) {
		return AttemptReceipt{}, errors.New("unexpected provider invocation")
	}
	value := provider.outcomes[index]
	if value.receipt.AttemptID == "" {
		value.receipt = AttemptReceipt{AttemptID: request.AttemptID, Route: request.Route,
			CapabilityDigest: request.CapabilityDigest, Outcome: "succeeded", Artifact: validArtifactRef(),
			EvidenceDigest: testDigest3}
	}
	return value.receipt, value.err
}

func newController(t *testing.T, store *memoryStore, work *workStub, cancel *cancelStub,
	route *routeStub, provider *providerStub) *Controller {
	t.Helper()
	if work == nil {
		work = &workStub{inspect: validWorkSnapshot(WorkRunning, NoSideEffect),
			resume: validWorkSnapshot(WorkWaiting, NoSideEffect)}
	}
	if cancel == nil {
		cancel = validCancelStub(store)
	}
	if route == nil {
		route = &routeStub{approved: validApprovedRoute(t)}
	}
	if provider == nil {
		provider = &providerStub{outcomes: []providerOutcome{{}}}
	}
	controller, err := New(store, work, cancel, cancel, route, provider, &testClock{now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func validScope() domain.CaseRef {
	return domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase}
}

func validWorkSnapshot(status WorkStatus, sideEffect SideEffectState) WorkSnapshot {
	value := WorkSnapshot{Case: validScope(), RunID: testRun, TaskID: testTask, Status: status,
		SideEffect: sideEffect, IntentDigest: testDigest1, ProvenanceDigest: testDigest2}
	if sideEffect == ConfirmedSideEffect {
		value.ReceiptDigest = testDigest3
	}
	if terminalWork(status) {
		value.TerminalEvidence = testDigest3
	}
	return value
}

func validRecoverRequest() RecoverRequest {
	return RecoverRequest{IdempotencyKey: "recover-one", ControlID: testControl, Case: validScope(),
		RunID: testRun, TaskID: testTask, PolicyDigest: testDigest1,
		ExpectedProvenanceDigest: testDigest2, IntentDigest: testDigest1,
		CreatedAt: testNow.Add(-time.Minute), Deadline: testNow.Add(time.Hour)}
}

func validCancelRequest() CancelRequest {
	return CancelRequest{IdempotencyKey: "cancel-one", ControlID: testControl, Case: validScope(),
		RunID: testRun, TaskID: testTask, PolicyDigest: testDigest1,
		ExpectedProvenanceDigest: testDigest2, ReasonDigest: testDigest3,
		Targets: []CancelTarget{
			{Sequence: 1, Kind: ChildTask, TargetID: testChild, ExpectedProvenanceDigest: testDigest1},
			{Sequence: 2, Kind: ToolJob, TargetID: testJob, ExpectedProvenanceDigest: testDigest2},
		}, CreatedAt: testNow.Add(-time.Minute), Deadline: testNow.Add(time.Hour)}
}

func validCancelStub(store *memoryStore) *cancelStub {
	return &cancelStub{store: store, acks: map[string]CancellationAck{
		testChild: {Sequence: 1, Kind: ChildTask, TargetID: testChild, Outcome: AckCanceled,
			EvidenceDigest: testDigest1, ProvenanceDigest: testDigest2},
		testJob: {Sequence: 2, Kind: ToolJob, TargetID: testJob, Outcome: AckAlreadyTerminal,
			EvidenceDigest: testDigest2, ProvenanceDigest: testDigest3},
	}, errs: map[string]error{}}
}

func validInvokeRequest() InvokeRequest {
	return InvokeRequest{IdempotencyKey: "fallback-one", ControlID: testControl, Case: validScope(),
		RunID: testRun, TaskID: testTask, PolicyDigest: testDigest1, RequestedRoute: "connected",
		Operation: domain.Operation{ID: testTask, Case: validScope(), Kind: "agent_plan", Version: "coh.agent-loop.v1"},
		InputRefs: []string{testDigest1, testDigest2}, BudgetReservationDigest: testDigest3,
		CreatedAt: testNow.Add(-time.Minute), Deadline: testNow.Add(time.Hour)}
}

func validApprovedRoute(t *testing.T) ApprovedRoute {
	t.Helper()
	capability := decodeCapability(t, nil)
	qualification := decodeQualification(t, capability)
	return ApprovedRoute{DecisionID: testDecision, PolicyDigest: testDigest1, RequestedRoute: "connected",
		PrimaryRoute: "local.primary", FallbackRoute: "local.backup", ApprovalDigest: testDigest2,
		PrimaryCapability: capability, PrimaryQualification: qualification,
		FallbackCapability: capability, FallbackQualification: qualification,
		IssuedAt: testNow.Add(-time.Minute), ExpiresAt: testNow.Add(time.Hour)}
}

func decodeQualification(t *testing.T,
	capability providercontract.ValidatedCapability) providercontract.ValidatedQualification {
	return decodeQualificationWithMutation(t, capability, nil)
}

func decodeQualificationWithMutation(t *testing.T, capability providercontract.ValidatedCapability,
	mutate func(*providercontract.QualificationRecord)) providercontract.ValidatedQualification {
	t.Helper()
	input, err := os.ReadFile("../../../contracts/provider/v1/fixtures/valid/qualification.json")
	if err != nil {
		t.Fatal(err)
	}
	var value providercontract.QualificationRecord
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	value.Provider = capability.Value().Provider
	value.CapabilityDigest = capability.Digest()
	if mutate != nil {
		mutate(&value)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := providercontract.DecodeQualification(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func decodeCapability(t *testing.T, mutate func(*providercontract.CapabilitySnapshot)) providercontract.ValidatedCapability {
	t.Helper()
	input, err := os.ReadFile("../../../contracts/provider/v1/fixtures/valid/capability.json")
	if err != nil {
		t.Fatal(err)
	}
	var value providercontract.CapabilitySnapshot
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&value)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := providercontract.DecodeCapability(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func validArtifactRef() domain.ArtifactRef {
	return domain.ArtifactRef{Digest: testDigest3, MediaType: "application/json", Classification: "internal", Length: 42}
}
