package agentloop

import (
	"context"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/recoverycontrol"
)

type intentResolverStub struct {
	intent domain.ToolIntent
	err    error
	calls  int
}

func (resolver *intentResolverStub) ResolveIntent(context.Context, domain.CaseRef,
	string) (domain.ToolIntent, error) {
	resolver.calls++
	return resolver.intent, resolver.err
}

func TestRecoveryControlAdapterResumesPlanningThroughExistingDurableLoop(t *testing.T) {
	loop, store, model, action, _ := newTestLoop(t)
	startPlan(t, loop)
	resolver := &intentResolverStub{}
	adapter, err := NewRecoveryControlAdapter(loop, resolver)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := adapter.Inspect(context.Background(), recoverycontrol.WorkLookup{
		Case: testScope(), RunID: testRun, TaskID: testPlanStep})
	if err != nil || observed.Status != recoverycontrol.WorkPending ||
		observed.SideEffect != recoverycontrol.NoSideEffect || observed.ProvenanceDigest != store.current.Step.ProvenanceDigest {
		t.Fatalf("observed=%+v err=%v", observed, err)
	}
	resumed, err := adapter.Resume(context.Background(), recoverycontrol.WorkResume{
		IdempotencyKey: "recover-plan", Case: testScope(), RunID: testRun, TaskID: testPlanStep,
		ExpectedProvenanceDigest: observed.ProvenanceDigest, IntentDigest: observed.IntentDigest})
	if err != nil || resumed.Status != recoverycontrol.WorkWaiting || model.calls != 1 || action.calls != 0 ||
		resolver.calls != 0 {
		t.Fatalf("resumed=%+v model=%d action=%d resolver=%d err=%v",
			resumed, model.calls, action.calls, resolver.calls, err)
	}
}

func TestRecoveryControlAdapterCancelsCurrentChildWithoutDirectActionAccess(t *testing.T) {
	loop, store, model, action, _ := newTestLoop(t)
	startPlan(t, loop)
	adapter, err := NewRecoveryControlAdapter(loop, &intentResolverStub{})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := adapter.CancelChild(context.Background(), recoverycontrol.CancelCommand{
		IdempotencyKey: "cancel-child", Case: testScope(), RunID: testRun, RootTaskID: testActionStep,
		Target: recoverycontrol.CancelTarget{Sequence: 1, Kind: recoverycontrol.ChildTask,
			TargetID: testPlanStep, ExpectedProvenanceDigest: store.current.Step.ProvenanceDigest},
		ReasonDigest: testDigestThree, Deadline: store.current.Step.Deadline})
	if err != nil || ack.Outcome != recoverycontrol.AckCanceled ||
		store.current.Step.Status != StepCanceled || model.calls != 0 || action.calls != 0 {
		t.Fatalf("ack=%+v state=%+v model=%d action=%d err=%v",
			ack, store.current, model.calls, action.calls, err)
	}
}

func TestRecoveryControlAdapterDeniesScopeProvenanceAndDispatchAmbiguity(t *testing.T) {
	loop, store, _, _, _ := newTestLoop(t)
	startPlan(t, loop)
	adapter, err := NewRecoveryControlAdapter(loop, &intentResolverStub{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Resume(context.Background(), recoverycontrol.WorkResume{
		IdempotencyKey: "bad", Case: testScope(), RunID: testRun, TaskID: testPlanStep,
		ExpectedProvenanceDigest: testDigestThree}); recoverycontrol.ErrorCode(err) != recoverycontrol.DeniedCode {
		t.Fatalf("provenance mismatch accepted: %v", err)
	}
	store.current.Step.Status = StepDispatching
	if _, err := adapter.CancelChild(context.Background(), recoverycontrol.CancelCommand{
		IdempotencyKey: "dispatch", Case: testScope(), RunID: testRun, RootTaskID: testActionStep,
		Target: recoverycontrol.CancelTarget{Sequence: 1, Kind: recoverycontrol.ChildTask,
			TargetID: testPlanStep, ExpectedProvenanceDigest: store.current.Step.ProvenanceDigest},
		ReasonDigest: testDigestThree, Deadline: store.current.Step.Deadline}); recoverycontrol.ErrorCode(err) != recoverycontrol.Conflict || !recoverycontrol.Indeterminate(err) {
		t.Fatalf("dispatch ambiguity accepted: %v", err)
	}
}
