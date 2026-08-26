package agentphase

import (
	"context"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/agentloop"
)

func TestPlanActObserveReviewCompletesWithTypedBindings(t *testing.T) {
	fixture := newPhaseFixture(t)
	policy := RetryPolicy{MaximumPhaseAttempts: 3, MaximumReviewCycles: 2}
	session := startSession(t, fixture, policy)
	actionStep, _ := phaseStepID(testRun, testTrace, 1, ActPhase)
	intent := domain.ToolIntent{
		OperationID: actionStep, Case: testScope(), Tool: "query_host", Action: "read",
		TargetDigest: testDigestOne, ArgumentDigest: testDigestSix,
	}
	intentDigest, err := agentloop.ToolIntentDigest(intent)
	if err != nil {
		t.Fatal(err)
	}

	plan := planOutput(t, fixture, session, intentDigest)
	fixture.resolver.outputs[testDigestTwo] = plan
	planned, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "plan", Session: session})
	if err != nil || !reflect.DeepEqual(planned.Output, plan) || fixture.resolver.calls[testDigestTwo] != 2 {
		t.Fatalf("planned=%+v err=%v resolver_calls=%d", planned, err, fixture.resolver.calls[testDigestTwo])
	}
	session, err = fixture.coordinator.Transition(context.Background(), TransitionRequest{IdempotencyKey: "to-act", Session: planned.Session, Output: planned.Output})
	if err != nil || session.Phase != ActPhase || session.Snapshot.Step.IntentDigest != intentDigest {
		t.Fatalf("session=%+v err=%v", session, err)
	}
	replayed, err := fixture.coordinator.Start(context.Background(), StartRequest{
		IdempotencyKey: "start", RunID: testRun, TraceID: testTrace, Case: testScope(), ActorID: testActor,
		PolicyDigest: testDigestOne, ProviderRoute: "connected", InputRefs: []string{testDigestOne},
		RetryPolicy: policy, Deadline: mustTime(t, "2026-08-26T17:45:00.000000000Z"),
	})
	if err != nil || replayed.Phase != ActPhase || !replayed.Snapshot.Replayed {
		t.Fatalf("start replay=%+v err=%v", replayed, err)
	}

	fixture.action.receipt = domain.ActionReceipt{IntentDigest: intentDigest, Outcome: "succeeded", Evidence: artifact(testDigestThree)}
	acted, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "act", Session: session, Intent: &intent})
	if err != nil || acted.Output.Phase != ActPhase || acted.Output.ReceiptDigest == "" ||
		acted.Output.ArtifactDigest != testDigestThree || fixture.action.calls != 1 {
		t.Fatalf("acted=%+v calls=%d err=%v", acted, fixture.action.calls, err)
	}
	session, err = fixture.coordinator.Transition(context.Background(), TransitionRequest{IdempotencyKey: "to-observe", Session: acted.Session, Output: acted.Output})
	if err != nil || session.Phase != ObservePhase {
		t.Fatalf("session=%+v err=%v", session, err)
	}

	observedOutput := observeOutput(t, fixture, session)
	fixture.resolver.outputs[testDigestFour] = observedOutput
	observed, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "observe", Session: session})
	if err != nil || observed.Output.Completeness != Complete || len(observed.Output.EvidenceRefs) != 2 {
		t.Fatalf("observed=%+v err=%v", observed, err)
	}
	session, err = fixture.coordinator.Transition(context.Background(), TransitionRequest{IdempotencyKey: "to-review", Session: observed.Session, Output: observed.Output})
	if err != nil || session.Phase != ReviewPhase {
		t.Fatalf("session=%+v err=%v", session, err)
	}

	reviewedOutput := reviewOutput(t, fixture, session, ReviewAccepted)
	fixture.resolver.outputs[testDigestFive] = reviewedOutput
	reviewed, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "review", Session: session})
	if err != nil || len(reviewed.Output.Claims) != 1 || len(reviewed.Output.Findings) != 1 {
		t.Fatalf("reviewed=%+v err=%v", reviewed, err)
	}
	session, err = fixture.coordinator.Transition(context.Background(), TransitionRequest{IdempotencyKey: "complete", Session: reviewed.Session, Output: reviewed.Output})
	if err != nil || session.Snapshot.Run.Status != agentloop.RunSucceeded || fixture.action.calls != 1 {
		t.Fatalf("session=%+v calls=%d err=%v", session, fixture.action.calls, err)
	}

	wantKinds := []string{"agent_plan", "agent_observe", "agent_review"}
	if len(fixture.model.calls) != len(wantKinds) {
		t.Fatalf("model calls=%+v", fixture.model.calls)
	}
	for index, operation := range fixture.model.calls {
		if operation.Kind != wantKinds[index] || operation.Version != ContractVersion || operation.Case != testScope() {
			t.Fatalf("operation[%d]=%+v", index, operation)
		}
	}
	for index := 1; index < len(fixture.store.history); index++ {
		if fixture.store.history[index].Run.Sequence <= fixture.store.history[index-1].Run.Sequence {
			t.Fatalf("non-monotonic history=%+v", fixture.store.history)
		}
	}
}
