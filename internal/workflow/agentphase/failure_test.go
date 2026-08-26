package agentphase

import (
	"context"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/agentloop"
)

func TestMalformedOutputAndGuardDriftFailClosed(t *testing.T) {
	fixture := newPhaseFixture(t)
	session := startSession(t, fixture, RetryPolicy{MaximumPhaseAttempts: 2, MaximumReviewCycles: 2})
	actionStep, _ := phaseStepID(testRun, testTrace, 1, ActPhase)
	intent := domain.ToolIntent{OperationID: actionStep, Case: testScope(), Tool: "query_host", Action: "read", TargetDigest: testDigestOne, ArgumentDigest: testDigestSix}
	intentDigest, _ := agentloop.ToolIntentDigest(intent)
	malformed := planOutput(t, fixture, session, intentDigest)
	malformed.TraceID = testActor
	fixture.resolver.outputs[testDigestTwo] = malformed
	result, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "malformed", Session: session})
	if Code(err) != Denied || result.Session.Snapshot.Run.Status != agentloop.RunDenied ||
		result.Session.Snapshot.Step.Status != agentloop.StepDenied || fixture.action.calls != 0 {
		t.Fatalf("result=%+v calls=%d err=%v", result, fixture.action.calls, err)
	}

	fixture = newPhaseFixture(t)
	session = startSession(t, fixture, RetryPolicy{MaximumPhaseAttempts: 2, MaximumReviewCycles: 2})
	control := session.ControlDigest
	session.TraceID = testActor
	session.ControlDigest = control
	if _, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "drift", Session: session}); Code(err) != Denied || len(fixture.model.calls) != 0 {
		t.Fatalf("trace drift err=%v calls=%d", err, len(fixture.model.calls))
	}
}

func TestRetryAndReviewCycleExhaustionBecomeDurableFailures(t *testing.T) {
	t.Run("phase_attempts", func(t *testing.T) {
		fixture := newPhaseFixture(t)
		session := startSession(t, fixture, RetryPolicy{MaximumPhaseAttempts: 1, MaximumReviewCycles: 2})
		current := cloneSnapshot(session.Snapshot)
		current.Run.Sequence++
		current.Run.Revision++
		current.Step.Revision++
		current.Step.Status = agentloop.StepRunning
		current.Run.UpdatedAt = current.Run.UpdatedAt.Add(time.Nanosecond)
		current.Step.UpdatedAt = current.Run.UpdatedAt
		current.Run.ProvenanceDigest = testDigestSeven
		current.Step.ProvenanceDigest = testDigestSeven
		fixture.store.current = current
		session.Snapshot = current
		result, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "exhaust", Session: session})
		if Code(err) != Conflict || result.Session.Snapshot.Run.Status != agentloop.RunFailed || len(fixture.model.calls) != 0 {
			t.Fatalf("result=%+v calls=%d err=%v", result, len(fixture.model.calls), err)
		}
	})

	t.Run("review_cycles", func(t *testing.T) {
		fixture := newPhaseFixture(t)
		session := advanceToReview(t, fixture, RetryPolicy{MaximumPhaseAttempts: 2, MaximumReviewCycles: 1})
		output := reviewOutput(t, fixture, session, ReviewRevise)
		fixture.resolver.outputs[testDigestFive] = output
		reviewed, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "review", Session: session})
		if err != nil {
			t.Fatal(err)
		}
		terminal, err := fixture.coordinator.Transition(context.Background(), TransitionRequest{IdempotencyKey: "revise", Session: reviewed.Session, Output: reviewed.Output})
		if Code(err) != Conflict || Reason(err) != "review_cycle_exhausted" || terminal.Snapshot.Run.Status != agentloop.RunFailed {
			t.Fatalf("terminal=%+v err=%v", terminal, err)
		}
	})
}

func TestReviewRevisionSchedulesOneBoundedNewPlanCycle(t *testing.T) {
	fixture := newPhaseFixture(t)
	session := advanceToReview(t, fixture, RetryPolicy{MaximumPhaseAttempts: 2, MaximumReviewCycles: 2})
	cycleOneStep := session.Snapshot.Step.StepID
	output := reviewOutput(t, fixture, session, ReviewRevise)
	fixture.resolver.outputs[testDigestFive] = output
	reviewed, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "review", Session: session})
	if err != nil {
		t.Fatal(err)
	}
	revised, err := fixture.coordinator.Transition(context.Background(), TransitionRequest{IdempotencyKey: "revise", Session: reviewed.Session, Output: reviewed.Output})
	if err != nil || revised.Phase != PlanPhase || revised.Cycle != 2 ||
		revised.Snapshot.Step.StepID == cycleOneStep || revised.Snapshot.Step.Attempt != 1 {
		t.Fatalf("revised=%+v err=%v", revised, err)
	}
}

func TestActionCrashFreezesUncertainWithoutRedispatch(t *testing.T) {
	fixture := newPhaseFixture(t)
	session := startSession(t, fixture, RetryPolicy{MaximumPhaseAttempts: 2, MaximumReviewCycles: 2})
	actionStep, _ := phaseStepID(testRun, testTrace, 1, ActPhase)
	intent := domain.ToolIntent{OperationID: actionStep, Case: testScope(), Tool: "query_host", Action: "read", TargetDigest: testDigestOne, ArgumentDigest: testDigestSix}
	intentDigest, _ := agentloop.ToolIntentDigest(intent)
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
	fixture.store.failSave = fixture.store.saves + 2
	crashed, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "action-crash", Session: session, Intent: &intent})
	if Code(err) != Unavailable || fixture.action.calls != 1 || fixture.store.current.Step.Status != agentloop.StepDispatching {
		t.Fatalf("crashed=%+v calls=%d state=%+v err=%v", crashed, fixture.action.calls, fixture.store.current, err)
	}
	fixture.store.failSave = 0
	recovered, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "action-recover", Session: crashed.Session, Intent: &intent})
	if Code(err) != Conflict || recovered.Session.Snapshot.Run.Status != agentloop.RunUncertain || fixture.action.calls != 1 {
		t.Fatalf("recovered=%+v calls=%d err=%v", recovered, fixture.action.calls, err)
	}
}

func TestBrokerDenialRemainsAnExplicitDurablePhaseOutcome(t *testing.T) {
	fixture := newPhaseFixture(t)
	session := startSession(t, fixture, RetryPolicy{MaximumPhaseAttempts: 2, MaximumReviewCycles: 2})
	actionStep, _ := phaseStepID(testRun, testTrace, 1, ActPhase)
	intent := domain.ToolIntent{OperationID: actionStep, Case: testScope(), Tool: "query_host", Action: "read", TargetDigest: testDigestOne, ArgumentDigest: testDigestSix}
	intentDigest, _ := agentloop.ToolIntentDigest(intent)
	fixture.resolver.outputs[testDigestTwo] = planOutput(t, fixture, session, intentDigest)
	planned, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "plan", Session: session})
	if err != nil {
		t.Fatal(err)
	}
	session, err = fixture.coordinator.Transition(context.Background(), TransitionRequest{IdempotencyKey: "to-act", Session: planned.Session, Output: planned.Output})
	if err != nil {
		t.Fatal(err)
	}
	fixture.action.receipt = domain.ActionReceipt{IntentDigest: intentDigest, Outcome: "denied", Evidence: artifact(testDigestThree)}
	result, err := fixture.coordinator.Advance(context.Background(), AdvanceRequest{IdempotencyKey: "denied", Session: session, Intent: &intent})
	if Code(err) != Denied || result.Session.Snapshot.Run.Status != agentloop.RunDenied ||
		result.Session.Snapshot.Step.Status != agentloop.StepDenied || fixture.action.calls != 1 {
		t.Fatalf("result=%+v calls=%d err=%v", result, fixture.action.calls, err)
	}
}

func TestCancellationAndTimeoutPersistTypedPhaseOutcomes(t *testing.T) {
	for name, duration := range map[string]time.Duration{"canceled": time.Hour, "timeout": 5 * time.Millisecond} {
		t.Run(name, func(t *testing.T) {
			fixture := newPhaseFixture(t)
			fixture.model.block = true
			session := startSession(t, fixture, RetryPolicy{MaximumPhaseAttempts: 2, MaximumReviewCycles: 2})
			ctx, cancel := context.WithTimeout(context.Background(), duration)
			if name == "canceled" {
				go func() {
					time.Sleep(time.Millisecond)
					cancel()
				}()
			} else {
				defer cancel()
			}
			result, err := fixture.coordinator.Advance(ctx, AdvanceRequest{IdempotencyKey: name, Session: session})
			if name == "canceled" && (Code(err) != Canceled || result.Session.Snapshot.Run.Status != agentloop.RunCanceled) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			if name == "timeout" && (Code(err) != Timeout || result.Session.Snapshot.Run.Status != agentloop.RunTimeout) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}
