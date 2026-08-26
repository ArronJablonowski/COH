package agentloop

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestDurablePlanActionLoopPersistsBeforeActivities(t *testing.T) {
	loop, store, model, action, _ := newTestLoop(t)
	started := startPlan(t, loop)
	if started.Run.Status != RunRunning || started.Step.Status != StepPending || started.Run.Sequence != 1 || started.Run.ProvenanceDigest == "" {
		t.Fatalf("started=%+v", started)
	}
	planned, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan-1", Case: testScope(), RunID: testRun, StepID: testPlanStep})
	if err != nil {
		t.Fatal(err)
	}
	if planned.Run.Status != RunWaiting || planned.Step.Status != StepSucceeded || model.calls != 1 || len(planned.Run.OutputRefs) != 1 || store.history[1].Step.Status != StepRunning {
		t.Fatalf("planned=%+v calls=%d history=%+v", planned, model.calls, store.history)
	}
	intent, intentDigest := testIntent(t)
	action.receipt = domain.ActionReceipt{IntentDigest: intentDigest, Outcome: "succeeded", Evidence: domain.ArtifactRef{Digest: testDigestThree, MediaType: "application/json", Classification: "internal", Length: 8}}
	scheduled, err := loop.Schedule(context.Background(), ScheduleRequest{IdempotencyKey: "schedule-1", Case: testScope(), RunID: testRun, StepID: testActionStep, Activity: AuthorizedActionActivity, InputRefs: []string{testDigestTwo}, IntentDigest: intentDigest, Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")})
	if err != nil || scheduled.Step.Status != StepPending || scheduled.Run.Status != RunRunning {
		t.Fatalf("scheduled=%+v err=%v", scheduled, err)
	}
	acted, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "action-1", Case: testScope(), RunID: testRun, StepID: testActionStep, Intent: &intent})
	if err != nil {
		t.Fatal(err)
	}
	if acted.Run.Status != RunWaiting || acted.Step.Status != StepSucceeded || acted.Step.ReceiptDigest == "" || action.calls != 1 || store.history[len(store.history)-2].Step.Status != StepDispatching {
		t.Fatalf("acted=%+v calls=%d history=%+v", acted, action.calls, store.history)
	}
	completed, err := loop.Complete(context.Background(), CompleteRequest{IdempotencyKey: "complete-1", Case: testScope(), RunID: testRun})
	if err != nil || completed.Run.Status != RunSucceeded || completed.Run.Sequence != 7 || len(completed.Run.OutputRefs) != 2 {
		t.Fatalf("completed=%+v err=%v", completed, err)
	}
	replayed, err := loop.Resume(context.Background(), ResumeRequest{IdempotencyKey: "resume-complete", Case: testScope(), RunID: testRun})
	if err != nil || !replayed.Replayed || action.calls != 1 || model.calls != 1 {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
}

func TestCrashAfterBrokerReceiptNeverReplaysAction(t *testing.T) {
	loop, store, _, action, _ := newTestLoop(t)
	startPlan(t, loop)
	if _, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan-1", Case: testScope(), RunID: testRun, StepID: testPlanStep}); err != nil {
		t.Fatal(err)
	}
	intent, digest := testIntent(t)
	action.receipt = domain.ActionReceipt{IntentDigest: digest, Outcome: "succeeded", Evidence: domain.ArtifactRef{Digest: testDigestThree, MediaType: "application/json", Classification: "internal", Length: 1}}
	if _, err := loop.Schedule(context.Background(), ScheduleRequest{IdempotencyKey: "schedule-1", Case: testScope(), RunID: testRun, StepID: testActionStep, Activity: AuthorizedActionActivity, InputRefs: []string{}, IntentDigest: digest, Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")}); err != nil {
		t.Fatal(err)
	}
	store.failSave = store.saveCalls + 2
	if _, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "action-crash", Case: testScope(), RunID: testRun, StepID: testActionStep, Intent: &intent}); Code(err) != Unavailable {
		t.Fatalf("crash err=%v", err)
	}
	if action.calls != 1 || store.current.Step.Status != StepDispatching {
		t.Fatalf("calls=%d current=%+v", action.calls, store.current)
	}
	store.failSave = 0
	recovered, err := loop.Resume(context.Background(), ResumeRequest{IdempotencyKey: "restart-1", Case: testScope(), RunID: testRun, Intent: &intent})
	if Code(err) != Conflict || Reason(err) != "dispatch_receipt_missing" || recovered.Run.Status != RunUncertain || recovered.Step.Status != StepUncertain || action.calls != 1 {
		t.Fatalf("recovered=%+v err=%v calls=%d", recovered, err, action.calls)
	}
}

func TestPlanningCanResumeFromPersistedRunningState(t *testing.T) {
	loop, store, model, _, clock := newTestLoop(t)
	startPlan(t, loop)
	current := cloneSnapshot(store.current)
	current.Run.Sequence++
	current.Run.Revision++
	current.Step.Revision++
	current.Step.Status = StepRunning
	current.Step.UpdatedAt = clock.Now().UTC()
	current.Run.UpdatedAt = current.Step.UpdatedAt
	current.Run.ProvenanceDigest = testDigestThree
	current.Step.ProvenanceDigest = testDigestThree
	store.current = current
	result, err := loop.Resume(context.Background(), ResumeRequest{IdempotencyKey: "restart-plan", Case: testScope(), RunID: testRun})
	if err != nil || result.Step.Status != StepSucceeded || result.Step.Attempt != 2 || model.calls != 1 {
		t.Fatalf("result=%+v err=%v calls=%d", result, err, model.calls)
	}
}

func TestCancellationAndTimeoutBecomeDurableTerminalStates(t *testing.T) {
	for name, deadline := range map[string]time.Duration{"cancel": time.Hour, "timeout": 10 * time.Millisecond} {
		t.Run(name, func(t *testing.T) {
			store := &memoryStore{}
			model := &blockingModel{}
			action := &actionStub{store: store}
			clock := &fixedClock{value: mustTime(t, "2026-08-26T16:10:00.000000000Z")}
			loop, err := New(store, model, action, clock)
			if err != nil {
				t.Fatal(err)
			}
			startPlan(t, loop)
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			if name == "cancel" {
				go func() {
					time.Sleep(time.Millisecond)
					cancel()
				}()
			} else {
				defer cancel()
			}
			result, executeErr := loop.Execute(ctx, ExecuteRequest{IdempotencyKey: name, Case: testScope(), RunID: testRun, StepID: testPlanStep})
			if name == "cancel" {
				if Code(executeErr) != Canceled || result.Run.Status != RunCanceled || store.current.Run.Status != RunCanceled {
					t.Fatalf("result=%+v err=%v current=%+v", result, executeErr, store.current)
				}
			} else if Code(executeErr) != Timeout || result.Run.Status != RunTimeout || store.current.Run.Status != RunTimeout {
				t.Fatalf("result=%+v err=%v current=%+v", result, executeErr, store.current)
			}
		})
	}
}

func TestBrokerDenialAndAmbiguousFailureRemainExplicit(t *testing.T) {
	for name, outcome := range map[string]string{"denied": "denied", "uncertain": "uncertain"} {
		t.Run(name, func(t *testing.T) {
			loop, _, _, action, _ := newTestLoop(t)
			startPlan(t, loop)
			if _, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan", Case: testScope(), RunID: testRun, StepID: testPlanStep}); err != nil {
				t.Fatal(err)
			}
			intent, digest := testIntent(t)
			action.receipt = domain.ActionReceipt{IntentDigest: digest, Outcome: outcome, Evidence: domain.ArtifactRef{Digest: testDigestThree, MediaType: "application/json", Classification: "internal", Length: 1}}
			if _, err := loop.Schedule(context.Background(), ScheduleRequest{IdempotencyKey: "schedule", Case: testScope(), RunID: testRun, StepID: testActionStep, Activity: AuthorizedActionActivity, IntentDigest: digest, Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")}); err != nil {
				t.Fatal(err)
			}
			result, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "action", Case: testScope(), RunID: testRun, StepID: testActionStep, Intent: &intent})
			if err != nil {
				t.Fatal(err)
			}
			if name == "denied" && (result.Run.Status != RunDenied || result.Step.Status != StepDenied) || name == "uncertain" && (result.Run.Status != RunUncertain || result.Step.Status != StepUncertain) {
				t.Fatalf("result=%+v", result)
			}
		})
	}
	loop, store, _, action, _ := newTestLoop(t)
	startPlan(t, loop)
	if _, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan", Case: testScope(), RunID: testRun, StepID: testPlanStep}); err != nil {
		t.Fatal(err)
	}
	intent, digest := testIntent(t)
	if _, err := loop.Schedule(context.Background(), ScheduleRequest{IdempotencyKey: "schedule", Case: testScope(), RunID: testRun, StepID: testActionStep, Activity: AuthorizedActionActivity, IntentDigest: digest, Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")}); err != nil {
		t.Fatal(err)
	}
	action.err = errors.New("secret connector response")
	result, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "action", Case: testScope(), RunID: testRun, StepID: testActionStep, Intent: &intent})
	if Code(err) != Unavailable || Reason(err) != "action_outcome_uncertain" || result.Run.Status != RunUncertain || action.calls != 1 || store.current.Run.Status != RunUncertain {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
