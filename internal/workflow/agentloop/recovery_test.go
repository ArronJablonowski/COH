package agentloop

import (
	"context"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestInjectedCrashesAtEveryDurableBoundaryRecoverSafely(t *testing.T) {
	t.Run("create_before_commit", func(t *testing.T) {
		loop, store, model, action, _ := newTestLoop(t)
		store.failCreate = true
		_, err := loop.Start(context.Background(), planStartRequest(t))
		if Code(err) != Unavailable || store.current.Run.RunID != "" || model.calls != 0 || action.calls != 0 {
			t.Fatalf("state=%+v model=%d action=%d err=%v", store.current, model.calls, action.calls, err)
		}
		store.failCreate = false
		if _, err := loop.Start(context.Background(), planStartRequest(t)); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("planning_before_dispatch", func(t *testing.T) {
		loop, store, model, _, _ := newTestLoop(t)
		startPlan(t, loop)
		store.failSave = store.saveCalls + 1
		_, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan-crash-before", Case: testScope(), RunID: testRun, StepID: testPlanStep})
		if Code(err) != Unavailable || model.calls != 0 || store.current.Step.Status != StepPending {
			t.Fatalf("state=%+v calls=%d err=%v", store.current, model.calls, err)
		}
		store.failSave = 0
		if result, err := loop.Resume(context.Background(), ResumeRequest{IdempotencyKey: "plan-retry", Case: testScope(), RunID: testRun}); err != nil || result.Step.Status != StepSucceeded || model.calls != 1 {
			t.Fatalf("result=%+v calls=%d err=%v", result, model.calls, err)
		}
	})

	t.Run("planning_after_result", func(t *testing.T) {
		loop, store, model, _, _ := newTestLoop(t)
		startPlan(t, loop)
		store.failSave = store.saveCalls + 2
		_, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan-crash-after", Case: testScope(), RunID: testRun, StepID: testPlanStep})
		if Code(err) != Unavailable || model.calls != 1 || store.current.Step.Status != StepRunning {
			t.Fatalf("state=%+v calls=%d err=%v", store.current, model.calls, err)
		}
		store.failSave = 0
		if result, err := loop.Resume(context.Background(), ResumeRequest{IdempotencyKey: "plan-resume", Case: testScope(), RunID: testRun}); err != nil || result.Step.Status != StepSucceeded || result.Step.Attempt != 2 || model.calls != 2 {
			t.Fatalf("result=%+v calls=%d err=%v", result, model.calls, err)
		}
	})

	t.Run("schedule_and_complete", func(t *testing.T) {
		loop, store, _, action, _ := newTestLoop(t)
		startPlan(t, loop)
		if _, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan", Case: testScope(), RunID: testRun, StepID: testPlanStep}); err != nil {
			t.Fatal(err)
		}
		intent, digest := testIntent(t)
		action.receipt = domain.ActionReceipt{IntentDigest: digest, Outcome: "succeeded", Evidence: domain.ArtifactRef{Digest: testDigestThree, MediaType: "application/json", Classification: "internal", Length: 1}}
		schedule := ScheduleRequest{IdempotencyKey: "schedule-crash", Case: testScope(), RunID: testRun, StepID: testActionStep, Activity: AuthorizedActionActivity, IntentDigest: digest, Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")}
		store.failSave = store.saveCalls + 1
		if _, err := loop.Schedule(context.Background(), schedule); Code(err) != Unavailable || store.current.Run.Status != RunWaiting {
			t.Fatalf("state=%+v err=%v", store.current, err)
		}
		store.failSave = 0
		if _, err := loop.Schedule(context.Background(), schedule); err != nil {
			t.Fatal(err)
		}
		if _, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "action", Case: testScope(), RunID: testRun, StepID: testActionStep, Intent: &intent}); err != nil {
			t.Fatal(err)
		}
		store.failSave = store.saveCalls + 1
		complete := CompleteRequest{IdempotencyKey: "complete-crash", Case: testScope(), RunID: testRun}
		if _, err := loop.Complete(context.Background(), complete); Code(err) != Unavailable || store.current.Run.Status != RunWaiting {
			t.Fatalf("state=%+v err=%v", store.current, err)
		}
		store.failSave = 0
		if result, err := loop.Complete(context.Background(), complete); err != nil || result.Run.Status != RunSucceeded || action.calls != 1 {
			t.Fatalf("result=%+v calls=%d err=%v", result, action.calls, err)
		}
	})
}

func planStartRequest(t *testing.T) StartRequest {
	t.Helper()
	return StartRequest{
		IdempotencyKey: "start-1", RunID: testRun, StepID: testPlanStep, Case: testScope(), ActorID: testActor,
		PolicyDigest: testDigestOne, ProviderRoute: "connected", Activity: PlanningActivity,
		InputRefs: []string{testDigestOne}, Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z"),
	}
}
