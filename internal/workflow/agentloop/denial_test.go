package agentloop

import (
	"context"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

func TestInvalidStartRequestsDoNotPersist(t *testing.T) {
	mutations := []func(*StartRequest){
		func(value *StartRequest) { value.RunID = "not-a-run" },
		func(value *StartRequest) { value.ActorID = "" },
		func(value *StartRequest) { value.PolicyDigest = "raw" },
		func(value *StartRequest) { value.ProviderRoute = "CONNECTED" },
		func(value *StartRequest) { value.Activity = "shell" },
		func(value *StartRequest) { value.InputRefs = []string{testDigestTwo, testDigestOne} },
		func(value *StartRequest) { value.IntentDigest = testDigestOne },
		func(value *StartRequest) { value.Deadline = mustTime(t, "2026-08-26T15:10:00.000000000Z") },
	}
	for _, mutate := range mutations {
		loop, store, _, _, _ := newTestLoop(t)
		request := StartRequest{IdempotencyKey: "start", RunID: testRun, StepID: testPlanStep, Case: testScope(), ActorID: testActor, PolicyDigest: testDigestOne, ProviderRoute: "connected", Activity: PlanningActivity, InputRefs: []string{testDigestOne}, Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")}
		mutate(&request)
		if _, err := loop.Start(context.Background(), request); Code(err) != InvalidInput || store.createCalls != 0 {
			t.Fatalf("request=%+v err=%v creates=%d", request, err, store.createCalls)
		}
	}
}

func TestScopeIntentAndStoreDriftFailBeforeActivities(t *testing.T) {
	t.Run("scope", func(t *testing.T) {
		loop, _, model, action, _ := newTestLoop(t)
		startPlan(t, loop)
		scope := testScope()
		scope.TenantID = "0199a213-81c0-7800-8aa1-bbab2a035a79"
		_, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "wrong-scope", Case: scope, RunID: testRun, StepID: testPlanStep})
		if Code(err) != Denied || model.calls != 0 || action.calls != 0 {
			t.Fatalf("err=%v model=%d action=%d", err, model.calls, action.calls)
		}
	})
	t.Run("intent", func(t *testing.T) {
		loop, _, _, action, _ := newTestLoop(t)
		startPlan(t, loop)
		if _, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan", Case: testScope(), RunID: testRun, StepID: testPlanStep}); err != nil {
			t.Fatal(err)
		}
		intent, digest := testIntent(t)
		if _, err := loop.Schedule(context.Background(), ScheduleRequest{IdempotencyKey: "schedule", Case: testScope(), RunID: testRun, StepID: testActionStep, Activity: AuthorizedActionActivity, IntentDigest: digest, Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")}); err != nil {
			t.Fatal(err)
		}
		intent.ArgumentDigest = testDigestThree
		_, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "drift", Case: testScope(), RunID: testRun, StepID: testActionStep, Intent: &intent})
		if Code(err) != Denied || Reason(err) != "intent_binding_mismatch" || action.calls != 0 {
			t.Fatalf("err=%v calls=%d", err, action.calls)
		}
	})
	t.Run("store", func(t *testing.T) {
		loop, store, model, _, _ := newTestLoop(t)
		startPlan(t, loop)
		store.current.Run.ProviderRoute = ""
		_, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "corrupt", Case: testScope(), RunID: testRun, StepID: testPlanStep})
		if Code(err) != Denied || Reason(err) != "store_result_invalid" || model.calls != 0 {
			t.Fatalf("err=%v calls=%d", err, model.calls)
		}
	})
}

func TestInvalidBrokerReceiptFreezesRunAsUncertain(t *testing.T) {
	loop, _, _, action, _ := newTestLoop(t)
	startPlan(t, loop)
	if _, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan", Case: testScope(), RunID: testRun, StepID: testPlanStep}); err != nil {
		t.Fatal(err)
	}
	intent, digest := testIntent(t)
	action.receipt = domain.ActionReceipt{IntentDigest: testDigestOne, Outcome: "succeeded", Evidence: domain.ArtifactRef{Digest: testDigestThree, MediaType: "application/json", Classification: "internal", Length: 1}}
	if _, err := loop.Schedule(context.Background(), ScheduleRequest{IdempotencyKey: "schedule", Case: testScope(), RunID: testRun, StepID: testActionStep, Activity: AuthorizedActionActivity, IntentDigest: digest, Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")}); err != nil {
		t.Fatal(err)
	}
	result, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "action", Case: testScope(), RunID: testRun, StepID: testActionStep, Intent: &intent})
	if Code(err) != Denied || Reason(err) != "broker_receipt_invalid" || result.Run.Status != RunUncertain || result.Step.Status != StepUncertain || action.calls != 1 {
		t.Fatalf("result=%+v err=%v calls=%d", result, err, action.calls)
	}
}

func TestActivityBoundaryHasNoDirectExecutorOrGenericCallback(t *testing.T) {
	loopType := reflect.TypeOf(Loop{})
	activityField, ok := loopType.FieldByName("activities")
	if !ok || activityField.Type != reflect.TypeOf((*Activities)(nil)) {
		t.Fatal("typed activities boundary missing")
	}
	for index := 0; index < loopType.NumField(); index++ {
		field := loopType.Field(index)
		if field.Type.Kind() == reflect.Func || field.Name == "connector" || field.Name == "runner" || field.Name == "credential" || field.Name == "executor" {
			t.Fatalf("unsafe dependency field: %s %v", field.Name, field.Type)
		}
	}
	activityType := reflect.TypeOf(Activities{})
	models, ok := activityType.FieldByName("models")
	if !ok || models.Type != reflect.TypeOf((*workflowbase.ModelProvider)(nil)).Elem() {
		t.Fatal("model provider port missing")
	}
	actions, ok := activityType.FieldByName("actions")
	if !ok || actions.Type != reflect.TypeOf((*workflowbase.ActionAuthority)(nil)).Elem() {
		t.Fatal("action authority port missing")
	}
	for index := 0; index < activityType.NumField(); index++ {
		field := activityType.Field(index)
		if field.Type.Kind() == reflect.Func || field.Name == "connector" || field.Name == "runner" || field.Name == "credential" || field.Name == "executor" {
			t.Fatalf("unsafe activity dependency field: %s %v", field.Name, field.Type)
		}
	}
}
