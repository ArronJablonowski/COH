package agentloop

import (
	"context"
	"testing"
)

func TestTerminatePersistsExternalFailureWithoutExposingActivity(t *testing.T) {
	loop, _, model, action, _ := newTestLoop(t)
	startPlan(t, loop)
	request := TerminateRequest{
		IdempotencyKey: "semantic-denial", Case: testScope(), RunID: testRun, StepID: testPlanStep,
		Outcome: TerminalDenied, ReasonDigest: testDigestThree,
	}
	result, err := loop.Terminate(context.Background(), request)
	if err != nil || result.Run.Status != RunDenied || result.Step.Status != StepDenied || model.calls != 0 || action.calls != 0 {
		t.Fatalf("result=%+v model=%d action=%d err=%v", result, model.calls, action.calls, err)
	}
	replayed, err := loop.Terminate(context.Background(), request)
	if err != nil || !replayed.Replayed {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
}

func TestTerminateRejectsSuccessfulSemanticOutputWithoutLosingReference(t *testing.T) {
	loop, _, _, _, _ := newTestLoop(t)
	startPlan(t, loop)
	planned, err := loop.Execute(context.Background(), ExecuteRequest{IdempotencyKey: "plan", Case: testScope(), RunID: testRun, StepID: testPlanStep})
	if err != nil {
		t.Fatal(err)
	}
	result, err := loop.Terminate(context.Background(), TerminateRequest{
		IdempotencyKey: "malformed-result", Case: testScope(), RunID: testRun, StepID: testPlanStep,
		Outcome: TerminalDenied, ReasonDigest: testDigestThree,
	})
	if err != nil || result.Run.Status != RunDenied || result.Step.Status != StepDenied ||
		len(result.Step.OutputRefs) != 1 || result.Step.OutputRefs[0] != planned.Step.OutputRefs[0] {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
