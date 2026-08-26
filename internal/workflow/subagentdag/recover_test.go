package subagentdag

import (
	"context"
	"testing"
)

func TestRecoveryNeverRedispatchesAnIndeterminateChild(t *testing.T) {
	controller, clock, authority, budgets, _ := newFixture(t)
	if _, err := controller.Create(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	delegate := delegateRequest("crashed", DetectionRole, testRoot)
	created, err := controller.Delegate(context.Background(), delegate)
	if err != nil {
		t.Fatal(err)
	}
	dispatched, err := controller.transitionTask(context.Background(), "simulate-dispatch",
		created.Graph, created.Task, func(task *Task) { task.Status = TaskDispatching }, clock.now)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &executionRuntime{result: validResult(delegate.TaskID, delegate.Role)}
	controller.runtime = runtime
	request := recoverRequest(delegate.TaskID, "recover-crashed")
	result, err := controller.Recover(context.Background(), request)
	if err != nil || result.Task.Status != TaskUncertain || result.Task.BudgetSettlementDigest == "" ||
		runtime.calls != 0 || budgets.settles != 1 || authority.last.Operation != Recover {
		t.Fatalf("dispatched=%+v result=%+v err=%v runtime=%d settle=%d authority=%+v",
			dispatched.Task, result, err, runtime.calls, budgets.settles, authority.last)
	}
	replay, err := controller.Recover(context.Background(), request)
	if err != nil || !replay.Replayed || runtime.calls != 0 || budgets.settles != 1 {
		t.Fatalf("replay=%+v err=%v runtime=%d settle=%d", replay, err, runtime.calls, budgets.settles)
	}
}

func TestRecoveryLeavesNeverDispatchedPendingWorkSafeToSchedule(t *testing.T) {
	controller, _, _, budgets, _ := newFixture(t)
	if _, err := controller.Create(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	request := recoverRequest(testRoot, "recover-pending")
	result, err := controller.Recover(context.Background(), request)
	if err != nil || result.Task.Status != TaskPending || result.Task.BudgetSettlementDigest != "" || budgets.settles != 0 {
		t.Fatalf("result=%+v err=%v settle=%d", result, err, budgets.settles)
	}
}

func recoverRequest(taskID, key string) RecoverRequest {
	return RecoverRequest{RequestID: testUUID("request-" + key), IdempotencyKey: key, GraphID: testGraph,
		TaskID: taskID, Case: createRequest().Case, ActorID: testActor, ActorRevision: 3,
		PolicyDigest: testDigest("policy")}
}
