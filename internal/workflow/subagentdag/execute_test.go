package subagentdag

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

type executionRuntime struct {
	request ExecutionRequest
	result  StructuredResult
	err     error
	calls   int
}

type cancelAwareRuntime struct{ started chan struct{} }

func (runtime cancelAwareRuntime) RunChild(ctx context.Context, _ ExecutionRequest) (StructuredResult, error) {
	close(runtime.started)
	<-ctx.Done()
	return StructuredResult{}, ctx.Err()
}

func (runtime *executionRuntime) RunChild(_ context.Context, request ExecutionRequest) (StructuredResult, error) {
	runtime.calls++
	runtime.request = request
	return cloneStructuredResult(runtime.result), runtime.err
}

func TestExecutePersistsDispatchValidatesStructuredResultAndSettles(t *testing.T) {
	controller, _, authority, budgets, _ := newFixture(t)
	if _, err := controller.Create(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	delegate := delegateRequest("analysis", HuntingRole, testRoot)
	if _, err := controller.Delegate(context.Background(), delegate); err != nil {
		t.Fatal(err)
	}
	runtime := &executionRuntime{result: validResult(delegate.TaskID, delegate.Role)}
	controller.runtime = runtime
	request := executeRequest(delegate.TaskID, "execute-analysis")
	result, err := controller.Execute(context.Background(), request)
	if err != nil || result.Task.Status != TaskSucceeded || result.Task.Result == nil ||
		result.Task.BudgetSettlementDigest == "" || runtime.calls != 1 || budgets.settles != 1 {
		t.Fatalf("result=%+v err=%v runtime=%d settles=%d", result, err, runtime.calls, budgets.settles)
	}
	if runtime.request.Role != HuntingRole || runtime.request.AssignmentDigest != result.Task.AssignmentDigest ||
		authority.last.Operation != Execute || authority.last.TaskID != delegate.TaskID {
		t.Fatalf("runtime=%+v authority=%+v", runtime.request, authority.last)
	}
	replay, err := controller.Execute(context.Background(), request)
	if err != nil || !replay.Replayed || runtime.calls != 1 || budgets.settles != 1 {
		t.Fatalf("replay=%+v err=%v runtime=%d settles=%d", replay, err, runtime.calls, budgets.settles)
	}
}

func TestMalformedResultAndRuntimeFailureBecomeDurableTerminalStates(t *testing.T) {
	t.Run("malformed", func(t *testing.T) {
		controller, _, _, budgets, store := newFixture(t)
		if _, err := controller.Create(context.Background(), createRequest()); err != nil {
			t.Fatal(err)
		}
		delegate := delegateRequest("malformed", ValidationRole, testRoot)
		if _, err := controller.Delegate(context.Background(), delegate); err != nil {
			t.Fatal(err)
		}
		malformed := validResult(delegate.TaskID, delegate.Role)
		malformed.Claims[0].EvidenceRefs = nil
		controller.runtime = &executionRuntime{result: malformed}
		if _, err := controller.Execute(context.Background(), executeRequest(delegate.TaskID, "execute-malformed")); CodeOf(err) != Denied {
			t.Fatalf("err=%v", err)
		}
		stored, _, _ := store.Load(context.Background(), createRequest().Case, testGraph)
		task, _ := findTask(stored, delegate.TaskID)
		if task.Status != TaskDenied || task.Result != nil || task.BudgetSettlementDigest == "" || budgets.settles != 1 {
			t.Fatalf("task=%+v settles=%d", task, budgets.settles)
		}
	})
	t.Run("dependency", func(t *testing.T) {
		controller, _, _, _, store := newFixture(t)
		if _, err := controller.Create(context.Background(), createRequest()); err != nil {
			t.Fatal(err)
		}
		delegate := delegateRequest("failed", SIEMQueryRole, testRoot)
		if _, err := controller.Delegate(context.Background(), delegate); err != nil {
			t.Fatal(err)
		}
		controller.runtime = &executionRuntime{err: errors.New("provider unavailable")}
		if _, err := controller.Execute(context.Background(), executeRequest(delegate.TaskID, "execute-failed")); CodeOf(err) != Unavailable {
			t.Fatalf("err=%v", err)
		}
		stored, _, _ := store.Load(context.Background(), createRequest().Case, testGraph)
		task, _ := findTask(stored, delegate.TaskID)
		if task.Status != TaskFailed || task.BudgetSettlementDigest == "" {
			t.Fatalf("task=%+v", task)
		}
	})
}

func TestCanceledExecutePersistsUncertainStateWithoutForgingCancellationAck(t *testing.T) {
	controller, _, _, budgets, store := newFixture(t)
	if _, err := controller.Create(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	delegate := delegateRequest("caller-canceled", DetectionRole, testRoot)
	if _, err := controller.Delegate(context.Background(), delegate); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	controller.runtime = cancelAwareRuntime{started: started}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := controller.Execute(ctx, executeRequest(delegate.TaskID, "execute-canceled"))
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("runtime did not start")
	}
	cancel()
	select {
	case err := <-done:
		if CodeOf(err) != Canceled {
			t.Fatalf("execute err=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("execute did not finish")
	}
	stored, found, err := store.Load(context.Background(), createRequest().Case, testGraph)
	if err != nil || !found {
		t.Fatalf("stored found=%v err=%v", found, err)
	}
	task, found := findTask(stored, delegate.TaskID)
	if !found || task.Status != TaskUncertain || task.Cancellation != nil ||
		task.BudgetSettlementDigest == "" || budgets.settles != 1 {
		t.Fatalf("task=%+v settles=%d", task, budgets.settles)
	}
}

func TestElapsedChildDeadlinePersistsTimeoutWithoutDispatch(t *testing.T) {
	controller, clock, authority, budgets, store := newFixture(t)
	if _, err := controller.Create(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	delegate := delegateRequest("elapsed-deadline", SIEMQueryRole, testRoot)
	delegate.Deadline = testNow.Add(5 * time.Minute)
	if _, err := controller.Delegate(context.Background(), delegate); err != nil {
		t.Fatal(err)
	}
	clock.now = testNow.Add(10 * time.Minute)
	runtime := &executionRuntime{result: validResult(delegate.TaskID, delegate.Role)}
	controller.runtime = runtime
	if _, err := controller.Execute(context.Background(), executeRequest(delegate.TaskID, "execute-expired")); CodeOf(err) != Timeout || Reason(err) != "task_deadline_elapsed" {
		t.Fatalf("execute err=%v", err)
	}
	stored, found, err := store.Load(context.Background(), createRequest().Case, testGraph)
	if err != nil || !found {
		t.Fatalf("stored found=%v err=%v", found, err)
	}
	task, found := findTask(stored, delegate.TaskID)
	if !found || task.Status != TaskTimedOut || task.BudgetSettlementDigest == "" ||
		runtime.calls != 0 || budgets.settles != 1 || authority.last.Deadline != stored.Deadline {
		t.Fatalf("task=%+v runtime=%d settles=%d authority=%+v", task, runtime.calls, budgets.settles, authority.last)
	}
}

func TestExecutionPortContainsNoAuthorityOrExecutorCapability(t *testing.T) {
	typeOf := reflect.TypeOf(ExecutionRequest{})
	for index := 0; index < typeOf.NumField(); index++ {
		name := strings.ToLower(typeOf.Field(index).Name)
		for _, forbidden := range []string{"actor", "policy", "approval", "credential", "connector", "broker", "tool", "executor", "shell", "http", "callback"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("execution request exposes %s", typeOf.Field(index).Name)
			}
		}
	}
	port := reflect.TypeOf((*Runtime)(nil)).Elem()
	if port.NumMethod() != 1 || port.Method(0).Name != "RunChild" {
		t.Fatalf("runtime port=%v", port)
	}
}

func TestEveryClosedRoleProducesTheSameTypedResultContract(t *testing.T) {
	roles := []Role{CoordinatorRole, AlertTriageRole, SIEMQueryRole, TimelineCorrelationRole,
		HuntingRole, CTIAttackRole, DetectionRole, VulnerabilityRole, ValidationRole,
		IRPlannerRole, ReviewerRole, ReportWriterRole}
	for _, role := range roles {
		result := validResult(testUUID("typed-result-"+string(role)), role)
		if err := validateStructuredResult(result); err != nil {
			t.Fatalf("role=%s result=%+v err=%v", role, result, err)
		}
	}
	findingOnly := StructuredResult{TaskID: testUUID("finding-only"), Role: ReviewerRole,
		Artifact: domain.ArtifactRef{Digest: testDigest("finding-artifact"), MediaType: "application/json",
			Classification: "restricted", Length: 128}, Claims: []Claim{},
		Findings: []Finding{{FindingID: testUUID("finding"), SummaryDigest: testDigest("summary"),
			Status: "confirmed", Severity: "high", EvidenceRefs: []string{testDigest("finding-evidence")},
			CounterevidenceRefs: []string{testDigest("counterevidence")}, ConfidenceBasisPoints: 9000,
			UnknownDigests:             []string{testDigest("unknown")},
			RecommendedNextStepDigests: []string{testDigest("remediate")}}},
		Completeness: Partial, RuntimeDigest: testDigest("finding-runtime")}
	findingOnly.ResultDigest, _ = ResultBindingDigest(findingOnly)
	if err := validateStructuredResult(findingOnly); err != nil {
		t.Fatalf("finding-only result=%+v err=%v", findingOnly, err)
	}
}

func validResult(taskID string, role Role) StructuredResult {
	value := StructuredResult{TaskID: taskID, Role: role,
		Artifact: domain.ArtifactRef{Digest: testDigest("result-artifact-" + taskID), MediaType: "application/json", Classification: "restricted", Length: 256},
		Claims: []Claim{{ClaimID: testUUID("claim-" + taskID), StatementDigest: testDigest("statement-" + taskID),
			EvidenceRefs: []string{testDigest("evidence-" + taskID)}, CounterevidenceRefs: []string{},
			ConfidenceBasisPoints: 7500, UnknownDigests: []string{testDigest("unknown-" + taskID)},
			RecommendedNextStepDigests: []string{testDigest("next-" + taskID)}}},
		Findings: []Finding{}, Completeness: Complete, RuntimeDigest: testDigest("runtime")}
	value.ResultDigest, _ = ResultBindingDigest(value)
	return value
}

func executeRequest(taskID, key string) ExecuteRequest {
	return ExecuteRequest{RequestID: testUUID("request-" + key), IdempotencyKey: key,
		GraphID: testGraph, TaskID: taskID, Case: createRequest().Case, ActorID: testActor,
		ActorRevision: 3, PolicyDigest: testDigest("policy")}
}
