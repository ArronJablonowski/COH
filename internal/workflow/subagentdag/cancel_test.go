package subagentdag

import (
	"context"
	"errors"
	"testing"
)

type recordingCanceler struct {
	requests []ExecutionRequest
	errAt    int
}

func (canceler *recordingCanceler) CancelChild(_ context.Context, request ExecutionRequest, reason string) (CancellationAck, error) {
	canceler.requests = append(canceler.requests, request)
	if canceler.errAt > 0 && len(canceler.requests) == canceler.errAt {
		return CancellationAck{}, errors.New("cancel dependency unavailable")
	}
	return CancellationAck{TaskID: request.TaskID, Outcome: "canceled",
		EvidenceDigest:   testDigest("cancel-evidence-" + request.TaskID + reason),
		ProvenanceDigest: testDigest("cancel-provenance-" + request.TaskID + reason)}, nil
}

func TestCancellationPersistsDescendantFirstTargetsAcknowledgmentsAndSettlement(t *testing.T) {
	controller, _, authority, budgets, _ := newFixture(t)
	if _, err := controller.Create(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	child := delegateRequest("cancel-child", HuntingRole, testRoot)
	if _, err := controller.Delegate(context.Background(), child); err != nil {
		t.Fatal(err)
	}
	grandchild := delegateRequest("cancel-grandchild", ReviewerRole, child.TaskID)
	grandchild.BudgetClaim.DelegationDepth = 2
	if _, err := controller.Delegate(context.Background(), grandchild); err != nil {
		t.Fatal(err)
	}
	canceler := &recordingCanceler{}
	controller.canceler = canceler
	request := cancelRequest(child.TaskID, "cancel-subtree")
	result, err := controller.Cancel(context.Background(), request)
	if err != nil || result.Task.Status != TaskCanceled || len(result.Graph.Cancellations) != 1 ||
		result.Graph.Cancellations[0].Status != CancellationCompleted ||
		len(result.Graph.Cancellations[0].Acknowledgments) != 2 || budgets.settles != 2 {
		t.Fatalf("result=%+v err=%v settles=%d", result, err, budgets.settles)
	}
	if len(canceler.requests) != 2 || canceler.requests[0].TaskID != grandchild.TaskID ||
		canceler.requests[1].TaskID != child.TaskID || authority.last.Operation != Cancel {
		t.Fatalf("cancel order=%+v authority=%+v", canceler.requests, authority.last)
	}
	replay, err := controller.Cancel(context.Background(), request)
	if err != nil || !replay.Replayed || len(canceler.requests) != 2 || budgets.settles != 2 {
		t.Fatalf("replay=%+v err=%v cancel=%d settle=%d", replay, err, len(canceler.requests), budgets.settles)
	}
}

func TestCancellationDependencyFailureLeavesDurableActivePlanForRecovery(t *testing.T) {
	controller, _, _, budgets, store := newFixture(t)
	if _, err := controller.Create(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	child := delegateRequest("cancel-recover", ValidationRole, testRoot)
	if _, err := controller.Delegate(context.Background(), child); err != nil {
		t.Fatal(err)
	}
	controller.canceler = &recordingCanceler{errAt: 1}
	request := cancelRequest(child.TaskID, "cancel-recover")
	if _, err := controller.Cancel(context.Background(), request); CodeOf(err) != Unavailable {
		t.Fatalf("err=%v", err)
	}
	stored, _, _ := store.Load(context.Background(), createRequest().Case, testGraph)
	if len(stored.Cancellations) != 1 || stored.Cancellations[0].Status != CancellationActive ||
		len(stored.Cancellations[0].TargetTaskIDs) != 1 || len(stored.Cancellations[0].Acknowledgments) != 0 {
		t.Fatalf("durable cancellation=%+v", stored.Cancellations)
	}
	budgetCalls := budgets.calls
	blocked := delegateRequest("beneath-active-cancellation", ReviewerRole, child.TaskID)
	blocked.BudgetClaim.DelegationDepth = 2
	if _, err := controller.Delegate(context.Background(), blocked); CodeOf(err) != Denied ||
		Reason(err) != "parent_invalid" || budgets.calls != budgetCalls {
		t.Fatalf("delegation under active cancellation err=%v budget calls=%d", err, budgets.calls)
	}
	controller.canceler = &recordingCanceler{}
	result, err := controller.Cancel(context.Background(), request)
	if err != nil || result.Task.Status != TaskCanceled || result.Graph.Cancellations[0].Status != CancellationCompleted {
		t.Fatalf("recovered=%+v err=%v", result, err)
	}
}

func TestCancellationValidationRejectsIncompleteSubtreeAndUnboundAcknowledgment(t *testing.T) {
	controller, _, _, _, _ := newFixture(t)
	if _, err := controller.Create(context.Background(), createRequest()); err != nil {
		t.Fatal(err)
	}
	child := delegateRequest("validate-cancel-child", HuntingRole, testRoot)
	if _, err := controller.Delegate(context.Background(), child); err != nil {
		t.Fatal(err)
	}
	grandchild := delegateRequest("validate-cancel-grandchild", ReviewerRole, child.TaskID)
	grandchild.BudgetClaim.DelegationDepth = 2
	if _, err := controller.Delegate(context.Background(), grandchild); err != nil {
		t.Fatal(err)
	}
	controller.canceler = &recordingCanceler{}
	result, err := controller.Cancel(context.Background(), cancelRequest(child.TaskID, "validate-cancel"))
	if err != nil {
		t.Fatal(err)
	}
	incomplete := cloneGraph(result.Graph)
	incomplete.Cancellations[0].TargetTaskIDs = incomplete.Cancellations[0].TargetTaskIDs[1:]
	incomplete.Cancellations[0].Acknowledgments = incomplete.Cancellations[0].Acknowledgments[1:]
	incomplete.ProvenanceDigest = ""
	incomplete.ProvenanceDigest, _ = graphProvenanceDigest(incomplete)
	if err = validateGraph(incomplete); CodeOf(err) != Denied {
		t.Fatalf("incomplete subtree accepted: %v", err)
	}
	unbound := cloneGraph(result.Graph)
	task, _ := findTask(unbound, child.TaskID)
	for index := range unbound.Tasks {
		if unbound.Tasks[index].TaskID == task.TaskID {
			unbound.Tasks[index].Cancellation.EvidenceDigest = testDigest("forged-ack")
			unbound.Tasks[index].ProvenanceDigest = ""
			unbound.Tasks[index].ProvenanceDigest, _ = taskProvenanceDigest(unbound.Tasks[index])
		}
	}
	unbound.ProvenanceDigest = ""
	unbound.ProvenanceDigest, _ = graphProvenanceDigest(unbound)
	if err = validateGraph(unbound); CodeOf(err) != Denied {
		t.Fatalf("unbound acknowledgment accepted: %v", err)
	}
}

func cancelRequest(taskID, key string) CancelRequest {
	return CancelRequest{RequestID: testUUID("request-" + key), IdempotencyKey: key, GraphID: testGraph,
		TaskID: taskID, Case: createRequest().Case, ActorID: testActor, ActorRevision: 3,
		PolicyDigest: testDigest("policy"), ReasonDigest: testDigest("reason-" + key)}
}
