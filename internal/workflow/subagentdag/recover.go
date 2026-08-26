package subagentdag

import "context"

func (controller *Controller) Recover(ctx context.Context, request RecoverRequest) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	if err := validateRecoverRequest(request); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	current, found, err := controller.store.Load(ctx, request.Case, request.GraphID)
	if err != nil {
		return Result{}, mapStoreError("graph_load", err)
	}
	if !found {
		return Result{}, newError(NotFound, "graph_not_found", false, nil)
	}
	if err = validateGraph(current); err != nil {
		return Result{}, err
	}
	if err = bindGraphRequest(current, request.Case, request.GraphID, request.ActorID,
		request.ActorRevision, request.PolicyDigest, now); err != nil {
		return Result{}, err
	}
	task, found := findTask(current, request.TaskID)
	if !found {
		return Result{}, newError(NotFound, "task_not_found", false, nil)
	}
	intent, err := authorizationIntentDigest(struct {
		RequestID        string   `json:"request_id"`
		GraphID          string   `json:"graph_id"`
		TaskID           string   `json:"task_id"`
		Case             caseWire `json:"case"`
		ActorID          string   `json:"actor_id"`
		ActorRevision    uint64   `json:"actor_revision"`
		PolicyDigest     string   `json:"policy_digest"`
		AssignmentDigest string   `json:"assignment_digest"`
	}{request.RequestID, request.GraphID, request.TaskID, caseToWire(request.Case), request.ActorID,
		request.ActorRevision, request.PolicyDigest, task.AssignmentDigest})
	if err != nil {
		return Result{}, err
	}
	auth := AuthorizationRequest{IntentDigest: intent, Operation: Recover, GraphID: request.GraphID,
		TaskID: request.TaskID, Case: request.Case, ActorID: request.ActorID,
		ActorRevision: request.ActorRevision, Role: task.Role, ParentTaskIDs: append([]string{}, task.ParentTaskIDs...),
		PolicyDigest: request.PolicyDigest, Deadline: current.Deadline}
	if err = controller.authorize(ctx, auth, now); err != nil {
		return Result{}, err
	}
	receipt := Receipt{Operation: Recover, IdempotencyDigest: idempotencyDigest(request.IdempotencyKey),
		IntentDigest: intent, TaskID: request.TaskID}
	if recovered, ok := receiptResult(current, receipt); ok {
		if terminalTask(recovered.Task.Status) && recovered.Task.BudgetSettlementDigest == "" {
			return controller.settleAndBind(ctx, request.IdempotencyKey+":recovery", recovered.Graph, recovered.Task)
		}
		recovered.Replayed = true
		return recovered, nil
	}
	if receiptChangedReplay(current, receipt) {
		return Result{}, newError(Denied, "changed_replay", false, nil)
	}
	if task.Status == TaskDispatching {
		receipt.Revision = current.Revision + 2
		persisted, finishErr := controller.finishTask(ctx, request.IdempotencyKey+":uncertain",
			current, task, TaskUncertain, nil, nil, receipt, now)
		if finishErr != nil {
			return Result{}, finishErr
		}
		return controller.settleAndBind(ctx, request.IdempotencyKey+":uncertain", persisted.Graph, persisted.Task)
	}
	receipt.Revision = current.Revision + 1
	current, err = controller.addReceipt(ctx, request.IdempotencyKey+":receipt", current, receipt, now)
	if err != nil {
		return Result{}, err
	}
	task, _ = findTask(current, request.TaskID)
	if terminalTask(task.Status) && task.BudgetSettlementDigest == "" {
		return controller.settleAndBind(ctx, request.IdempotencyKey+":settle", current, task)
	}
	return Result{Graph: cloneGraph(current), Task: task}, nil
}
