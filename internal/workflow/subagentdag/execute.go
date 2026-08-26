package subagentdag

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/runbudget"
)

func (controller *Controller) Execute(ctx context.Context, request ExecuteRequest) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	if err := validateExecuteRequest(request); err != nil {
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
	auth := AuthorizationRequest{IntentDigest: intent, Operation: Execute, GraphID: request.GraphID,
		TaskID: request.TaskID, Case: request.Case, ActorID: request.ActorID,
		ActorRevision: request.ActorRevision, Role: task.Role, ParentTaskIDs: append([]string{}, task.ParentTaskIDs...),
		PolicyDigest: request.PolicyDigest, Deadline: current.Deadline}
	if err = controller.authorize(ctx, auth, now); err != nil {
		return Result{}, err
	}
	receipt := Receipt{Operation: Execute, IdempotencyDigest: idempotencyDigest(request.IdempotencyKey),
		IntentDigest: intent, TaskID: request.TaskID}
	if recovered, ok := receiptResult(current, receipt); ok {
		if recovered.Task.BudgetSettlementDigest == "" && terminalTask(recovered.Task.Status) {
			return controller.settleAndBind(ctx, request.IdempotencyKey+":recovery", recovered.Graph, recovered.Task)
		}
		recovered.Replayed = true
		return recovered, nil
	}
	if receiptChangedReplay(current, receipt) {
		return Result{}, newError(Denied, "changed_replay", false, nil)
	}
	if terminalTask(task.Status) {
		return Result{}, newError(Denied, "execute_replay_invalid", false, nil)
	}
	if task.Status == TaskDispatching {
		persisted, persistErr := controller.finishTask(ctx, request.IdempotencyKey+":uncertain",
			current, task, TaskUncertain, nil, nil, receipt, now)
		if persistErr != nil {
			return Result{}, persistErr
		}
		_, settleErr := controller.settleAndBind(ctx, request.IdempotencyKey+":uncertain", persisted.Graph, persisted.Task)
		if settleErr != nil {
			return Result{}, settleErr
		}
		return Result{}, newError(Conflict, "dispatch_result_unknown", false, nil)
	}
	if !now.Before(task.Deadline) {
		persisted, persistErr := controller.finishTask(ctx, request.IdempotencyKey+":timeout",
			current, task, TaskTimedOut, nil, nil, receipt, now)
		if persistErr != nil {
			return Result{}, persistErr
		}
		_, _ = controller.settleAndBind(ctx, request.IdempotencyKey+":timeout", persisted.Graph, persisted.Task)
		return Result{}, newError(Timeout, "task_deadline_elapsed", false, context.DeadlineExceeded)
	}
	dispatching, err := controller.transitionTask(ctx, request.IdempotencyKey+":dispatch", current, task,
		func(next *Task) { next.Status = TaskDispatching }, now)
	if err != nil {
		return Result{}, err
	}
	opCtx, cancel := context.WithDeadline(ctx, task.Deadline)
	defer cancel()
	output, runErr := controller.runtime.RunChild(opCtx, ExecutionRequest{GraphID: current.GraphID,
		TaskID: task.TaskID, Role: task.Role, InputRefs: append([]string{}, task.InputRefs...),
		AssignmentDigest: task.AssignmentDigest, Deadline: task.Deadline})
	finishedAt, clockErr := controller.now()
	if clockErr != nil {
		return Result{}, clockErr
	}
	status := TaskSucceeded
	var outputPointer *StructuredResult
	if runErr != nil {
		status = TaskFailed
		if errors.Is(opCtx.Err(), context.Canceled) {
			// A canceled caller cannot prove whether the external child stopped.
			// Mark it uncertain; only the explicit cancellation protocol may
			// persist TaskCanceled with a cancellation acknowledgement.
			status = TaskUncertain
		}
		if errors.Is(opCtx.Err(), context.DeadlineExceeded) {
			status = TaskTimedOut
		}
	} else if !finishedAt.Before(task.Deadline) {
		status = TaskTimedOut
		runErr = context.DeadlineExceeded
	} else if validateStructuredResult(output) != nil || output.TaskID != task.TaskID || output.Role != task.Role {
		status = TaskDenied
		runErr = newError(Denied, "runtime_result_invalid", false, nil)
	} else {
		copyOutput := cloneStructuredResult(output)
		outputPointer = &copyOutput
	}
	persistCtx, persistCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer persistCancel()
	persisted, err := controller.finishTask(persistCtx, request.IdempotencyKey+":terminal", dispatching.Graph,
		dispatching.Task, status, outputPointer, nil, receipt, finishedAt)
	if err != nil {
		return Result{}, err
	}
	settled, err := controller.settleAndBind(persistCtx, request.IdempotencyKey, persisted.Graph, persisted.Task)
	if err != nil {
		return Result{}, err
	}
	if runErr != nil {
		return Result{}, mapRuntimeError(opCtx, status, runErr)
	}
	return settled, nil
}

func (controller *Controller) finishTask(ctx context.Context, key string, graph Graph, task Task,
	status TaskStatus, result *StructuredResult, cancellation *CancellationAck, receipt Receipt,
	now time.Time) (Result, error) {
	receipt.Revision = graph.Revision + 2
	transitioned, err := controller.transitionTask(ctx, key, graph, task, func(value *Task) {
		value.Status = status
		value.Result = cloneResultPointer(result)
		value.Cancellation = cloneCancellation(cancellation)
	}, now)
	if err != nil {
		return Result{}, err
	}
	updated := cloneGraph(transitioned.Graph)
	updated.Receipts = append(updated.Receipts, receipt)
	sort.Slice(updated.Receipts, func(i, j int) bool {
		return updated.Receipts[i].IdempotencyDigest < updated.Receipts[j].IdempotencyDigest
	})
	updated.PreviousProvenanceDigest = transitioned.Graph.ProvenanceDigest
	updated.ProvenanceDigest = ""
	updated.Revision++
	updated.UpdatedAt = now
	updated.ProvenanceDigest, err = graphProvenanceDigest(updated)
	if err != nil || validateGraph(updated) != nil {
		return Result{}, newError(Internal, "terminal_receipt_invalid", false, err)
	}
	stored, replayed, err := controller.store.Save(ctx, key+":receipt", transitioned.Graph, updated)
	if err != nil {
		return Result{}, mapStoreError("terminal_save", err)
	}
	storedTask, found := findTask(stored, task.TaskID)
	if !found || validateGraph(stored) != nil {
		return Result{}, newError(Denied, "terminal_store_invalid", false, nil)
	}
	return Result{Graph: cloneGraph(stored), Task: storedTask, Replayed: replayed}, nil
}

func (controller *Controller) transitionTask(ctx context.Context, key string, graph Graph, task Task,
	mutate func(*Task), now time.Time) (Result, error) {
	next := cloneGraph(graph)
	index := sort.Search(len(next.Tasks), func(index int) bool { return next.Tasks[index].TaskID >= task.TaskID })
	if index == len(next.Tasks) || next.Tasks[index].TaskID != task.TaskID || next.Tasks[index].ProvenanceDigest != task.ProvenanceDigest {
		return Result{}, newError(Conflict, "task_transition_conflict", true, nil)
	}
	nextTask := cloneTask(next.Tasks[index])
	nextTask.PreviousProvenanceDigest = task.ProvenanceDigest
	nextTask.ProvenanceDigest = ""
	nextTask.UpdatedAt = now
	nextTask.Revision++
	mutate(&nextTask)
	var err error
	nextTask.ProvenanceDigest, err = taskProvenanceDigest(nextTask)
	if err != nil {
		return Result{}, err
	}
	next.Tasks[index] = nextTask
	next.PreviousProvenanceDigest = graph.ProvenanceDigest
	next.ProvenanceDigest = ""
	next.UpdatedAt = now
	next.Revision++
	next.ProvenanceDigest, err = graphProvenanceDigest(next)
	if err != nil || validateGraph(next) != nil {
		return Result{}, newError(Internal, "task_transition_invalid", false, err)
	}
	stored, replayed, err := controller.store.Save(ctx, key, graph, next)
	if err != nil {
		return Result{}, mapStoreError("task_transition", err)
	}
	storedTask, found := findTask(stored, task.TaskID)
	if !found || validateGraph(stored) != nil {
		return Result{}, newError(Denied, "task_transition_store_invalid", false, nil)
	}
	return Result{Graph: cloneGraph(stored), Task: storedTask, Replayed: replayed}, nil
}

func (controller *Controller) settleAndBind(ctx context.Context, key string, graph Graph, task Task) (Result, error) {
	if !terminalTask(task.Status) {
		return Result{}, newError(Conflict, "task_not_terminal", false, nil)
	}
	if task.BudgetSettlementDigest != "" {
		return Result{Graph: cloneGraph(graph), Task: cloneTask(task), Replayed: true}, nil
	}
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	settlement, err := controller.budgets.Settle(persistCtx, runbudget.SettlementRequest{
		IdempotencyKey: "subagent-settle:" + graph.GraphID + ":" + task.TaskID,
		RunID:          graph.RunID, TaskID: task.TaskID, Case: graph.Case,
		ReservationDigest: task.BudgetReservationDigest, Outcome: budgetOutcome(task.Status)})
	if err != nil {
		return Result{}, mapBudgetError(err)
	}
	if settlement.ReservationDigest != task.BudgetReservationDigest || !digestPattern.MatchString(settlement.SettlementDigest) {
		return Result{}, newError(Denied, "budget_settlement_invalid", false, nil)
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	return controller.transitionTask(persistCtx, key+":settled", graph, task,
		func(value *Task) { value.BudgetSettlementDigest = settlement.SettlementDigest }, now)
}

func budgetOutcome(status TaskStatus) string {
	switch status {
	case TaskSucceeded:
		return "succeeded"
	case TaskDenied:
		return "denied"
	case TaskCanceled:
		return "canceled"
	case TaskTimedOut:
		return "timeout"
	case TaskUncertain:
		return "uncertain"
	default:
		return "failed"
	}
}

func mapRuntimeError(ctx context.Context, status TaskStatus, err error) error {
	if status == TaskCanceled || ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return newError(Canceled, "runtime_canceled", false, context.Canceled)
	}
	if status == TaskTimedOut || ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newError(Timeout, "runtime_timeout", false, context.DeadlineExceeded)
	}
	if CodeOf(err) == Denied {
		return err
	}
	return newError(Unavailable, "runtime_failed", true, err)
}
