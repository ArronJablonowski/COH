package subagentdag

import (
	"context"
	"sort"
	"time"
)

func (controller *Controller) Cancel(ctx context.Context, request CancelRequest) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	if err := validateCancelRequest(request); err != nil {
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
	root, found := findTask(current, request.TaskID)
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
		ReasonDigest     string   `json:"reason_digest"`
		AssignmentDigest string   `json:"assignment_digest"`
	}{request.RequestID, request.GraphID, request.TaskID, caseToWire(request.Case), request.ActorID,
		request.ActorRevision, request.PolicyDigest, request.ReasonDigest, root.AssignmentDigest})
	if err != nil {
		return Result{}, err
	}
	auth := AuthorizationRequest{IntentDigest: intent, Operation: Cancel, GraphID: request.GraphID,
		TaskID: request.TaskID, Case: request.Case, ActorID: request.ActorID,
		ActorRevision: request.ActorRevision, Role: root.Role, ParentTaskIDs: append([]string{}, root.ParentTaskIDs...),
		PolicyDigest: request.PolicyDigest, Deadline: current.Deadline}
	if err = controller.authorize(ctx, auth, now); err != nil {
		return Result{}, err
	}
	receipt := Receipt{Operation: Cancel, IdempotencyDigest: idempotencyDigest(request.IdempotencyKey),
		IntentDigest: intent, TaskID: request.TaskID}
	if recovered, ok := receiptResult(current, receipt); ok {
		recovered.Replayed = true
		return recovered, nil
	}
	if receiptChangedReplay(current, receipt) {
		return Result{}, newError(Denied, "changed_replay", false, nil)
	}
	recordIndex, record, exists := findCancellation(current, receipt.IdempotencyDigest)
	if exists && (record.IntentDigest != intent || record.RootTaskID != request.TaskID || record.ReasonDigest != request.ReasonDigest) {
		return Result{}, newError(Denied, "cancel_changed_replay", false, nil)
	}
	if !exists {
		targets := cancellationTargets(current, request.TaskID)
		if len(targets) == 0 {
			return Result{}, newError(NotFound, "cancellation_target_missing", false, nil)
		}
		record = CancellationRecord{CancellationID: request.RequestID, RootTaskID: request.TaskID,
			ReasonDigest: request.ReasonDigest, TargetTaskIDs: targets, Acknowledgments: []CancellationAck{},
			Status: CancellationActive, IntentDigest: intent, IdempotencyDigest: receipt.IdempotencyDigest,
			CreatedAt: now, UpdatedAt: now, Revision: 1}
		current, err = controller.saveCancellationRecord(ctx, request.IdempotencyKey+":prepared", current, -1, record, now)
		if err != nil {
			return Result{}, err
		}
		recordIndex, record, _ = findCancellation(current, receipt.IdempotencyDigest)
	}
	for len(record.Acknowledgments) < len(record.TargetTaskIDs) {
		targetID := record.TargetTaskIDs[len(record.Acknowledgments)]
		task, found := findTask(current, targetID)
		if !found {
			return Result{}, newError(Denied, "cancellation_target_missing", false, nil)
		}
		ack := CancellationAck{}
		if terminalTask(task.Status) {
			ack = alreadyTerminalAck(task)
		} else {
			ack, err = controller.canceler.CancelChild(ctx, ExecutionRequest{GraphID: current.GraphID,
				TaskID: task.TaskID, Role: task.Role, InputRefs: append([]string{}, task.InputRefs...),
				AssignmentDigest: task.AssignmentDigest, Deadline: task.Deadline}, request.ReasonDigest)
			if err != nil {
				return Result{}, mapDependency(ctx, "cancellation_unavailable", err)
			}
			if validateCancellation(&ack, task.TaskID) != nil || ack.Outcome == "already_terminal" {
				return Result{}, newError(Denied, "cancellation_ack_invalid", false, nil)
			}
		}
		current, task, err = controller.applyCancellationAck(ctx, request.IdempotencyKey+":ack", current,
			recordIndex, task, ack, now)
		if err != nil {
			return Result{}, err
		}
		if terminalTask(task.Status) && task.BudgetSettlementDigest == "" {
			settled, settleErr := controller.settleAndBind(ctx, request.IdempotencyKey+":cancel", current, task)
			if settleErr != nil {
				return Result{}, settleErr
			}
			current = settled.Graph
		}
		recordIndex, record, _ = findCancellation(current, receipt.IdempotencyDigest)
	}
	record.Status = CancellationCompleted
	for _, ack := range record.Acknowledgments {
		if ack.Outcome == "uncertain" {
			record.Status = CancellationUncertain
		}
	}
	record.Revision++
	record.UpdatedAt = now
	current, err = controller.saveCancellationRecord(ctx, request.IdempotencyKey+":complete", current, recordIndex, record, now)
	if err != nil {
		return Result{}, err
	}
	receipt.Revision = current.Revision + 1
	current, err = controller.addReceipt(ctx, request.IdempotencyKey+":receipt", current, receipt, now)
	if err != nil {
		return Result{}, err
	}
	root, found = findTask(current, request.TaskID)
	if !found {
		return Result{}, newError(Denied, "cancel_result_invalid", false, nil)
	}
	return Result{Graph: cloneGraph(current), Task: root}, nil
}

func cancellationTargets(graph Graph, root string) []string {
	reachable := map[string]bool{root: true}
	changed := true
	for changed {
		changed = false
		for _, edge := range graph.Edges {
			if reachable[edge.ParentTaskID] && !reachable[edge.ChildTaskID] {
				reachable[edge.ChildTaskID] = true
				changed = true
			}
		}
	}
	result := make([]Task, 0, len(reachable))
	for _, task := range graph.Tasks {
		if reachable[task.TaskID] {
			result = append(result, task)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Depth != result[j].Depth {
			return result[i].Depth > result[j].Depth
		}
		return result[i].TaskID < result[j].TaskID
	})
	ids := make([]string, len(result))
	for index := range result {
		ids[index] = result[index].TaskID
	}
	return ids
}

func (controller *Controller) applyCancellationAck(ctx context.Context, key string, graph Graph,
	recordIndex int, task Task, ack CancellationAck, now time.Time) (Graph, Task, error) {
	next := cloneGraph(graph)
	taskIndex := sort.Search(len(next.Tasks), func(index int) bool { return next.Tasks[index].TaskID >= task.TaskID })
	if taskIndex == len(next.Tasks) || next.Tasks[taskIndex].TaskID != task.TaskID ||
		recordIndex < 0 || recordIndex >= len(next.Cancellations) {
		return Graph{}, Task{}, newError(Conflict, "cancellation_transition_conflict", true, nil)
	}
	if !terminalTask(task.Status) {
		updated := cloneTask(task)
		updated.PreviousProvenanceDigest = task.ProvenanceDigest
		updated.ProvenanceDigest = ""
		updated.UpdatedAt = now
		updated.Revision++
		updated.Cancellation = cloneCancellation(&ack)
		if ack.Outcome == "canceled" {
			updated.Status = TaskCanceled
		} else {
			updated.Status = TaskUncertain
		}
		var err error
		updated.ProvenanceDigest, err = taskProvenanceDigest(updated)
		if err != nil {
			return Graph{}, Task{}, err
		}
		next.Tasks[taskIndex] = updated
		task = updated
	}
	record := next.Cancellations[recordIndex]
	record.Acknowledgments = append(record.Acknowledgments, ack)
	if len(record.Acknowledgments) == len(record.TargetTaskIDs) {
		record.Status = CancellationCompleted
		for _, current := range record.Acknowledgments {
			if current.Outcome == "uncertain" {
				record.Status = CancellationUncertain
			}
		}
	}
	record.Revision++
	record.UpdatedAt = now
	next.Cancellations[recordIndex] = record
	stored, err := controller.saveGraph(ctx, key+":"+task.TaskID, graph, next, now)
	if err != nil {
		return Graph{}, Task{}, err
	}
	storedTask, _ := findTask(stored, task.TaskID)
	return stored, storedTask, nil
}

func (controller *Controller) saveCancellationRecord(ctx context.Context, key string, graph Graph,
	index int, record CancellationRecord, now time.Time) (Graph, error) {
	next := cloneGraph(graph)
	if index < 0 {
		next.Cancellations = append(next.Cancellations, record)
		sort.Slice(next.Cancellations, func(i, j int) bool {
			return next.Cancellations[i].CancellationID < next.Cancellations[j].CancellationID
		})
	} else if index < len(next.Cancellations) {
		next.Cancellations[index] = record
	} else {
		return Graph{}, newError(Conflict, "cancellation_record_conflict", true, nil)
	}
	return controller.saveGraph(ctx, key, graph, next, now)
}

func (controller *Controller) addReceipt(ctx context.Context, key string, graph Graph,
	receipt Receipt, now time.Time) (Graph, error) {
	next := cloneGraph(graph)
	next.Receipts = append(next.Receipts, receipt)
	sort.Slice(next.Receipts, func(i, j int) bool { return next.Receipts[i].IdempotencyDigest < next.Receipts[j].IdempotencyDigest })
	return controller.saveGraph(ctx, key, graph, next, now)
}

func (controller *Controller) saveGraph(ctx context.Context, key string, graph, next Graph, now time.Time) (Graph, error) {
	next.PreviousProvenanceDigest = graph.ProvenanceDigest
	next.ProvenanceDigest = ""
	next.UpdatedAt = now
	next.Revision = graph.Revision + 1
	var err error
	next.ProvenanceDigest, err = graphProvenanceDigest(next)
	if err != nil || validateGraph(next) != nil {
		return Graph{}, newError(Internal, "graph_transition_invalid", false, err)
	}
	stored, _, err := controller.store.Save(ctx, key, graph, next)
	if err != nil {
		return Graph{}, mapStoreError("graph_save", err)
	}
	if validateGraph(stored) != nil || stored.ProvenanceDigest != next.ProvenanceDigest {
		return Graph{}, newError(Denied, "graph_store_invalid", false, nil)
	}
	return cloneGraph(stored), nil
}

func findCancellation(graph Graph, idempotency string) (int, CancellationRecord, bool) {
	for index, record := range graph.Cancellations {
		if record.IdempotencyDigest == idempotency {
			return index, record, true
		}
	}
	return -1, CancellationRecord{}, false
}

func alreadyTerminalAck(task Task) CancellationAck {
	evidence := task.ProvenanceDigest
	return CancellationAck{TaskID: task.TaskID, Outcome: "already_terminal", EvidenceDigest: evidence,
		ProvenanceDigest: digest("COH-SUBAGENT-DAG-CANCEL-ACK-V1\x00", []byte(task.TaskID+"\x00"+evidence+"\x00already_terminal"))}
}
