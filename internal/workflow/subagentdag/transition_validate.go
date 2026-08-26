package subagentdag

import (
	"reflect"
	"slices"
)

func validateGraphTransition(prior, next Graph) error {
	if !sameGraphIdentity(prior, next) || next.Revision != prior.Revision+1 ||
		next.PreviousProvenanceDigest != prior.ProvenanceDigest || next.UpdatedAt.Before(prior.UpdatedAt) ||
		len(next.Tasks) < len(prior.Tasks) || len(next.Edges) < len(prior.Edges) ||
		len(next.Receipts) < len(prior.Receipts) || len(next.Cancellations) < len(prior.Cancellations) {
		return newError(Denied, "graph_transition_invalid", false, nil)
	}
	for _, oldTask := range prior.Tasks {
		newTask, found := findTask(next, oldTask.TaskID)
		if !found || validateTaskTransition(oldTask, newTask) != nil {
			return newError(Denied, "graph_task_transition_invalid", false, nil)
		}
	}
	for _, newTask := range next.Tasks {
		if _, found := findTask(prior, newTask.TaskID); !found &&
			(newTask.Revision != 1 || newTask.Status != TaskPending || newTask.PreviousProvenanceDigest == "") {
			return newError(Denied, "graph_new_task_invalid", false, nil)
		}
	}
	if !edgeSubset(prior.Edges, next.Edges) || !receiptSubset(prior.Receipts, next.Receipts) ||
		!cancellationTransitionsValid(prior.Cancellations, next.Cancellations) {
		return newError(Denied, "graph_append_only_transition_invalid", false, nil)
	}
	return nil
}

func validateTaskTransition(prior, next Task) error {
	if sameTask(prior, next) {
		return nil
	}
	if prior.TaskID != next.TaskID || !slices.Equal(prior.ParentTaskIDs, next.ParentTaskIDs) ||
		prior.Role != next.Role || prior.Depth != next.Depth || !slices.Equal(prior.InputRefs, next.InputRefs) ||
		prior.AssignmentDigest != next.AssignmentDigest ||
		prior.BudgetReservationDigest != next.BudgetReservationDigest ||
		!prior.CreatedAt.Equal(next.CreatedAt) || !prior.Deadline.Equal(next.Deadline) ||
		next.Revision != prior.Revision+1 || next.PreviousProvenanceDigest != prior.ProvenanceDigest ||
		next.UpdatedAt.Before(prior.UpdatedAt) {
		return newError(Denied, "task_transition_invalid", false, nil)
	}
	if terminalTask(prior.Status) {
		if next.Status != prior.Status || prior.BudgetSettlementDigest != "" || next.BudgetSettlementDigest == "" ||
			!reflect.DeepEqual(prior.Result, next.Result) || !reflect.DeepEqual(prior.Cancellation, next.Cancellation) {
			return newError(Denied, "task_terminal_transition_invalid", false, nil)
		}
		return nil
	}
	if prior.BudgetSettlementDigest != "" || next.BudgetSettlementDigest != "" {
		return newError(Denied, "task_early_settlement_invalid", false, nil)
	}
	switch prior.Status {
	case TaskPending:
		if !slices.Contains([]TaskStatus{TaskDispatching, TaskCanceled, TaskTimedOut, TaskUncertain}, next.Status) {
			return newError(Denied, "task_pending_transition_invalid", false, nil)
		}
	case TaskDispatching:
		if !slices.Contains([]TaskStatus{TaskSucceeded, TaskFailed, TaskDenied, TaskCanceled, TaskTimedOut, TaskUncertain}, next.Status) {
			return newError(Denied, "task_dispatch_transition_invalid", false, nil)
		}
	default:
		return newError(Denied, "task_transition_invalid", false, nil)
	}
	return nil
}

func sameTask(left, right Task) bool {
	return reflect.DeepEqual(left, right)
}

func edgeSubset(prior, next []Edge) bool {
	available := make(map[Edge]bool, len(next))
	for _, edge := range next {
		available[edge] = true
	}
	for _, edge := range prior {
		if !available[edge] {
			return false
		}
	}
	return true
}

func receiptSubset(prior, next []Receipt) bool {
	available := make(map[string]Receipt, len(next))
	for _, receipt := range next {
		available[receipt.IdempotencyDigest] = receipt
	}
	for _, receipt := range prior {
		if current, found := available[receipt.IdempotencyDigest]; !found || current != receipt {
			return false
		}
	}
	return true
}

func cancellationTransitionsValid(prior, next []CancellationRecord) bool {
	available := make(map[string]CancellationRecord, len(next))
	for _, record := range next {
		available[record.CancellationID] = record
	}
	for _, oldRecord := range prior {
		newRecord, found := available[oldRecord.CancellationID]
		if !found {
			return false
		}
		if reflect.DeepEqual(oldRecord, newRecord) {
			continue
		}
		if oldRecord.CancellationID != newRecord.CancellationID || oldRecord.RootTaskID != newRecord.RootTaskID ||
			oldRecord.ReasonDigest != newRecord.ReasonDigest ||
			!slices.Equal(oldRecord.TargetTaskIDs, newRecord.TargetTaskIDs) ||
			oldRecord.IntentDigest != newRecord.IntentDigest || oldRecord.IdempotencyDigest != newRecord.IdempotencyDigest ||
			!oldRecord.CreatedAt.Equal(newRecord.CreatedAt) || newRecord.UpdatedAt.Before(oldRecord.UpdatedAt) ||
			newRecord.Revision != oldRecord.Revision+1 || len(newRecord.Acknowledgments) < len(oldRecord.Acknowledgments) ||
			!slices.Equal(oldRecord.Acknowledgments, newRecord.Acknowledgments[:len(oldRecord.Acknowledgments)]) {
			return false
		}
		if oldRecord.Status != CancellationActive && newRecord.Status != oldRecord.Status {
			return false
		}
	}
	for _, newRecord := range next {
		found := false
		for _, oldRecord := range prior {
			found = found || oldRecord.CancellationID == newRecord.CancellationID
		}
		if !found && (newRecord.Revision != 1 || newRecord.Status != CancellationActive ||
			len(newRecord.Acknowledgments) != 0) {
			return false
		}
	}
	return true
}
