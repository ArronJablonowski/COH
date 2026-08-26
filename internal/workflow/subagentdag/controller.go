package subagentdag

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/runbudget"
)

type Controller struct {
	store     Store
	authority Authority
	runtime   Runtime
	canceler  Canceler
	budgets   runbudget.Authority
	clock     Clock
}

func New(store Store, authority Authority, runtime Runtime, canceler Canceler,
	budgets runbudget.Authority, clock Clock) (*Controller, error) {
	if store == nil || authority == nil || runtime == nil || canceler == nil || budgets == nil || clock == nil {
		return nil, newError(InvalidInput, "dependencies_required", false, nil)
	}
	return &Controller{store, authority, runtime, canceler, budgets, clock}, nil
}

func (controller *Controller) Create(ctx context.Context, request CreateRequest) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err = validateCreateRequest(request, now); err != nil {
		return Result{}, err
	}
	planBytes, err := runbudget.CanonicalPlan(request.BudgetPlan)
	if err != nil {
		return Result{}, newError(InvalidInput, "budget_plan_invalid", false, err)
	}
	intent, err := authorizationIntentDigest(struct {
		RequestID      string           `json:"request_id"`
		GraphID        string           `json:"graph_id"`
		RunID          string           `json:"run_id"`
		RootTaskID     string           `json:"root_task_id"`
		Case           caseWire         `json:"case"`
		ActorID        string           `json:"actor_id"`
		ActorRevision  uint64           `json:"actor_revision"`
		PolicyDigest   string           `json:"policy_digest"`
		ProviderRoute  string           `json:"provider_route"`
		Limits         Limits           `json:"limits"`
		InputRefs      []string         `json:"input_refs"`
		Deadline       string           `json:"deadline"`
		BudgetPlanHash string           `json:"budget_plan_hash"`
		TaskBudget     runbudget.Vector `json:"task_budget"`
		BudgetClaim    runbudget.Vector `json:"budget_claim"`
	}{request.RequestID, request.GraphID, request.RunID, request.RootTaskID, caseToWire(request.Case),
		request.ActorID, request.ActorRevision, request.PolicyDigest, request.ProviderRoute,
		request.Limits, append([]string{}, request.InputRefs...), formatTime(request.Deadline),
		rawDigest(planBytes), request.TaskBudget, request.BudgetClaim})
	if err != nil {
		return Result{}, err
	}
	auth := AuthorizationRequest{IntentDigest: intent, Operation: CreateGraph, GraphID: request.GraphID,
		TaskID: request.RootTaskID, Case: request.Case, ActorID: request.ActorID,
		ActorRevision: request.ActorRevision, Role: CoordinatorRole, PolicyDigest: request.PolicyDigest,
		Deadline: request.Deadline}
	if err = controller.authorize(ctx, auth, now); err != nil {
		return Result{}, err
	}
	reservation, err := controller.budgets.Reserve(ctx, runbudget.ReservationRequest{
		IdempotencyKey: request.IdempotencyKey, RunID: request.RunID, TaskID: request.RootTaskID,
		Case: request.Case, Activity: roleActivity(CoordinatorRole), PolicyDigest: request.PolicyDigest,
		ProviderRoute: request.ProviderRoute, Deadline: request.Deadline, Plan: &request.BudgetPlan,
		TaskLimits: request.TaskBudget, Claim: request.BudgetClaim})
	if err != nil {
		return Result{}, mapBudgetError(err)
	}
	root := Task{TaskID: request.RootTaskID, ParentTaskIDs: []string{}, Role: CoordinatorRole,
		Status: TaskPending, InputRefs: append([]string{}, request.InputRefs...),
		BudgetReservationDigest: reservation.ReservationDigest, CreatedAt: now, Deadline: request.Deadline,
		UpdatedAt: now, Revision: 1}
	root.AssignmentDigest, err = assignmentBindingDigest(root)
	if err != nil {
		return Result{}, err
	}
	root.ProvenanceDigest, err = taskProvenanceDigest(root)
	if err != nil {
		return Result{}, err
	}
	receipt := Receipt{Operation: CreateGraph, IdempotencyDigest: idempotencyDigest(request.IdempotencyKey),
		IntentDigest: intent, TaskID: request.RootTaskID, Revision: 1}
	graph := Graph{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion, GraphID: request.GraphID,
		RunID: request.RunID, Case: request.Case, ActorID: request.ActorID, ActorRevision: request.ActorRevision,
		PolicyDigest: request.PolicyDigest, ProviderRoute: request.ProviderRoute, Limits: request.Limits,
		BudgetPlanDigest: reservation.PlanDigest, Tasks: []Task{root}, Edges: []Edge{}, Receipts: []Receipt{receipt},
		Cancellations: []CancellationRecord{},
		CreatedAt:     now, Deadline: request.Deadline, UpdatedAt: now, Revision: 1}
	graph.ProvenanceDigest, err = graphProvenanceDigest(graph)
	if err != nil || validateGraph(graph) != nil {
		return Result{}, newError(Internal, "graph_build_invalid", false, err)
	}
	stored, replayed, err := controller.store.Begin(ctx, request.IdempotencyKey, graph)
	if err != nil {
		return Result{}, mapStoreError("graph_begin", err)
	}
	return controller.validateStoredResult(stored, receipt, replayed)
}

func (controller *Controller) Delegate(ctx context.Context, request DelegateRequest) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err = validateDelegateRequest(request, now); err != nil {
		return Result{}, err
	}
	intent, err := authorizationIntentDigest(struct {
		RequestID     string           `json:"request_id"`
		GraphID       string           `json:"graph_id"`
		TaskID        string           `json:"task_id"`
		ParentTaskIDs []string         `json:"parent_task_ids"`
		Case          caseWire         `json:"case"`
		ActorID       string           `json:"actor_id"`
		ActorRevision uint64           `json:"actor_revision"`
		Role          Role             `json:"role"`
		InputRefs     []string         `json:"input_refs"`
		PolicyDigest  string           `json:"policy_digest"`
		Deadline      string           `json:"deadline"`
		TaskBudget    runbudget.Vector `json:"task_budget"`
		BudgetClaim   runbudget.Vector `json:"budget_claim"`
	}{request.RequestID, request.GraphID, request.TaskID, append([]string{}, request.ParentTaskIDs...),
		caseToWire(request.Case), request.ActorID, request.ActorRevision, request.Role,
		append([]string{}, request.InputRefs...), request.PolicyDigest, formatTime(request.Deadline),
		request.TaskBudget, request.BudgetClaim})
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
	auth := AuthorizationRequest{IntentDigest: intent, Operation: Delegate, GraphID: request.GraphID,
		TaskID: request.TaskID, Case: request.Case, ActorID: request.ActorID,
		ActorRevision: request.ActorRevision, Role: request.Role,
		ParentTaskIDs: append([]string{}, request.ParentTaskIDs...), PolicyDigest: request.PolicyDigest,
		Deadline: request.Deadline}
	if err = controller.authorize(ctx, auth, now); err != nil {
		return Result{}, err
	}
	receipt := Receipt{Operation: Delegate, IdempotencyDigest: idempotencyDigest(request.IdempotencyKey),
		IntentDigest: intent, TaskID: request.TaskID}
	if recovered, ok := receiptResult(current, receipt); ok {
		reservation, budgetErr := controller.reserveChild(ctx, current, request)
		if budgetErr != nil {
			return Result{}, budgetErr
		}
		if recovered.Task.BudgetReservationDigest != reservation.ReservationDigest {
			return Result{}, newError(Denied, "budget_replay_invalid", false, nil)
		}
		recovered.Replayed = true
		return recovered, nil
	}
	if receiptChangedReplay(current, receipt) {
		return Result{}, newError(Denied, "changed_replay", false, nil)
	}
	if len(current.Tasks) >= int(current.Limits.MaximumTasks) || activeTasks(current) >= current.Limits.MaximumConcurrency {
		return Result{}, newError(Denied, "graph_capacity_exhausted", false, nil)
	}
	depth, previous, err := deriveChild(current, request)
	if err != nil {
		return Result{}, err
	}
	reservation, err := controller.reserveChild(ctx, current, request)
	if err != nil {
		return Result{}, err
	}
	task := Task{TaskID: request.TaskID, ParentTaskIDs: append([]string{}, request.ParentTaskIDs...),
		Role: request.Role, Status: TaskPending, Depth: depth, InputRefs: append([]string{}, request.InputRefs...),
		BudgetReservationDigest: reservation.ReservationDigest, PreviousProvenanceDigest: previous,
		CreatedAt: now, Deadline: request.Deadline, UpdatedAt: now, Revision: 1}
	task.AssignmentDigest, err = assignmentBindingDigest(task)
	if err != nil {
		return Result{}, err
	}
	task.ProvenanceDigest, err = taskProvenanceDigest(task)
	if err != nil {
		return Result{}, err
	}
	next := cloneGraph(current)
	next.Tasks = append(next.Tasks, task)
	sort.Slice(next.Tasks, func(i, j int) bool { return next.Tasks[i].TaskID < next.Tasks[j].TaskID })
	for _, parent := range request.ParentTaskIDs {
		next.Edges = append(next.Edges, Edge{ParentTaskID: parent, ChildTaskID: request.TaskID})
	}
	sort.Slice(next.Edges, func(i, j int) bool {
		return next.Edges[i].ParentTaskID+"\x00"+next.Edges[i].ChildTaskID < next.Edges[j].ParentTaskID+"\x00"+next.Edges[j].ChildTaskID
	})
	receipt.Revision = current.Revision + 1
	next.Receipts = append(next.Receipts, receipt)
	sort.Slice(next.Receipts, func(i, j int) bool { return next.Receipts[i].IdempotencyDigest < next.Receipts[j].IdempotencyDigest })
	next.PreviousProvenanceDigest = current.ProvenanceDigest
	next.ProvenanceDigest = ""
	next.UpdatedAt = now
	next.Revision++
	next.ProvenanceDigest, err = graphProvenanceDigest(next)
	if err != nil || validateGraph(next) != nil {
		return Result{}, newError(Internal, "delegated_graph_invalid", false, err)
	}
	stored, replayed, err := controller.store.Save(ctx, request.IdempotencyKey, current, next)
	if err != nil {
		return Result{}, mapStoreError("graph_save", err)
	}
	return controller.validateStoredResult(stored, receipt, replayed)
}

func (controller *Controller) authorize(ctx context.Context, request AuthorizationRequest, now time.Time) error {
	decision, err := controller.authority.AuthorizeDelegation(ctx, request)
	if err != nil {
		return mapDependency(ctx, "authority_unavailable", err)
	}
	if err = validateDecision(decision, request, now); err != nil {
		return err
	}
	if decision.Outcome != "allow" {
		return newError(Denied, decision.ReasonCode, false, nil)
	}
	return nil
}

func (controller *Controller) reserveChild(ctx context.Context, graph Graph, request DelegateRequest) (runbudget.Reservation, error) {
	reservation, err := controller.budgets.Reserve(ctx, runbudget.ReservationRequest{
		IdempotencyKey: request.IdempotencyKey, RunID: graph.RunID, TaskID: request.TaskID,
		ParentTaskID: request.ParentTaskIDs[0], Case: request.Case, Activity: roleActivity(request.Role),
		PolicyDigest: graph.PolicyDigest, ProviderRoute: graph.ProviderRoute, Deadline: request.Deadline,
		TaskLimits: request.TaskBudget, Claim: request.BudgetClaim})
	if err != nil {
		return runbudget.Reservation{}, mapBudgetError(err)
	}
	if reservation.PlanDigest != graph.BudgetPlanDigest {
		return runbudget.Reservation{}, newError(Denied, "budget_plan_invalid", false, nil)
	}
	return reservation, nil
}

func deriveChild(graph Graph, request DelegateRequest) (uint32, string, error) {
	if _, found := findTask(graph, request.TaskID); found {
		return 0, "", newError(Denied, "task_already_exists", false, nil)
	}
	depth := uint32(0)
	previous := ""
	for index, parentID := range request.ParentTaskIDs {
		parent, found := findTask(graph, parentID)
		if !found || terminalTask(parent.Status) && parent.Status != TaskSucceeded || parent.Deadline.Before(request.Deadline) ||
			cancellationInProgress(graph, parentID) {
			return 0, "", newError(Denied, "parent_invalid", false, nil)
		}
		if parent.Depth >= depth {
			depth = parent.Depth + 1
		}
		if index == 0 {
			previous = parent.ProvenanceDigest
		}
		if childCount(graph, parentID) >= graph.Limits.MaximumFanout {
			return 0, "", newError(Denied, "graph_fanout_exhausted", false, nil)
		}
	}
	if depth > graph.Limits.MaximumDepth {
		return 0, "", newError(Denied, "graph_depth_exhausted", false, nil)
	}
	return depth, previous, nil
}

func cancellationInProgress(graph Graph, taskID string) bool {
	for _, record := range graph.Cancellations {
		if record.Status != CancellationActive {
			continue
		}
		for _, targetID := range record.TargetTaskIDs {
			if targetID == taskID {
				return true
			}
		}
	}
	return false
}

func (controller *Controller) validateStoredResult(graph Graph, receipt Receipt, replayed bool) (Result, error) {
	if err := validateGraph(graph); err != nil {
		return Result{}, newError(Denied, "stored_graph_invalid", false, err)
	}
	result, ok := receiptResult(graph, receipt)
	if !ok {
		return Result{}, newError(Denied, "stored_receipt_invalid", false, nil)
	}
	result.Replayed = replayed
	return result, nil
}

func receiptResult(graph Graph, wanted Receipt) (Result, bool) {
	for _, receipt := range graph.Receipts {
		if receipt.IdempotencyDigest != wanted.IdempotencyDigest {
			continue
		}
		if receipt.Operation != wanted.Operation || receipt.IntentDigest != wanted.IntentDigest || receipt.TaskID != wanted.TaskID {
			return Result{}, false
		}
		task, found := findTask(graph, receipt.TaskID)
		return Result{Graph: cloneGraph(graph), Task: cloneTask(task)}, found
	}
	return Result{}, false
}

func receiptChangedReplay(graph Graph, wanted Receipt) bool {
	for _, receipt := range graph.Receipts {
		if receipt.IdempotencyDigest == wanted.IdempotencyDigest {
			return receipt.Operation != wanted.Operation || receipt.IntentDigest != wanted.IntentDigest ||
				receipt.TaskID != wanted.TaskID
		}
	}
	return false
}

func bindGraphRequest(graph Graph, scope domain.CaseRef, graphID, actorID string, actorRevision uint64, policy string, now time.Time) error {
	if graph.GraphID != graphID || graph.Case != scope || graph.ActorID != actorID ||
		graph.ActorRevision != actorRevision || graph.PolicyDigest != policy || !now.Before(graph.Deadline) {
		return newError(Denied, "graph_scope_invalid", false, nil)
	}
	return nil
}

func findTask(graph Graph, taskID string) (Task, bool) {
	index, found := sort.Find(len(graph.Tasks), func(index int) int { return stringCompare(taskID, graph.Tasks[index].TaskID) })
	if !found {
		return Task{}, false
	}
	return cloneTask(graph.Tasks[index]), true
}

func childCount(graph Graph, taskID string) uint32 {
	count := uint32(0)
	for _, edge := range graph.Edges {
		if edge.ParentTaskID == taskID {
			count++
		}
	}
	return count
}
func activeTasks(graph Graph) uint32 {
	count := uint32(0)
	for _, task := range graph.Tasks {
		if task.Status == TaskPending || task.Status == TaskDispatching {
			count++
		}
	}
	return count
}
func terminalTask(status TaskStatus) bool { return status != TaskPending && status != TaskDispatching }
func roleActivity(role Role) string       { return "subagent." + string(role) }
func stringCompare(left, right string) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func (controller *Controller) now() (time.Time, error) {
	now := controller.clock.Now()
	if !validTime(now) {
		return time.Time{}, newError(Internal, "clock_invalid", false, nil)
	}
	return now, nil
}

func mapBudgetError(err error) error {
	switch runbudget.ErrorCode(err) {
	case runbudget.InvalidInput:
		return newError(InvalidInput, runbudget.ErrorReason(err), false, err)
	case runbudget.Denied:
		return newError(Denied, runbudget.ErrorReason(err), false, err)
	case runbudget.Conflict:
		return newError(Conflict, runbudget.ErrorReason(err), false, err)
	case runbudget.Canceled:
		return newError(Canceled, runbudget.ErrorReason(err), false, err)
	case runbudget.Timeout:
		return newError(Timeout, runbudget.ErrorReason(err), false, err)
	default:
		return newError(Unavailable, runbudget.ErrorReason(err), runbudget.Retryable(err), err)
	}
}
func mapStoreError(operation string, err error) error {
	if CodeOf(err) != Unavailable {
		return err
	}
	return newError(Unavailable, operation+"_unavailable", true, err)
}
func mapDependency(ctx context.Context, reason string, err error) error {
	if ctx != nil && errors.Is(ctx.Err(), context.Canceled) {
		return newError(Canceled, "request_canceled", false, context.Canceled)
	}
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", false, context.DeadlineExceeded)
	}
	return newError(Unavailable, reason, true, err)
}
