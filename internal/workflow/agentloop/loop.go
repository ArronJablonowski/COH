package agentloop

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
)

type Loop struct {
	store      StateStore
	activities *Activities
	clock      Clock
}

func New(store StateStore, models workflowbase.ModelProvider, actions workflowbase.ActionAuthority, clock Clock) (*Loop, error) {
	if store == nil || models == nil || actions == nil || clock == nil {
		return nil, newError(InvalidInput, "new", "dependencies_required", false, nil)
	}
	activities, err := NewActivities(models, actions)
	if err != nil {
		return nil, err
	}
	return &Loop{store: store, activities: activities, clock: clock}, nil
}

func (loop *Loop) Start(ctx context.Context, request StartRequest) (Snapshot, error) {
	if loop == nil {
		return Snapshot{}, newError(InvalidInput, "start", "loop_required", false, nil)
	}
	if err := validateContext(ctx, "start"); err != nil {
		return Snapshot{}, err
	}
	now, err := loop.now("start")
	if err != nil {
		return Snapshot{}, err
	}
	if err := validateStart(request, now); err != nil {
		return Snapshot{}, err
	}
	provenance, err := transitionDigest("", "start", request)
	if err != nil {
		return Snapshot{}, err
	}
	inputRefs := append([]string{}, request.InputRefs...)
	run := Run{ContractVersion: ContractVersion, RunID: request.RunID, Case: request.Case, ActorID: request.ActorID, WorkflowVersion: WorkflowVersion, PolicyDigest: request.PolicyDigest, ProviderRoute: request.ProviderRoute, Status: RunRunning, CurrentStepID: request.StepID, Sequence: 1, InputRefs: inputRefs, OutputRefs: []string{}, ProvenanceDigest: provenance, CreatedAt: now, UpdatedAt: now, Revision: 1}
	step := Step{ContractVersion: ContractVersion, StepID: request.StepID, RunID: request.RunID, Case: request.Case, Kind: request.Activity, Status: StepPending, Attempt: 1, Deadline: request.Deadline, InputRefs: inputRefs, OutputRefs: []string{}, IntentDigest: request.IntentDigest, ProvenanceDigest: provenance, CreatedAt: now, UpdatedAt: now, Revision: 1}
	return loop.create(ctx, request.IdempotencyKey, Snapshot{Run: run, Step: step})
}

func (loop *Loop) Execute(ctx context.Context, request ExecuteRequest) (Snapshot, error) {
	if loop == nil {
		return Snapshot{}, newError(InvalidInput, "execute", "loop_required", false, nil)
	}
	if err := validateContext(ctx, "execute"); err != nil {
		return Snapshot{}, err
	}
	if err := validateExecute(request); err != nil {
		return Snapshot{}, err
	}
	current, err := loop.load(ctx, request.Case, request.RunID)
	if err != nil {
		return Snapshot{}, err
	}
	if current.Step.StepID != request.StepID || current.Run.Case != request.Case {
		return Snapshot{}, newError(Denied, "execute", "scope_or_step_mismatch", false, nil)
	}
	if terminalRun(current.Run.Status) || terminalStep(current.Step.Status) {
		current.Replayed = true
		return current, nil
	}
	if current.Run.Status != RunRunning {
		return Snapshot{}, newError(Conflict, "execute", "run_not_executable", false, nil)
	}
	if current.Step.Kind == AuthorizedActionActivity && current.Step.Status == StepDispatching {
		return loop.markUncertain(ctx, request.IdempotencyKey+":recovery", current, "dispatch_receipt_missing")
	}
	if current.Step.Kind == PlanningActivity && request.Intent != nil || current.Step.Kind == AuthorizedActionActivity && request.Intent == nil {
		return Snapshot{}, newError(InvalidInput, "execute", "activity_payload_mismatch", false, nil)
	}
	if request.Intent != nil {
		digest, digestErr := toolIntentDigest(*request.Intent)
		if digestErr != nil || digest != current.Step.IntentDigest || request.Intent.Case != current.Run.Case || request.Intent.OperationID != current.Step.StepID {
			return Snapshot{}, newError(Denied, "execute", "intent_binding_mismatch", false, nil)
		}
	}
	now, err := loop.now("execute")
	if err != nil {
		return Snapshot{}, err
	}
	if !now.Before(current.Step.Deadline) {
		return loop.finish(ctx, request.IdempotencyKey+":deadline", current, StepTimeout, RunTimeout, nil, "", "deadline_elapsed")
	}
	active := cloneSnapshot(current)
	active.Run.Revision++
	active.Run.Sequence++
	active.Step.Revision++
	if active.Step.Status != StepPending {
		active.Step.Attempt++
	}
	if active.Step.Attempt > 1000 {
		return loop.finish(ctx, request.IdempotencyKey+":attempt-limit", current, StepFailed, RunFailed, nil, "", "attempt_limit")
	}
	active.Step.Status = StepRunning
	if active.Step.Kind == AuthorizedActionActivity {
		active.Step.Status = StepDispatching
	}
	if err := loop.stamp(&active, current.Run.ProvenanceDigest, "activity_started", now); err != nil {
		return Snapshot{}, err
	}
	active, err = loop.save(ctx, request.IdempotencyKey+":started", current, active)
	if err != nil {
		return Snapshot{}, err
	}
	if active.Step.Kind == PlanningActivity {
		return loop.executePlanning(ctx, request.IdempotencyKey, active)
	}
	return loop.executeAction(ctx, request.IdempotencyKey, active, *request.Intent)
}

func (loop *Loop) Schedule(ctx context.Context, request ScheduleRequest) (Snapshot, error) {
	if loop == nil {
		return Snapshot{}, newError(InvalidInput, "schedule", "loop_required", false, nil)
	}
	if err := validateContext(ctx, "schedule"); err != nil {
		return Snapshot{}, err
	}
	now, err := loop.now("schedule")
	if err != nil {
		return Snapshot{}, err
	}
	if err := validateSchedule(request, now); err != nil {
		return Snapshot{}, err
	}
	current, err := loop.load(ctx, request.Case, request.RunID)
	if err != nil {
		return Snapshot{}, err
	}
	if current.Run.Status != RunWaiting || current.Step.Status != StepSucceeded || current.Run.Case != request.Case || request.StepID == current.Step.StepID {
		return Snapshot{}, newError(Conflict, "schedule", "run_not_waiting", false, nil)
	}
	next := cloneSnapshot(current)
	next.Run.Status = RunRunning
	next.Run.CurrentStepID = request.StepID
	next.Run.Revision++
	next.Run.Sequence++
	next.Step = Step{ContractVersion: ContractVersion, StepID: request.StepID, RunID: request.RunID, Case: request.Case, Kind: request.Activity, Status: StepPending, Attempt: 1, Deadline: request.Deadline, InputRefs: append([]string{}, request.InputRefs...), OutputRefs: []string{}, IntentDigest: request.IntentDigest, CreatedAt: now, UpdatedAt: now, Revision: 1}
	if err := loop.stamp(&next, current.Run.ProvenanceDigest, "step_scheduled", now); err != nil {
		return Snapshot{}, err
	}
	return loop.save(ctx, request.IdempotencyKey, current, next)
}

func (loop *Loop) Complete(ctx context.Context, request CompleteRequest) (Snapshot, error) {
	if loop == nil || !validateOpaque(request.IdempotencyKey, 256) || !validateCase(request.Case) || !uuidV7Pattern.MatchString(request.RunID) {
		return Snapshot{}, newError(InvalidInput, "complete", "complete_request_invalid", false, nil)
	}
	if err := validateContext(ctx, "complete"); err != nil {
		return Snapshot{}, err
	}
	current, err := loop.load(ctx, request.Case, request.RunID)
	if err != nil {
		return Snapshot{}, err
	}
	if current.Run.Status == RunSucceeded {
		current.Replayed = true
		return current, nil
	}
	if current.Run.Status != RunWaiting || current.Step.Status != StepSucceeded {
		return Snapshot{}, newError(Conflict, "complete", "run_not_completable", false, nil)
	}
	now, err := loop.now("complete")
	if err != nil {
		return Snapshot{}, err
	}
	next := cloneSnapshot(current)
	next.Run.Status = RunSucceeded
	next.Run.Revision++
	next.Run.Sequence++
	next.Step.Revision++
	if err := loop.stamp(&next, current.Run.ProvenanceDigest, "run_completed", now); err != nil {
		return Snapshot{}, err
	}
	return loop.save(ctx, request.IdempotencyKey, current, next)
}

func (loop *Loop) Resume(ctx context.Context, request ResumeRequest) (Snapshot, error) {
	if loop == nil || !validateOpaque(request.IdempotencyKey, 256) || !validateCase(request.Case) || !uuidV7Pattern.MatchString(request.RunID) {
		return Snapshot{}, newError(InvalidInput, "resume", "resume_request_invalid", false, nil)
	}
	if err := validateContext(ctx, "resume"); err != nil {
		return Snapshot{}, err
	}
	current, err := loop.load(ctx, request.Case, request.RunID)
	if err != nil {
		return Snapshot{}, err
	}
	if terminalRun(current.Run.Status) || current.Run.Status == RunWaiting {
		current.Replayed = true
		return current, nil
	}
	if current.Step.Kind == AuthorizedActionActivity && current.Step.Status == StepDispatching {
		return loop.markUncertain(ctx, request.IdempotencyKey+":uncertain", current, "dispatch_receipt_missing")
	}
	return loop.Execute(ctx, ExecuteRequest{IdempotencyKey: request.IdempotencyKey, Case: request.Case, RunID: request.RunID, StepID: current.Step.StepID, Intent: request.Intent})
}

// Terminate durably records a caller-detected terminal condition without
// exposing an activity. A dispatching action can only become uncertain.
func (loop *Loop) Terminate(ctx context.Context, request TerminateRequest) (Snapshot, error) {
	if loop == nil {
		return Snapshot{}, newError(InvalidInput, "terminate", "loop_required", false, nil)
	}
	if err := validateContext(ctx, "terminate"); err != nil {
		return Snapshot{}, err
	}
	if err := validateTerminate(request); err != nil {
		return Snapshot{}, err
	}
	current, err := loop.load(ctx, request.Case, request.RunID)
	if err != nil {
		return Snapshot{}, err
	}
	if current.Step.StepID != request.StepID || current.Run.Case != request.Case {
		return Snapshot{}, newError(Denied, "terminate", "scope_or_step_mismatch", false, nil)
	}
	if terminalRun(current.Run.Status) {
		current.Replayed = true
		return current, nil
	}
	if current.Step.Status == StepDispatching && request.Outcome != TerminalUncertain {
		return Snapshot{}, newError(Denied, "terminate", "dispatch_outcome_requires_uncertainty", false, nil)
	}
	stepStatus, runStatus := terminalStatuses(request.Outcome)
	operation := "terminated_" + string(request.Outcome) + "_" + request.ReasonDigest
	var outputs []string
	if current.Step.Status == StepSucceeded {
		outputs = current.Step.OutputRefs
	}
	return loop.finish(ctx, request.IdempotencyKey, current, stepStatus, runStatus, outputs, "", operation)
}

func (loop *Loop) executePlanning(ctx context.Context, key string, active Snapshot) (Snapshot, error) {
	result, err := loop.activities.Plan(ctx, PlanningRequest{Operation: domain.Operation{ID: active.Step.StepID, Case: active.Run.Case, Kind: "agent_plan", Version: WorkflowDefinition}})
	if err != nil {
		status, runStatus, mapped := planningFailure(ctx, err)
		return loop.finishAfterActivity(ctx, key+":finished", active, status, runStatus, nil, "", Reason(mapped), mapped)
	}
	return loop.finish(ctx, key+":finished", active, StepSucceeded, RunWaiting, []string{result.Artifact.Digest}, "", "planning_succeeded")
}

func (loop *Loop) executeAction(ctx context.Context, key string, active Snapshot, intent domain.ToolIntent) (Snapshot, error) {
	result, err := loop.activities.Act(ctx, AuthorizedActionRequest{Intent: intent, IntentDigest: active.Step.IntentDigest})
	if err != nil {
		if Code(err) == Denied && Reason(err) == "broker_receipt_invalid" {
			return loop.finishAfterActivity(ctx, key+":finished", active, StepUncertain, RunUncertain, nil, "", "broker_receipt_invalid", err)
		}
		mapped := newError(Unavailable, "authorized_action", "action_outcome_uncertain", false, nil)
		return loop.finishAfterActivity(ctx, key+":finished", active, StepUncertain, RunUncertain, nil, "", "action_outcome_uncertain", mapped)
	}
	receiptDigest, err := actionReceiptDigest(result.Receipt)
	if err != nil {
		return Snapshot{}, err
	}
	stepStatus, runStatus := receiptStatuses(result.Receipt.Outcome)
	output := []string{result.Receipt.Evidence.Digest}
	return loop.finish(ctx, key+":finished", active, stepStatus, runStatus, output, receiptDigest, "action_"+result.Receipt.Outcome)
}

func (loop *Loop) finishAfterActivity(ctx context.Context, key string, active Snapshot, step StepStatus, run RunStatus, outputs []string, receipt, reason string, activityErr error) (Snapshot, error) {
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	result, err := loop.finish(persistCtx, key, active, step, run, outputs, receipt, reason)
	if err != nil {
		return Snapshot{}, err
	}
	return result, activityErr
}

func (loop *Loop) finish(ctx context.Context, key string, current Snapshot, stepStatus StepStatus, runStatus RunStatus, outputs []string, receiptDigest, operation string) (Snapshot, error) {
	now, err := loop.now("finish")
	if err != nil {
		return Snapshot{}, err
	}
	next := cloneSnapshot(current)
	next.Run.Status = runStatus
	next.Run.Revision++
	next.Run.Sequence++
	next.Step.Status = stepStatus
	next.Step.Revision++
	next.Step.OutputRefs = sortedReferences(outputs)
	next.Step.ReceiptDigest = receiptDigest
	if stepStatus == StepSucceeded {
		next.Run.OutputRefs = mergeReferences(next.Run.OutputRefs, outputs)
	}
	if err := loop.stamp(&next, current.Run.ProvenanceDigest, operation, now); err != nil {
		return Snapshot{}, err
	}
	return loop.save(ctx, key, current, next)
}

func (loop *Loop) markUncertain(ctx context.Context, key string, current Snapshot, reason string) (Snapshot, error) {
	result, err := loop.finish(ctx, key, current, StepUncertain, RunUncertain, nil, "", reason)
	if err != nil {
		return Snapshot{}, err
	}
	return result, newError(Conflict, "resume", reason, false, nil)
}

func (loop *Loop) stamp(value *Snapshot, prior, operation string, now time.Time) error {
	value.Run.UpdatedAt = now
	value.Step.UpdatedAt = now
	digest, err := transitionDigest(prior, operation, struct {
		RunID         string     `json:"run_id"`
		StepID        string     `json:"step_id"`
		RunStatus     RunStatus  `json:"run_status"`
		StepStatus    StepStatus `json:"step_status"`
		Sequence      uint64     `json:"sequence"`
		RunRevision   uint64     `json:"run_revision"`
		StepRevision  uint64     `json:"step_revision"`
		IntentDigest  string     `json:"intent_digest"`
		ReceiptDigest string     `json:"receipt_digest"`
		UpdatedAt     string     `json:"updated_at"`
	}{value.Run.RunID, value.Step.StepID, value.Run.Status, value.Step.Status, value.Run.Sequence, value.Run.Revision, value.Step.Revision, value.Step.IntentDigest, value.Step.ReceiptDigest, formatTime(now)})
	if err != nil {
		return err
	}
	value.Run.ProvenanceDigest = digest
	value.Step.ProvenanceDigest = digest
	return nil
}

func (loop *Loop) now(operation string) (time.Time, error) {
	value := loop.clock.Now().UTC()
	if value.IsZero() {
		return time.Time{}, newError(Internal, operation, "clock_unavailable", false, nil)
	}
	return value, nil
}

func (loop *Loop) create(ctx context.Context, key string, value Snapshot) (Snapshot, error) {
	result, err := loop.store.Create(ctx, key, cloneSnapshot(value))
	if err != nil {
		return Snapshot{}, err
	}
	if err := validateSnapshot(result); err != nil || result.Run.RunID != value.Run.RunID || result.Run.Case != value.Run.Case {
		return Snapshot{}, newError(Denied, "create", "store_result_invalid", false, nil)
	}
	return cloneSnapshot(result), nil
}

func (loop *Loop) load(ctx context.Context, scope domain.CaseRef, runID string) (Snapshot, error) {
	result, err := loop.store.Load(ctx, scope, runID)
	if err != nil {
		return Snapshot{}, err
	}
	if err := validateSnapshot(result); err != nil || result.Run.RunID != runID || result.Run.Case != scope {
		return Snapshot{}, newError(Denied, "load", "store_result_invalid", false, nil)
	}
	return cloneSnapshot(result), nil
}

func (loop *Loop) save(ctx context.Context, key string, prior, next Snapshot) (Snapshot, error) {
	result, err := loop.store.Save(ctx, key, cloneSnapshot(prior), cloneSnapshot(next))
	if err != nil {
		return Snapshot{}, err
	}
	if err := validateSnapshot(result); err != nil || result.Run.RunID != next.Run.RunID || result.Run.Case != next.Run.Case {
		return Snapshot{}, newError(Denied, "save", "store_result_invalid", false, nil)
	}
	return cloneSnapshot(result), nil
}
