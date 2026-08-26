package agentphase

import (
	"context"
	"sort"

	"github.com/ArronJablonowski/COH/internal/workflow/agentloop"
)

type Coordinator struct {
	loop    *agentloop.Loop
	results ResultResolver
}

func New(dependencies Dependencies) (*Coordinator, error) {
	if dependencies.Store == nil || dependencies.Models == nil || dependencies.Actions == nil || dependencies.Budgets == nil ||
		dependencies.Results == nil || dependencies.Clock == nil {
		return nil, newError(InvalidInput, "new", "dependencies_required", false, nil)
	}
	model := &phaseModel{models: dependencies.Models, results: dependencies.Results}
	loop, err := agentloop.New(dependencies.Store, model, dependencies.Actions, dependencies.Budgets, dependencies.Clock)
	if err != nil {
		return nil, mapLoopError("new", err)
	}
	return &Coordinator{loop: loop, results: dependencies.Results}, nil
}

func (coordinator *Coordinator) Start(ctx context.Context, request StartRequest) (Session, error) {
	if coordinator == nil || coordinator.loop == nil {
		return Session{}, newError(InvalidInput, "start", "coordinator_required", false, nil)
	}
	if err := validateContext(ctx, "start"); err != nil {
		return Session{}, err
	}
	if err := validateStart(request); err != nil {
		return Session{}, err
	}
	control, err := controlDigest(request.RunID, request.TraceID, request.RetryPolicy)
	if err != nil {
		return Session{}, err
	}
	stepID, err := phaseStepID(request.RunID, request.TraceID, 1, PlanPhase)
	if err != nil {
		return Session{}, err
	}
	refs := mergeReferences(request.InputRefs, []string{control})
	snapshot, err := coordinator.loop.Start(ctx, agentloop.StartRequest{
		IdempotencyKey: request.IdempotencyKey, RunID: request.RunID, StepID: stepID,
		Case: request.Case, ActorID: request.ActorID, PolicyDigest: request.PolicyDigest,
		ProviderRoute: request.ProviderRoute, Activity: agentloop.PlanningActivity,
		InputRefs: refs, Deadline: request.Deadline, BudgetPlan: request.BudgetPlan,
		TaskBudget: request.TaskBudget, BudgetClaim: request.BudgetClaim,
	})
	if err != nil {
		return Session{}, mapLoopError("start", err)
	}
	return sessionFromSnapshot(request.TraceID, request.RetryPolicy, control, snapshot)
}

func (coordinator *Coordinator) Advance(ctx context.Context, request AdvanceRequest) (AdvanceResult, error) {
	if coordinator == nil || coordinator.loop == nil {
		return AdvanceResult{}, newError(InvalidInput, "advance", "coordinator_required", false, nil)
	}
	if err := validateContext(ctx, "advance"); err != nil {
		return AdvanceResult{}, err
	}
	if !validateOpaque(request.IdempotencyKey, 256) {
		return AdvanceResult{}, newError(InvalidInput, "advance", "idempotency_key_invalid", false, nil)
	}
	if err := validateSession(request.Session); err != nil {
		return AdvanceResult{}, err
	}
	if request.Session.Phase == ActPhase && request.Intent == nil || request.Session.Phase != ActPhase && request.Intent != nil {
		return AdvanceResult{}, newError(InvalidInput, "advance", "phase_payload_mismatch", false, nil)
	}
	if request.Session.Snapshot.Step.Status == agentloop.StepRunning &&
		request.Session.Snapshot.Step.Attempt >= request.Session.RetryPolicy.MaximumPhaseAttempts {
		return coordinator.exhaust(ctx, request)
	}
	snapshot, err := coordinator.loop.Execute(ctx, agentloop.ExecuteRequest{
		IdempotencyKey: request.IdempotencyKey, Case: request.Session.Snapshot.Run.Case,
		RunID: request.Session.Snapshot.Run.RunID, StepID: request.Session.Snapshot.Step.StepID, Intent: request.Intent,
	})
	session := request.Session
	if snapshot.Run.RunID != "" {
		session.Snapshot = snapshot
	}
	result := AdvanceResult{Session: session}
	if err != nil {
		return result, mapLoopError("advance", err)
	}
	if snapshot.Step.Status != agentloop.StepSucceeded || snapshot.Run.Status != agentloop.RunWaiting {
		return result, terminalError(snapshot)
	}
	output, err := coordinator.output(ctx, session)
	if err != nil {
		terminated, termErr := coordinator.loop.Terminate(ctx, agentloop.TerminateRequest{
			IdempotencyKey: request.IdempotencyKey + ":reject", Case: snapshot.Run.Case,
			RunID: snapshot.Run.RunID, StepID: snapshot.Step.StepID,
			Outcome: agentloop.TerminalDenied, ReasonDigest: failureDigest("structured_output_invalid"),
		})
		if termErr != nil {
			return result, mapLoopError("reject_output", termErr)
		}
		result.Session.Snapshot = terminated
		return result, err
	}
	result.Output = output
	return result, nil
}

func (coordinator *Coordinator) Transition(ctx context.Context, request TransitionRequest) (Session, error) {
	if coordinator == nil || coordinator.loop == nil {
		return Session{}, newError(InvalidInput, "transition", "coordinator_required", false, nil)
	}
	if err := validateContext(ctx, "transition"); err != nil {
		return Session{}, err
	}
	if !validateOpaque(request.IdempotencyKey, 256) {
		return Session{}, newError(InvalidInput, "transition", "idempotency_key_invalid", false, nil)
	}
	if err := validateSession(request.Session); err != nil {
		return Session{}, err
	}
	if request.Session.Snapshot.Run.Status != agentloop.RunWaiting ||
		request.Session.Snapshot.Step.Status != agentloop.StepSucceeded {
		return Session{}, newError(Conflict, "transition", "phase_not_waiting", false, nil)
	}
	if err := validateOutputBinding(request.Session, request.Output); err != nil {
		return Session{}, err
	}
	if request.Session.Phase == ReviewPhase && request.Output.ReviewDisposition == ReviewAccepted {
		snapshot, err := coordinator.loop.Complete(ctx, agentloop.CompleteRequest{
			IdempotencyKey: request.IdempotencyKey, Case: request.Session.Snapshot.Run.Case,
			RunID: request.Session.Snapshot.Run.RunID,
		})
		if err != nil {
			return Session{}, mapLoopError("complete", err)
		}
		request.Session.Snapshot = snapshot
		return request.Session, nil
	}
	nextPhase, nextCycle, err := nextPhase(request.Session, request.Output)
	if err != nil {
		if Code(err) == Conflict {
			return coordinator.terminateExhausted(ctx, request, err)
		}
		return Session{}, err
	}
	stepID, err := phaseStepID(request.Session.Snapshot.Run.RunID, request.Session.TraceID, nextCycle, nextPhase)
	if err != nil {
		return Session{}, err
	}
	activity := agentloop.PlanningActivity
	intentDigest := ""
	if nextPhase == ActPhase {
		activity = agentloop.AuthorizedActionActivity
		intentDigest = request.Output.IntentDigest
	}
	snapshot, err := coordinator.loop.Schedule(ctx, agentloop.ScheduleRequest{
		IdempotencyKey: request.IdempotencyKey, Case: request.Session.Snapshot.Run.Case,
		RunID: request.Session.Snapshot.Run.RunID, StepID: stepID, Activity: activity,
		InputRefs: []string{request.Output.ArtifactDigest}, IntentDigest: intentDigest,
		Deadline: request.Session.Snapshot.Step.Deadline, TaskBudget: request.NextTaskBudget,
		BudgetClaim: request.NextBudgetClaim,
	})
	if err != nil {
		return Session{}, mapLoopError("schedule", err)
	}
	return sessionFromSnapshot(request.Session.TraceID, request.Session.RetryPolicy, request.Session.ControlDigest, snapshot)
}

func (coordinator *Coordinator) Input(session Session) (PhaseInput, error) {
	if coordinator == nil {
		return PhaseInput{}, newError(InvalidInput, "input", "coordinator_required", false, nil)
	}
	if err := validateSession(session); err != nil {
		return PhaseInput{}, err
	}
	digest, err := inputSetDigest(session.Snapshot.Step.InputRefs)
	if err != nil {
		return PhaseInput{}, err
	}
	prior := ""
	if session.Phase != PlanPhase || session.Cycle > 1 {
		prior = session.Snapshot.Step.InputRefs[0]
	}
	value := PhaseInput{
		ContractVersion: ContractVersion, Phase: session.Phase, TraceID: session.TraceID, Cycle: session.Cycle,
		InputRefs: append([]string{}, session.Snapshot.Step.InputRefs...), InputSetDigest: digest,
		PriorOutputDigest: prior, RetryPolicy: session.RetryPolicy,
		Deadline: session.Snapshot.Step.Deadline.Format("2006-01-02T15:04:05.000000000Z"),
	}
	return value, validatePhaseInput(value)
}

func (coordinator *Coordinator) output(ctx context.Context, session Session) (PhaseOutput, error) {
	if len(session.Snapshot.Step.OutputRefs) != 1 {
		return PhaseOutput{}, newError(Denied, "output", "output_reference_invalid", false, nil)
	}
	digest, err := inputSetDigest(session.Snapshot.Step.InputRefs)
	if err != nil {
		return PhaseOutput{}, err
	}
	artifact := session.Snapshot.Step.OutputRefs[0]
	if session.Phase == ActPhase {
		value := PhaseOutput{
			ContractVersion: ContractVersion, Phase: ActPhase, TraceID: session.TraceID, Cycle: session.Cycle,
			InputSetDigest: digest, ArtifactDigest: artifact, IntentDigest: session.Snapshot.Step.IntentDigest,
			ReceiptDigest: session.Snapshot.Step.ReceiptDigest, EvidenceRefs: []string{artifact},
			Completeness: Complete, Claims: []Claim{}, Findings: []Finding{},
		}
		return value, validatePhaseOutput(value)
	}
	value, err := coordinator.results.Resolve(ctx, artifact, session.Phase)
	if err != nil {
		return PhaseOutput{}, mapContextOrUnavailable("resolve_output", err)
	}
	if err := validatePhaseOutput(value); err != nil || value.Phase != session.Phase ||
		value.TraceID != session.TraceID || value.Cycle != session.Cycle ||
		value.InputSetDigest != digest || value.ArtifactDigest != artifact {
		return PhaseOutput{}, newError(Denied, "output", "output_binding_invalid", false, nil)
	}
	return value, nil
}

func validateOutputBinding(session Session, output PhaseOutput) error {
	if err := validatePhaseOutput(output); err != nil {
		return err
	}
	inputDigest, err := inputSetDigest(session.Snapshot.Step.InputRefs)
	if err != nil {
		return err
	}
	if output.Phase != session.Phase || output.TraceID != session.TraceID || output.Cycle != session.Cycle ||
		output.InputSetDigest != inputDigest || len(session.Snapshot.Step.OutputRefs) != 1 ||
		output.ArtifactDigest != session.Snapshot.Step.OutputRefs[0] {
		return newError(Denied, "transition", "output_binding_invalid", false, nil)
	}
	return nil
}

func nextPhase(session Session, output PhaseOutput) (Phase, uint32, error) {
	switch session.Phase {
	case PlanPhase:
		return ActPhase, session.Cycle, nil
	case ActPhase:
		return ObservePhase, session.Cycle, nil
	case ObservePhase:
		return ReviewPhase, session.Cycle, nil
	case ReviewPhase:
		if output.ReviewDisposition != ReviewRevise {
			return "", 0, newError(Denied, "transition", "review_disposition_invalid", false, nil)
		}
		if session.Cycle >= session.RetryPolicy.MaximumReviewCycles {
			return "", 0, newError(Conflict, "transition", "review_cycle_exhausted", false, nil)
		}
		return PlanPhase, session.Cycle + 1, nil
	default:
		return "", 0, newError(Denied, "transition", "phase_invalid", false, nil)
	}
}

func (coordinator *Coordinator) exhaust(ctx context.Context, request AdvanceRequest) (AdvanceResult, error) {
	snapshot, err := coordinator.loop.Terminate(ctx, agentloop.TerminateRequest{
		IdempotencyKey: request.IdempotencyKey + ":exhausted", Case: request.Session.Snapshot.Run.Case,
		RunID: request.Session.Snapshot.Run.RunID, StepID: request.Session.Snapshot.Step.StepID,
		Outcome: agentloop.TerminalFailed, ReasonDigest: failureDigest("phase_attempts_exhausted"),
	})
	request.Session.Snapshot = snapshot
	if err != nil {
		return AdvanceResult{Session: request.Session}, mapLoopError("exhaust", err)
	}
	return AdvanceResult{Session: request.Session}, newError(Conflict, "advance", "phase_attempts_exhausted", false, nil)
}

func (coordinator *Coordinator) terminateExhausted(ctx context.Context, request TransitionRequest, cause error) (Session, error) {
	snapshot, err := coordinator.loop.Terminate(ctx, agentloop.TerminateRequest{
		IdempotencyKey: request.IdempotencyKey + ":exhausted", Case: request.Session.Snapshot.Run.Case,
		RunID: request.Session.Snapshot.Run.RunID, StepID: request.Session.Snapshot.Step.StepID,
		Outcome: agentloop.TerminalFailed, ReasonDigest: failureDigest(Reason(cause)),
	})
	if err != nil {
		return Session{}, mapLoopError("exhaust", err)
	}
	request.Session.Snapshot = snapshot
	return request.Session, cause
}

func terminalError(snapshot agentloop.Snapshot) error {
	switch snapshot.Run.Status {
	case agentloop.RunDenied:
		return newError(Denied, "advance", "phase_denied", false, nil)
	case agentloop.RunCanceled:
		return newError(Canceled, "advance", "phase_canceled", false, nil)
	case agentloop.RunTimeout:
		return newError(Timeout, "advance", "phase_timeout", false, nil)
	case agentloop.RunFailed:
		return newError(Unavailable, "advance", "phase_failed", true, nil)
	case agentloop.RunUncertain:
		return newError(Conflict, "advance", "phase_uncertain", false, nil)
	default:
		return newError(Conflict, "advance", "phase_not_complete", false, nil)
	}
}

func mapLoopError(operation string, err error) error {
	switch agentloop.Code(err) {
	case agentloop.InvalidInput:
		return newError(InvalidInput, operation, agentloop.Reason(err), false, nil)
	case agentloop.Denied:
		return newError(Denied, operation, agentloop.Reason(err), false, nil)
	case agentloop.Conflict, agentloop.NotFound:
		return newError(Conflict, operation, agentloop.Reason(err), false, nil)
	case agentloop.Canceled:
		return newError(Canceled, operation, agentloop.Reason(err), false, err)
	case agentloop.Timeout:
		return newError(Timeout, operation, agentloop.Reason(err), false, err)
	case agentloop.Internal:
		return newError(Internal, operation, agentloop.Reason(err), false, nil)
	default:
		return newError(Unavailable, operation, agentloop.Reason(err), agentloop.Retryable(err), nil)
	}
}

func sessionFromSnapshot(traceID string, policy RetryPolicy, control string, snapshot agentloop.Snapshot) (Session, error) {
	phase, err := phaseFromStepID(snapshot.Step.StepID)
	if err != nil {
		return Session{}, err
	}
	for cycle := uint32(1); cycle <= policy.MaximumReviewCycles; cycle++ {
		expected, identityErr := phaseStepID(snapshot.Run.RunID, traceID, cycle, phase)
		if identityErr != nil {
			return Session{}, identityErr
		}
		if expected != snapshot.Step.StepID {
			continue
		}
		session := Session{
			TraceID: traceID, Cycle: cycle, Phase: phase, RetryPolicy: policy,
			ControlDigest: control, Snapshot: snapshot,
		}
		if err := validateSession(session); err != nil {
			return Session{}, err
		}
		return session, nil
	}
	return Session{}, newError(Denied, "session", "phase_cycle_binding_invalid", false, nil)
}

func failureDigest(reason string) string {
	value, err := digestValue("COH-AGENT-PHASE-FAILURE-V1\x00", reason)
	if err != nil {
		return "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	}
	return value
}

func mergeReferences(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	for _, value := range append(append([]string{}, left...), right...) {
		seen[value] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for value := range seen {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
