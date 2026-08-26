package recoverycontrol

import (
	"context"
)

func (controller *Controller) Recover(ctx context.Context, request RecoverRequest) (Result, error) {
	if controller == nil || controller.store == nil || controller.work == nil {
		return Result{}, newError(InvalidInput, "controller_required", false, false, nil)
	}
	if err := validateContext(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err := validateRecoverRequest(request, now); err != nil {
		return Result{}, err
	}
	intent, err := recoverIntentDigest(request)
	if err != nil {
		return Result{}, err
	}
	idempotency := idempotencyDigest(request.IdempotencyKey)
	identity := Record{Kind: RecoveryKind, ControlID: request.ControlID, Case: request.Case,
		RunID: request.RunID, TaskID: request.TaskID}
	if current, found, loadErr := controller.load(ctx, identity, intent, idempotency); loadErr != nil {
		return Result{}, loadErr
	} else if found {
		return controller.continueRecovery(ctx, request.IdempotencyKey, current, true)
	}

	observed, err := controller.work.Inspect(ctx, WorkLookup{Case: request.Case, RunID: request.RunID,
		TaskID: request.TaskID})
	if err != nil {
		return Result{}, mapDependency(ctx, "work_inspect", err)
	}
	if !validWork(observed) || observed.Case != request.Case || observed.RunID != request.RunID ||
		observed.TaskID != request.TaskID || observed.ProvenanceDigest != request.ExpectedProvenanceDigest ||
		observed.IntentDigest != request.IntentDigest {
		return Result{}, newError(DeniedCode, "work_binding_invalid", false, false, nil)
	}
	status, reason, resultWork := RecoveryPrepared, "safe_resume_prepared", WorkSnapshot{}
	if terminalWork(observed.Status) || observed.SideEffect == IndeterminateSideEffect {
		status, reason, resultWork = controlStatus(observed.Status), "terminal_preserved", observed
		if observed.SideEffect == IndeterminateSideEffect {
			status = Uncertain
		}
	}
	record := Record{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		ControlID: request.ControlID, Kind: RecoveryKind, Case: request.Case, RunID: request.RunID,
		TaskID: request.TaskID, PolicyDigest: request.PolicyDigest, IntentDigest: intent,
		IdempotencyDigest: idempotency, ExpectedProvenanceDigest: request.ExpectedProvenanceDigest,
		ObservedWork: observed, ResultWork: resultWork, InputRefs: []string{}, Targets: []CancelTarget{},
		Acknowledgments: []CancellationAck{}, Attempts: []ProviderAttempt{}, Status: status,
		ReasonCode: reason, CreatedAt: request.CreatedAt, Deadline: request.Deadline, UpdatedAt: now}
	if err := sealInitial(&record); err != nil {
		return Result{}, err
	}
	stored, replayed, err := controller.begin(ctx, request.IdempotencyKey+":recovery", record)
	if err != nil {
		return Result{}, err
	}
	return controller.continueRecovery(ctx, request.IdempotencyKey, stored, replayed)
}

func (controller *Controller) continueRecovery(ctx context.Context, key string, current Record,
	replayed bool) (Result, error) {
	if current.Status != RecoveryPrepared {
		result := resultFrom(current, replayed)
		if current.Status == Uncertain {
			return result, newError(Conflict, "work_outcome_uncertain", false, true, nil)
		}
		return result, nil
	}
	if err := validateContext(ctx); err != nil {
		return resultFrom(current, replayed), err
	}
	now, err := controller.now()
	if err != nil {
		return resultFrom(current, replayed), err
	}
	if !now.Before(current.Deadline) {
		next := cloneRecord(current)
		next.Status = Uncertain
		next.ReasonCode = "resume_outcome_uncertain"
		next.ResultWork = current.ObservedWork
		persistCtx, cancel := persistentContext(ctx)
		defer cancel()
		stored, saveErr := controller.save(persistCtx, key+":deadline", current, next)
		if saveErr != nil {
			return resultFrom(current, replayed), saveErr
		}
		return resultFrom(stored, replayed), newError(Conflict, "recovery_deadline_elapsed", false, true, nil)
	}
	resumed, err := controller.work.Resume(ctx, WorkResume{IdempotencyKey: key + ":resume",
		Case: current.Case, RunID: current.RunID, TaskID: current.TaskID,
		ExpectedProvenanceDigest: current.ExpectedProvenanceDigest,
		IntentDigest:             current.ObservedWork.IntentDigest})
	if err != nil {
		if ctx.Err() != nil || !Indeterminate(err) {
			return resultFrom(current, replayed), mapDependency(ctx, "work_resume", err)
		}
		next := cloneRecord(current)
		next.Status = Uncertain
		next.ReasonCode = "resume_outcome_uncertain"
		next.ResultWork = current.ObservedWork
		persistCtx, cancel := persistentContext(ctx)
		defer cancel()
		stored, saveErr := controller.save(persistCtx, key+":uncertain", current, next)
		if saveErr != nil {
			return resultFrom(current, replayed), saveErr
		}
		return resultFrom(stored, replayed), newError(Conflict, "work_outcome_uncertain", false, true, nil)
	}
	if !validWork(resumed) || resumed.Case != current.Case || resumed.RunID != current.RunID ||
		resumed.TaskID != current.TaskID || resumed.Status == WorkPending || resumed.Status == WorkRunning ||
		current.ObservedWork.SideEffect == ConfirmedSideEffect && resumed.ReceiptDigest != current.ObservedWork.ReceiptDigest {
		return resultFrom(current, replayed), newError(DeniedCode, "resume_result_invalid", false, false, nil)
	}
	next := cloneRecord(current)
	next.ResultWork = resumed
	next.Status = controlStatus(resumed.Status)
	next.ReasonCode = recoveryReason(next.Status)
	stored, err := controller.save(ctx, key+":completed", current, next)
	if err != nil {
		return resultFrom(current, replayed), err
	}
	result := resultFrom(stored, replayed)
	if stored.Status == Uncertain {
		return result, newError(Conflict, "work_outcome_uncertain", false, true, nil)
	}
	return result, nil
}

func recoveryReason(status Status) string {
	switch status {
	case Completed:
		return "recovery_completed"
	case Failed:
		return "recovery_failed"
	case Denied:
		return "recovery_denied"
	case Canceled:
		return "recovery_canceled"
	case TimedOut:
		return "recovery_timeout"
	default:
		return "resume_outcome_uncertain"
	}
}
