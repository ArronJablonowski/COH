package recoverycontrol

import (
	"context"
)

func (controller *Controller) Cancel(ctx context.Context, request CancelRequest) (Result, error) {
	if controller == nil || controller.store == nil || controller.children == nil || controller.jobs == nil {
		return Result{}, newError(InvalidInput, "controller_required", false, false, nil)
	}
	if err := validateContext(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err := validateCancelRequest(request, now); err != nil {
		return Result{}, err
	}
	intent, err := cancelIntentDigest(request)
	if err != nil {
		return Result{}, err
	}
	idempotency := idempotencyDigest(request.IdempotencyKey)
	identity := Record{Kind: CancellationKind, ControlID: request.ControlID, Case: request.Case,
		RunID: request.RunID, TaskID: request.TaskID}
	if current, found, loadErr := controller.load(ctx, identity, intent, idempotency); loadErr != nil {
		return Result{}, loadErr
	} else if found {
		return controller.continueCancellation(ctx, request.IdempotencyKey, current, true)
	}
	record := Record{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		ControlID: request.ControlID, Kind: CancellationKind, Case: request.Case, RunID: request.RunID,
		TaskID: request.TaskID, PolicyDigest: request.PolicyDigest, IntentDigest: intent,
		IdempotencyDigest: idempotency, ExpectedProvenanceDigest: request.ExpectedProvenanceDigest,
		ReasonDigest: request.ReasonDigest, InputRefs: []string{}, Targets: cloneTargets(request.Targets),
		Acknowledgments: []CancellationAck{}, Attempts: []ProviderAttempt{}, Status: CancellationActive,
		ReasonCode: "cancellation_propagating", CreatedAt: request.CreatedAt, Deadline: request.Deadline,
		UpdatedAt: now}
	if err := sealInitial(&record); err != nil {
		return Result{}, err
	}
	stored, replayed, err := controller.begin(ctx, request.IdempotencyKey+":cancellation", record)
	if err != nil {
		return Result{}, err
	}
	return controller.continueCancellation(ctx, request.IdempotencyKey, stored, replayed)
}

func (controller *Controller) continueCancellation(ctx context.Context, key string, current Record,
	replayed bool) (Result, error) {
	if current.Status != CancellationActive {
		result := resultFrom(current, replayed)
		if current.Status == Uncertain {
			return result, newError(Conflict, "cancellation_ack_uncertain", false, true, nil)
		}
		return result, nil
	}
	for len(current.Acknowledgments) < len(current.Targets) {
		now, err := controller.now()
		if err != nil {
			return resultFrom(current, replayed), err
		}
		if !now.Before(current.Deadline) {
			next := cloneRecord(current)
			for len(next.Acknowledgments) < len(next.Targets) {
				target := next.Targets[len(next.Acknowledgments)]
				next.Acknowledgments = append(next.Acknowledgments, uncertainAck(target, "cancellation_deadline_elapsed"))
			}
			next.Status = Uncertain
			next.ReasonCode = "cancellation_ack_uncertain"
			persistCtx, cancel := persistentContext(ctx)
			defer cancel()
			stored, saveErr := controller.save(persistCtx, key+":deadline", current, next)
			if saveErr != nil {
				return resultFrom(current, replayed), saveErr
			}
			return resultFrom(stored, replayed), newError(Conflict, "cancellation_ack_uncertain", false, true, nil)
		}
		target := current.Targets[len(current.Acknowledgments)]
		command := CancelCommand{IdempotencyKey: key + ":target:" + target.TargetID,
			Case: current.Case, RunID: current.RunID, RootTaskID: current.TaskID, Target: target,
			ReasonDigest: current.ReasonDigest, Deadline: current.Deadline}
		callCtx, cancel := context.WithDeadline(ctx, current.Deadline)
		var ack CancellationAck
		if target.Kind == ChildTask {
			ack, err = controller.children.CancelChild(callCtx, command)
		} else {
			ack, err = controller.jobs.CancelJob(callCtx, command)
		}
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return resultFrom(current, replayed), mapContext(ctx.Err())
			}
			if Retryable(err) && !Indeterminate(err) {
				return resultFrom(current, replayed), mapDependency(ctx, "cancellation_dependency", err)
			}
			ack = uncertainAck(target, ErrorReason(err))
		} else if !validAcknowledgments([]CancellationAck{ack}, []CancelTarget{target}) {
			ack = uncertainAck(target, "cancellation_ack_invalid")
		}
		next := cloneRecord(current)
		next.Acknowledgments = append(next.Acknowledgments, ack)
		if len(next.Acknowledgments) == len(next.Targets) {
			uncertain := false
			for _, value := range next.Acknowledgments {
				uncertain = uncertain || value.Outcome == AckUncertain
			}
			if uncertain {
				next.Status = Uncertain
				next.ReasonCode = "cancellation_ack_uncertain"
			} else {
				next.Status = Completed
				next.ReasonCode = "cancellation_completed"
			}
		}
		stored, saveErr := controller.save(ctx, command.IdempotencyKey+":ack", current, next)
		if saveErr != nil {
			return resultFrom(current, replayed), saveErr
		}
		current = stored
	}
	result := resultFrom(current, replayed)
	if current.Status == Uncertain {
		return result, newError(Conflict, "cancellation_ack_uncertain", false, true, nil)
	}
	return result, nil
}

func uncertainAck(target CancelTarget, reason string) CancellationAck {
	payload := []byte(string(target.Kind) + "\x00" + target.TargetID + "\x00" + reason)
	return CancellationAck{Sequence: target.Sequence, Kind: target.Kind, TargetID: target.TargetID,
		Outcome:          AckUncertain,
		EvidenceDigest:   compactDigest("COH-CANCELLATION-UNCERTAIN-EVIDENCE-V1\x00", payload),
		ProvenanceDigest: compactDigest("COH-CANCELLATION-UNCERTAIN-PROVENANCE-V1\x00", payload)}
}
