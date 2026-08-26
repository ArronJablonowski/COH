package recoverycontrol

import (
	"context"
	"strconv"
	"time"
)

func (controller *Controller) Invoke(ctx context.Context, request InvokeRequest) (Result, error) {
	if controller == nil || controller.store == nil || controller.routes == nil || controller.providers == nil {
		return Result{}, newError(InvalidInput, "controller_required", false, false, nil)
	}
	if err := validateContext(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err := validateInvokeRequest(request, now); err != nil {
		return Result{}, err
	}
	intent, err := invokeIntentDigest(request)
	if err != nil {
		return Result{}, err
	}
	idempotency := idempotencyDigest(request.IdempotencyKey)
	identity := Record{Kind: FallbackKind, ControlID: request.ControlID, Case: request.Case,
		RunID: request.RunID, TaskID: request.TaskID}
	if current, found, loadErr := controller.load(ctx, identity, intent, idempotency); loadErr != nil {
		return Result{}, loadErr
	} else if found {
		return controller.continueFallback(ctx, request.IdempotencyKey, current, true)
	}
	approved, err := controller.routes.ApproveFallback(ctx, RouteApprovalRequest{Case: request.Case,
		RunID: request.RunID, TaskID: request.TaskID, PolicyDigest: request.PolicyDigest,
		RequestedRoute: request.RequestedRoute, Operation: request.Operation,
		InputRefs: append([]string{}, request.InputRefs...), BudgetReservationDigest: request.BudgetReservationDigest,
		CreatedAt: request.CreatedAt, Deadline: request.Deadline})
	if err != nil {
		return Result{}, mapDependency(ctx, "route_approval", err)
	}
	route, err := approvedRouteBinding(approved, request, now)
	if err != nil {
		return Result{}, err
	}
	primary := pendingAttempt(1, request.ControlID, route.PrimaryRoute, route.Primary.CapabilityDigest,
		PrimaryAttempting)
	record := Record{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		ControlID: request.ControlID, Kind: FallbackKind, Case: request.Case, RunID: request.RunID,
		TaskID: request.TaskID, PolicyDigest: request.PolicyDigest, IntentDigest: intent,
		IdempotencyDigest: idempotency, Operation: request.Operation,
		InputRefs: append([]string{}, request.InputRefs...), BudgetReservationDigest: request.BudgetReservationDigest,
		Targets: []CancelTarget{}, Acknowledgments: []CancellationAck{}, Route: route,
		Attempts: []ProviderAttempt{primary}, Status: PrimaryAttempting, ReasonCode: "primary_attempting",
		CreatedAt: request.CreatedAt, Deadline: request.Deadline, UpdatedAt: now}
	if err := sealInitial(&record); err != nil {
		return Result{}, err
	}
	stored, replayed, err := controller.begin(ctx, request.IdempotencyKey+":fallback", record)
	if err != nil {
		return Result{}, err
	}
	if replayed {
		return controller.continueFallback(ctx, request.IdempotencyKey, stored, true)
	}
	return controller.executeAttempt(ctx, request.IdempotencyKey, stored, 0, false)
}

func (controller *Controller) continueFallback(ctx context.Context, key string, current Record,
	replayed bool) (Result, error) {
	switch current.Status {
	case PrimaryUnavailable:
		return controller.startFallback(ctx, key, current, replayed)
	case PrimaryAttempting, FallbackAttempting:
		now, err := controller.now()
		if err != nil {
			return resultFrom(current, replayed), err
		}
		if now.Before(current.Deadline) {
			return resultFrom(current, replayed), newError(Conflict, "provider_attempt_in_progress", true, false, nil)
		}
		return controller.markAttemptUncertain(ctx, key+":recovery", current, replayed,
			"provider_attempt_response_missing")
	default:
		result := resultFrom(current, replayed)
		if current.Status == Uncertain {
			return result, newError(Conflict, "provider_outcome_uncertain", false, true, nil)
		}
		return result, nil
	}
}

func (controller *Controller) startFallback(ctx context.Context, key string, current Record,
	replayed bool) (Result, error) {
	if current.Status != PrimaryUnavailable || len(current.Attempts) != 1 {
		return resultFrom(current, replayed), newError(Conflict, "fallback_not_available", false, false, nil)
	}
	now, err := controller.now()
	if err != nil {
		return resultFrom(current, replayed), err
	}
	if !now.Before(current.Deadline) || !now.Before(current.Route.ExpiresAt) {
		next := cloneRecord(current)
		next.Attempts = append(next.Attempts, terminalAttempt(2, current.ControlID, current.Route.FallbackRoute,
			current.Route.Fallback.CapabilityDigest, TimedOut, "timeout", "fallback_deadline_elapsed"))
		next.Status = TimedOut
		next.ReasonCode = "provider_timeout"
		persistCtx, cancel := persistentContext(ctx)
		defer cancel()
		stored, saveErr := controller.save(persistCtx, key+":fallback-timeout", current, next)
		if saveErr != nil {
			return resultFrom(current, replayed), saveErr
		}
		return resultFrom(stored, replayed), newError(Timeout, "fallback_deadline_elapsed", false, false, nil)
	}
	next := cloneRecord(current)
	next.Attempts = append(next.Attempts, pendingAttempt(2, current.ControlID, current.Route.FallbackRoute,
		current.Route.Fallback.CapabilityDigest, FallbackAttempting))
	next.Status = FallbackAttempting
	next.ReasonCode = "fallback_attempting"
	stored, err := controller.save(ctx, key+":fallback-attempt", current, next)
	if err != nil {
		return resultFrom(current, replayed), err
	}
	return controller.executeAttempt(ctx, key, stored, 1, replayed)
}

func (controller *Controller) executeAttempt(ctx context.Context, key string, current Record, index int,
	replayed bool) (Result, error) {
	if index < 0 || index >= len(current.Attempts) {
		return resultFrom(current, replayed), newError(Internal, "attempt_index_invalid", false, true, nil)
	}
	attempt := current.Attempts[index]
	callCtx, cancel := context.WithDeadline(ctx, current.Deadline)
	receipt, invokeErr := controller.providers.InvokeProvider(callCtx, AttemptRequest{
		AttemptID: attempt.AttemptID, Route: attempt.Route, CapabilityDigest: attempt.CapabilityDigest,
		Operation: current.Operation, InputRefs: append([]string{}, current.InputRefs...), Deadline: current.Deadline})
	cancel()
	if invokeErr != nil {
		return controller.finishAttempt(ctx, key, current, index, invokeErr, replayed)
	}
	if receipt.AttemptID != attempt.AttemptID || receipt.Route != attempt.Route ||
		receipt.CapabilityDigest != attempt.CapabilityDigest || receipt.Outcome != "succeeded" ||
		!validArtifact(receipt.Artifact) || !digestPattern.MatchString(receipt.EvidenceDigest) {
		return controller.markAttemptUncertain(ctx, key+":invalid-receipt", current, replayed,
			"provider_receipt_invalid")
	}
	next := cloneRecord(current)
	next.Attempts[index] = ProviderAttempt{Sequence: attempt.Sequence, AttemptID: attempt.AttemptID,
		Route: attempt.Route, CapabilityDigest: attempt.CapabilityDigest, Status: Completed,
		Outcome: "succeeded", Artifact: receipt.Artifact, EvidenceDigest: receipt.EvidenceDigest}
	next.ResultArtifact = receipt.Artifact
	next.Status = Completed
	next.ReasonCode = "provider_succeeded"
	persistCtx, persistCancel := persistentContext(ctx)
	defer persistCancel()
	stored, err := controller.save(persistCtx, key+":attempt-succeeded", current, next)
	if err != nil {
		return resultFrom(current, replayed), err
	}
	return resultFrom(stored, replayed), nil
}

func (controller *Controller) finishAttempt(ctx context.Context, key string, current Record, index int,
	invokeErr error, replayed bool) (Result, error) {
	attempt := current.Attempts[index]
	status, _, outcome := classifyProviderFailure(invokeErr, index == 0)
	next := cloneRecord(current)
	next.Attempts[index] = terminalAttempt(attempt.Sequence, current.ControlID, attempt.Route,
		attempt.CapabilityDigest, status, outcome, ErrorReason(invokeErr))
	next.Status = status
	if status == PrimaryUnavailable {
		next.ReasonCode = "primary_unavailable"
	} else {
		next.ReasonCode = fallbackTerminalReason(status)
	}
	persistCtx, persistCancel := persistentContext(ctx)
	defer persistCancel()
	stored, err := controller.save(persistCtx, key+":attempt-finished", current, next)
	if err != nil {
		return resultFrom(current, replayed), err
	}
	if status == PrimaryUnavailable {
		return controller.startFallback(ctx, key, stored, replayed)
	}
	result := resultFrom(stored, replayed)
	if status == Uncertain {
		return result, newError(Conflict, "provider_outcome_uncertain", false, true, nil)
	}
	return result, newError(ErrorCode(invokeErr), ErrorReason(invokeErr), Retryable(invokeErr), false, nil)
}

func (controller *Controller) markAttemptUncertain(ctx context.Context, key string, current Record,
	replayed bool, reason string) (Result, error) {
	next := cloneRecord(current)
	index := len(next.Attempts) - 1
	attempt := next.Attempts[index]
	next.Attempts[index] = terminalAttempt(attempt.Sequence, current.ControlID, attempt.Route,
		attempt.CapabilityDigest, Uncertain, "uncertain", reason)
	next.Status = Uncertain
	next.ReasonCode = "provider_outcome_uncertain"
	persistCtx, persistCancel := persistentContext(ctx)
	defer persistCancel()
	stored, err := controller.save(persistCtx, key, current, next)
	if err != nil {
		return resultFrom(current, replayed), err
	}
	return resultFrom(stored, replayed), newError(Conflict, "provider_outcome_uncertain", false, true, nil)
}

func classifyProviderFailure(err error, primary bool) (Status, string, string) {
	if Indeterminate(err) {
		return Uncertain, "provider_outcome_uncertain", "uncertain"
	}
	switch ErrorCode(err) {
	case DeniedCode:
		return Denied, "provider_denied", "denied"
	case CanceledCode:
		return Canceled, "provider_canceled", "canceled"
	case Timeout:
		return TimedOut, "provider_timeout", "timeout"
	case Unavailable:
		if primary {
			return PrimaryUnavailable, "primary_unavailable", "unavailable"
		}
		return Failed, "provider_failed", "failed"
	default:
		return Failed, "provider_failed", "failed"
	}
}

func pendingAttempt(sequence uint32, controlID, route, capability string, status Status) ProviderAttempt {
	id := attemptID(controlID, sequence, route, capability)
	return ProviderAttempt{Sequence: sequence, AttemptID: id, Route: route,
		CapabilityDigest: capability, Status: status, Outcome: "pending"}
}

func terminalAttempt(sequence uint32, controlID, route, capability string, status Status,
	outcome, reason string) ProviderAttempt {
	id := attemptID(controlID, sequence, route, capability)
	payload := []byte(id + "\x00" + outcome + "\x00" + reason)
	return ProviderAttempt{Sequence: sequence, AttemptID: id, Route: route,
		CapabilityDigest: capability, Status: status, Outcome: outcome,
		EvidenceDigest: compactDigest("COH-PROVIDER-ATTEMPT-EVIDENCE-V1\x00", payload)}
}

func attemptID(controlID string, sequence uint32, route, capability string) string {
	payload := []byte(controlID + "\x00" + strconv.FormatUint(uint64(sequence), 10) + "\x00" + route + "\x00" + capability)
	return compactDigest("COH-PROVIDER-ATTEMPT-ID-V1\x00", payload)
}

func persistentContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.Background()
	if ctx != nil {
		base = context.WithoutCancel(ctx)
	}
	return context.WithTimeout(base, 2*time.Second)
}
