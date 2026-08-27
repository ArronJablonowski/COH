package queryruntime

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (controller *Controller) Cancel(ctx context.Context, intent CancelIntent) (Session, error) {
	if controller == nil {
		return Session{}, newError(InvalidInput, "controller_required", nil)
	}
	if err := contextError(ctx); err != nil {
		return Session{}, err
	}
	if !uuidPattern.MatchString(intent.IdempotencyKey) || !oneOf(intent.ReasonCode,
		"user_requested", "operator_requested", "deadline", "emergency_stop") {
		return Session{}, newError(InvalidInput, "cancellation_intent_invalid", nil)
	}
	managed, err := controller.lookup(intent.SessionID)
	if err != nil {
		return Session{}, err
	}
	managed.mu.Lock()
	defer managed.mu.Unlock()
	digestInput := struct {
		SessionID      string `json:"session_id"`
		IdempotencyKey string `json:"idempotency_key"`
		ReasonCode     string `json:"reason_code"`
	}{intent.SessionID, intent.IdempotencyKey, intent.ReasonCode}
	intentDigest, err := canonicalDigest(cancellationDomain, digestInput)
	if err != nil {
		return Session{}, err
	}
	if managed.cancellationDigest != "" {
		if managed.cancellationDigest == intentDigest {
			return managed.value, nil
		}
		return Session{}, newError(Conflict, "cancellation_changed", nil)
	}
	if intent.SessionDigest != managed.value.SessionDigest {
		return Session{}, newError(Conflict, "session_revision_mismatch", nil)
	}
	if err := VerifySession(managed.value); err != nil {
		return Session{}, err
	}
	if !active(managed.value.Status) {
		return Session{}, newError(Denied, "session_terminal", nil)
	}
	now := controller.clock.Now().UTC()
	if !handleCurrent(managed.jobHandle, now) {
		input := transitionInput{usage: managed.value.Usage, status: "uncertain", reason: "job_handle_expired",
			cancelDigest: intentDigest, provenance: managed.value.VendorProvenanceDigest,
			nextPageNumber: managed.value.NextPageNumber}
		session, commitErr := controller.commit(ctx, managed, input, now)
		if commitErr != nil {
			return Session{}, commitErr
		}
		managed.cancellationKey, managed.cancellationReason, managed.cancellationDigest =
			intent.IdempotencyKey, intent.ReasonCode, intentDigest
		return session, newError(Denied, "job_handle_expired", nil)
	}
	reservation, err := controller.reserveRate(ctx, managed, "cancel", now)
	if err != nil {
		return Session{}, err
	}
	cancelContext, stop := context.WithTimeout(context.WithoutCancel(ctx), controller.config.CancellationWait)
	defer stop()
	cancellation, err := controller.adapter.Cancel(cancelContext, queryconnector.CancelRequest{QueryID: managed.value.QueryID,
		AttemptID: managed.value.AttemptID, Handle: managed.jobHandle, Authority: managed.authority,
		RequestedAt: now.Format(timestampLayout)})
	if err != nil {
		mapped := adapterError(err)
		input := transitionInput{usage: managed.value.Usage, status: "uncertain", reason: "cancellation_unavailable",
			rateDigest: reservation.ReservationDigest, cancelDigest: intentDigest,
			provenance: managed.value.VendorProvenanceDigest, nextPageNumber: managed.value.NextPageNumber}
		session, commitErr := controller.commit(ctx, managed, input, now)
		if commitErr != nil {
			return Session{}, commitErr
		}
		managed.cancellationKey, managed.cancellationReason, managed.cancellationDigest =
			intent.IdempotencyKey, intent.ReasonCode, intentDigest
		return session, mapped
	}
	value := cancellation.Value()
	if cancellation.Digest() == "" || value.QueryID != managed.value.QueryID || value.AttemptID != managed.value.AttemptID {
		input := transitionInput{usage: managed.value.Usage, status: "uncertain", reason: "cancellation_mismatch",
			rateDigest: reservation.ReservationDigest, cancelDigest: intentDigest,
			provenance: managed.value.VendorProvenanceDigest, nextPageNumber: managed.value.NextPageNumber}
		session, commitErr := controller.commit(ctx, managed, input, now)
		if commitErr != nil {
			return Session{}, commitErr
		}
		managed.cancellationKey, managed.cancellationReason, managed.cancellationDigest =
			intent.IdempotencyKey, intent.ReasonCode, intentDigest
		return session, newError(Conflict, "cancellation_mismatch", nil)
	}
	status, reason := "uncertain", "cancellation_unconfirmed"
	if value.Outcome == "confirmed" {
		status, reason = "canceled", "cancellation_confirmed"
	}
	input := transitionInput{usage: managed.value.Usage, status: status, reason: reason,
		rateDigest: reservation.ReservationDigest, cancelDigest: intentDigest,
		provenance: value.ProvenanceDigest, nextPageNumber: managed.value.NextPageNumber}
	session, err := controller.commit(ctx, managed, input, now)
	if err != nil {
		return Session{}, err
	}
	managed.cancellationKey, managed.cancellationReason = intent.IdempotencyKey, intent.ReasonCode
	managed.cancellationDigest = intentDigest
	return session, nil
}

func (controller *Controller) markUncertain(ctx context.Context, managed *managedSession, inputDigest,
	operation, reason string, now time.Time) (Result, error) {
	input := transitionInput{usage: managed.value.Usage, status: "uncertain", reason: reason,
		provenance: managed.value.VendorProvenanceDigest, nextPageNumber: managed.value.NextPageNumber}
	session, err := controller.commit(ctx, managed, input, now)
	if err != nil {
		return Result{}, err
	}
	result := Result{Session: session}
	resultErr := newError(Denied, reason, nil)
	managed.cacheOperation(operation, inputDigest, result, resultErr)
	return result, resultErr
}

func (controller *Controller) truncate(ctx context.Context, managed *managedSession, inputDigest, operation,
	reason string, now time.Time, rateDigest *string) (Result, error) {
	input := transitionInput{usage: managed.value.Usage, status: "truncated", reason: reason,
		provenance: managed.value.VendorProvenanceDigest, nextPageNumber: managed.value.NextPageNumber}
	if rateDigest != nil {
		input.rateDigest = *rateDigest
	}
	controller.protectiveCancel(ctx, managed, now, &input)
	session, commitErr := controller.commit(ctx, managed, input, now)
	result := Result{Session: session}
	resultErr := newError(Denied, reason, nil)
	if commitErr != nil {
		return Result{}, commitErr
	}
	managed.cacheOperation(operation, inputDigest, result, resultErr)
	return result, resultErr
}

func (controller *Controller) protectiveCancel(ctx context.Context, managed *managedSession, now time.Time,
	input *transitionInput) {
	reservation, err := controller.reserveRate(ctx, managed, "protective_cancel", now)
	if err != nil {
		input.reason = "limit_cancel_unavailable"
		return
	}
	input.rateDigest = reservation.ReservationDigest
	parent := context.Background()
	if ctx != nil {
		parent = context.WithoutCancel(ctx)
	}
	cancelContext, stop := context.WithTimeout(parent, controller.config.CancellationWait)
	defer stop()
	cancellation, err := controller.adapter.Cancel(cancelContext, queryconnector.CancelRequest{QueryID: managed.value.QueryID,
		AttemptID: managed.value.AttemptID, Handle: managed.jobHandle, Authority: managed.authority,
		RequestedAt: now.Format(timestampLayout)})
	if err != nil || cancellation.Digest() == "" {
		input.reason = "limit_cancel_uncertain"
		return
	}
	value := cancellation.Value()
	if value.QueryID != managed.value.QueryID || value.AttemptID != managed.value.AttemptID ||
		value.Outcome != "confirmed" {
		input.reason = "limit_cancel_uncertain"
		return
	}
	input.provenance = value.ProvenanceDigest
}
