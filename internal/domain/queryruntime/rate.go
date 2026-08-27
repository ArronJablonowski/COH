package queryruntime

import (
	"context"
	"errors"
	"time"
)

func (controller *Controller) reserveRate(ctx context.Context, managed *managedSession, operation string,
	now time.Time) (RateReservation, error) {
	request := RateRequest{SchemaVersion: RateSchemaVersion, ContractVersion: ContractVersion,
		SessionID: managed.value.SessionID, SessionDigest: managed.value.SessionDigest,
		OrganizationID: managed.value.OrganizationID, TenantID: managed.value.TenantID, ActorID: managed.value.ActorID,
		SourceID: managed.value.SourceID, Mode: managed.value.Mode, Operation: operation,
		MaximumPerMinute: managed.value.EffectiveLimits.RequestsPerMinute, RequestedAt: now.Format(timestampLayout)}
	keyDigest, err := canonicalDigest(rateRequestDigestDomain, request)
	if err != nil {
		return RateReservation{}, err
	}
	reservation, err := controller.rate.Reserve(ctx, request)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return RateReservation{}, contextErr
		}
		var typed *Error
		if errors.As(err, &typed) && typed.Code == Denied {
			return RateReservation{}, newError(Denied, "rate_exhausted", err)
		}
		return RateReservation{}, newError(Unavailable, "rate_unavailable", err)
	}
	if err := verifyRateReservation(reservation); err != nil || reservation.KeyDigest != keyDigest ||
		reservation.SessionID != request.SessionID || reservation.Operation != operation {
		return RateReservation{}, newError(Conflict, "rate_reservation_mismatch", err)
	}
	reservedAt, _ := time.Parse(timestampLayout, reservation.ReservedAt)
	validUntil, _ := time.Parse(timestampLayout, reservation.ValidUntil)
	if now.Before(reservedAt) || !now.Before(validUntil) {
		return RateReservation{}, newError(Denied, "rate_reservation_stale", nil)
	}
	return reservation, nil
}
