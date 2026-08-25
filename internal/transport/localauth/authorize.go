package localauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

func (service Service) Authorize(ctx context.Context, token string, request localidentity.Request) (localidentity.Decision, error) {
	if service.Audit == nil {
		return authorizationUnavailable(request, 0, "", "audit_unavailable"), authError(localidentity.Unavailable, "audit_unavailable")
	}
	if service.Actors == nil || service.Sessions == nil || service.Replay == nil || service.clock() == nil {
		resultErr := authError(localidentity.Unavailable, "authorization_unavailable")
		return service.recordAuthorization(ctx, authorizationOutcome(request, 0, "", resultErr), resultErr)
	}
	if err := contextError(ctx); err != nil {
		return service.recordAuthorization(ctx, authorizationOutcome(request, 0, "", err), err)
	}
	if err := localidentity.ValidateRequest(request); err != nil {
		return service.recordAuthorization(ctx, authorizationOutcome(request, 0, "", err), err)
	}
	if !validSessionToken(token) {
		resultErr := authError(localidentity.Denied, "session_invalid")
		return service.recordAuthorization(ctx, authorizationOutcome(request, 0, "", resultErr), resultErr)
	}
	digest := tokenDigest(token)
	session, err := service.Sessions.LookupSession(ctx, digest)
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "session_unavailable")
		if errors.Is(err, ErrNotFound) {
			resultErr = authError(localidentity.Denied, "session_invalid")
		} else if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return service.recordAuthorization(ctx, authorizationOutcome(request, 0, "", resultErr), resultErr)
	}
	if !validSessionRecord(session, digest) {
		resultErr := authError(localidentity.Denied, "session_invalid")
		return service.recordAuthorization(ctx, authorizationOutcome(request, 0, "", resultErr), resultErr)
	}
	now := service.now()
	if !session.RevokedAt.IsZero() {
		resultErr := authError(localidentity.Denied, "session_revoked")
		return service.recordAuthorization(ctx, authorizationOutcome(request, session.ActorRevision, session.ID, resultErr), resultErr)
	}
	if !now.Before(session.ExpiresAt) {
		resultErr := authError(localidentity.Denied, "session_expired")
		return service.recordAuthorization(ctx, authorizationOutcome(request, session.ActorRevision, session.ID, resultErr), resultErr)
	}
	if session.OrganizationID != request.Context.OrganizationID || session.ActorID != request.Context.ActorID {
		resultErr := authError(localidentity.Denied, "session_scope_mismatch")
		return service.recordAuthorization(ctx, authorizationOutcome(request, session.ActorRevision, session.ID, resultErr), resultErr)
	}
	actor, err := service.Actors.LookupActor(ctx, session.OrganizationID, session.ActorID)
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "identity_unavailable")
		if errors.Is(err, ErrNotFound) {
			resultErr = authError(localidentity.Denied, "actor_revoked")
		} else if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return service.recordAuthorization(ctx, authorizationOutcome(request, session.ActorRevision, session.ID, resultErr), resultErr)
	}
	if validationErr := localidentity.ValidateActor(actor); validationErr != nil || actor.ID != session.ActorID || actor.OrganizationID != session.OrganizationID || !actor.Active || actor.Revision != session.ActorRevision {
		resultErr := authError(localidentity.Denied, "actor_revoked")
		return service.recordAuthorization(ctx, authorizationOutcome(request, session.ActorRevision, session.ID, resultErr), resultErr)
	}
	decision, authorizationErr := localidentity.EvaluateRBAC(actor, request)
	decision = localidentity.BindSession(decision, session.ID, false)
	if authorizationErr != nil {
		return service.recordAuthorization(ctx, decision, authorizationErr)
	}
	replayResult, err := service.Replay.CheckAndStore(ctx, ReplayRecord{
		SessionID: session.ID, IdempotencyKey: request.IdempotencyKey, RequestDigest: authorizationRequestDigest(request),
	})
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "replay_store_unavailable")
		if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return service.recordAuthorization(ctx, authorizationOutcome(request, session.ActorRevision, session.ID, resultErr), resultErr)
	}
	switch replayResult {
	case ReplayNew:
	case ReplayExact:
		decision = localidentity.BindSession(decision, session.ID, true)
	case ReplayConflict:
		resultErr := authError(localidentity.Conflict, "idempotency_conflict")
		return service.recordAuthorization(ctx, authorizationOutcome(request, session.ActorRevision, session.ID, resultErr), resultErr)
	default:
		resultErr := authError(localidentity.Unavailable, "replay_store_unavailable")
		return service.recordAuthorization(ctx, authorizationOutcome(request, session.ActorRevision, session.ID, resultErr), resultErr)
	}
	return service.recordAuthorization(ctx, decision, nil)
}

func (service Service) Revoke(ctx context.Context, token string) error {
	now := service.now()
	event := AuthenticationEvent{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion, OccurredAt: now}
	if service.Sessions == nil || service.Audit == nil {
		return service.record(ctx, unavailable(event, "authentication_unavailable"), authError(localidentity.Unavailable, "authentication_unavailable"))
	}
	if err := contextError(ctx); err != nil {
		return service.record(ctx, outcome(event, err), err)
	}
	if !validSessionToken(token) {
		resultErr := authError(localidentity.Denied, "session_invalid")
		return service.record(ctx, outcome(event, resultErr), resultErr)
	}
	digest := tokenDigest(token)
	session, err := service.Sessions.LookupSession(ctx, digest)
	if err != nil || !validSessionRecord(session, digest) {
		resultErr := authError(localidentity.Denied, "session_invalid")
		if err != nil && !errors.Is(err, ErrNotFound) {
			resultErr = authError(localidentity.Unavailable, "session_unavailable")
		}
		return service.record(ctx, outcome(event, resultErr), resultErr)
	}
	event.OrganizationID, event.ActorID, event.ActorRevision, event.SessionID = session.OrganizationID, session.ActorID, session.ActorRevision, session.ID
	if !session.RevokedAt.IsZero() {
		event.Outcome, event.ReasonCode = "allowed", "session_already_revoked"
		return service.record(ctx, event, nil)
	}
	if err := service.Sessions.RevokeSession(ctx, digest, now); err != nil {
		resultErr := authError(localidentity.Unavailable, "session_unavailable")
		return service.record(ctx, outcome(event, resultErr), resultErr)
	}
	event.Outcome, event.ReasonCode = "allowed", "session_revoked"
	return service.record(ctx, event, nil)
}

func (service Service) recordAuthorization(ctx context.Context, decision localidentity.Decision, resultErr error) (localidentity.Decision, error) {
	if service.Audit == nil {
		return authorizationUnavailableFrom(decision, "audit_unavailable"), authError(localidentity.Unavailable, "audit_unavailable")
	}
	if err := service.Audit.AppendAuthorizationDecision(ctx, decision); err != nil {
		return authorizationUnavailableFrom(decision, "audit_unavailable"), authError(localidentity.Unavailable, "audit_unavailable")
	}
	return decision, resultErr
}

func authorizationOutcome(request localidentity.Request, actorRevision uint64, sessionID string, err error) localidentity.Decision {
	outcome := "unavailable"
	switch localidentity.Code(err) {
	case localidentity.InvalidInput:
		outcome = "invalid"
	case localidentity.Denied, localidentity.Conflict:
		outcome = "denied"
	case localidentity.Canceled:
		outcome = "canceled"
	case localidentity.Timeout:
		outcome = "timeout"
	}
	return localidentity.BindSession(localidentity.NewDecision(request, actorRevision, outcome, reason(err)), sessionID, false)
}

func authorizationUnavailable(request localidentity.Request, actorRevision uint64, sessionID, reasonCode string) localidentity.Decision {
	return localidentity.BindSession(localidentity.NewDecision(request, actorRevision, "unavailable", reasonCode), sessionID, false)
}

func authorizationUnavailableFrom(decision localidentity.Decision, reasonCode string) localidentity.Decision {
	request := localidentity.Request{
		SchemaVersion: decision.SchemaVersion, ContractVersion: decision.ContractVersion,
		RequestID: decision.RequestID, PayloadDigest: decision.PayloadDigest, Channel: decision.Channel,
		Context: decision.Context, Permission: decision.Permission, ActionTier: decision.ActionTier,
	}
	return authorizationUnavailable(request, decision.ActorRevision, decision.SessionID, reasonCode)
}

func validSessionToken(token string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(decoded) == 32
}

func validSessionRecord(record SessionRecord, digest string) bool {
	return validOpaqueID(record.ID, "sess_", 22) && record.TokenDigest == digest &&
		uuidV7Pattern.MatchString(record.OrganizationID) && uuidV7Pattern.MatchString(record.ActorID) &&
		record.ActorRevision > 0 && !record.IssuedAt.IsZero() && record.ExpiresAt.After(record.IssuedAt) &&
		record.ExpiresAt.Sub(record.IssuedAt) <= maximumSessionTTL &&
		(record.RevokedAt.IsZero() || !record.RevokedAt.Before(record.IssuedAt))
}

func authorizationRequestDigest(request localidentity.Request) string {
	encoded, err := json.Marshal(request)
	if err != nil {
		panic("local identity request contains only JSON-safe fields")
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
