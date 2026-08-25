package oidcauth

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
		err := authError(localidentity.Unavailable, "audit_unavailable")
		return authorizationOutcome(request, 0, "", err), err
	}
	if err := service.ready(); err != nil {
		return service.recordAuthorization(ctx, authorizationOutcome(request, 0, "", err), err)
	}
	if err := contextError(ctx); err != nil {
		return service.recordAuthorization(ctx, authorizationOutcome(request, 0, "", err), err)
	}
	if err := localidentity.ValidateRequest(request); err != nil {
		return service.recordAuthorization(ctx, authorizationOutcome(request, 0, "", err), err)
	}
	if !validSessionToken(token) {
		err := authError(localidentity.Denied, "session_invalid")
		return service.recordAuthorization(ctx, authorizationOutcome(request, 0, "", err), err)
	}
	digest := digestString(token)
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
	if !service.validSession(session, digest) {
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
	key, err := service.Keys.LookupKey(ctx, service.Config.Issuer, service.Config.JWKSReference, session.KeyID)
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "key_source_unavailable")
		if errors.Is(err, ErrNotFound) {
			resultErr = authError(localidentity.Denied, "signing_key_revoked")
		} else if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return service.recordAuthorization(ctx, authorizationOutcome(request, session.ActorRevision, session.ID, resultErr), resultErr)
	}
	if !validKeyRecord(key) || !key.Active || key.Revision != session.KeyRevision || key.Algorithm != session.Algorithm ||
		now.Before(key.NotBefore) || !now.Before(key.ExpiresAt) {
		resultErr := authError(localidentity.Denied, "signing_key_revoked")
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
	if localidentity.ValidateActor(actor) != nil || !actor.Active || actor.OrganizationID != session.OrganizationID ||
		actor.ID != session.ActorID || actor.Revision != session.ActorRevision {
		resultErr := authError(localidentity.Denied, "actor_revoked")
		return service.recordAuthorization(ctx, authorizationOutcome(request, session.ActorRevision, session.ID, resultErr), resultErr)
	}
	decision, authorizationErr := localidentity.EvaluateRBAC(actor, request)
	decision = localidentity.BindSession(decision, session.ID, false)
	if authorizationErr != nil {
		return service.recordAuthorization(ctx, decision, authorizationErr)
	}
	replay, err := service.Replay.CheckAndStore(ctx, ReplayRecord{SessionID: session.ID,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: authorizationRequestDigest(request)})
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "replay_store_unavailable")
		if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return service.recordAuthorization(ctx, authorizationOutcome(request, session.ActorRevision, session.ID, resultErr), resultErr)
	}
	switch replay {
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
	event := service.baseEvent("session_revocation", now)
	if service.Sessions == nil || service.Audit == nil {
		err := authError(localidentity.Unavailable, "authentication_unavailable")
		return service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	if err := contextError(ctx); err != nil {
		return service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	if !validSessionToken(token) {
		err := authError(localidentity.Denied, "session_invalid")
		return service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	digest := digestString(token)
	session, err := service.Sessions.LookupSession(ctx, digest)
	if err != nil || !service.validSession(session, digest) {
		resultErr := authError(localidentity.Denied, "session_invalid")
		if err != nil && !errors.Is(err, ErrNotFound) {
			resultErr = authError(localidentity.Unavailable, "session_unavailable")
		}
		return service.recordEvent(ctx, eventOutcome(event, resultErr), resultErr)
	}
	event.OrganizationID, event.ActorID, event.ActorRevision, event.SessionID = session.OrganizationID, session.ActorID, session.ActorRevision, session.ID
	if session.RevokedAt.IsZero() {
		if err := service.Sessions.RevokeSession(ctx, digest, now); err != nil {
			resultErr := authError(localidentity.Unavailable, "session_unavailable")
			return service.recordEvent(ctx, eventOutcome(event, resultErr), resultErr)
		}
		event.Outcome, event.ReasonCode = "allowed", "session_revoked"
	} else {
		event.Outcome, event.ReasonCode = "allowed", "session_already_revoked"
	}
	return service.recordEvent(ctx, event, nil)
}

func (service Service) recordAuthorization(ctx context.Context, decision localidentity.Decision, resultErr error) (localidentity.Decision, error) {
	if service.Audit == nil {
		return unavailableFrom(decision), authError(localidentity.Unavailable, "audit_unavailable")
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := service.Audit.AppendAuthorizationDecision(auditCtx, decision); err != nil {
		return unavailableFrom(decision), authError(localidentity.Unavailable, "audit_unavailable")
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

func unavailableFrom(decision localidentity.Decision) localidentity.Decision {
	request := localidentity.Request{SchemaVersion: decision.SchemaVersion, ContractVersion: decision.ContractVersion,
		RequestID: decision.RequestID, IdempotencyKey: "redacted", PayloadDigest: decision.PayloadDigest,
		Channel: decision.Channel, Context: decision.Context, Permission: decision.Permission, ActionTier: decision.ActionTier}
	return localidentity.BindSession(localidentity.NewDecision(request, decision.ActorRevision, "unavailable", "audit_unavailable"), decision.SessionID, false)
}

func (service Service) validSession(session SessionRecord, digest string) bool {
	return validOpaqueID(session.ID, "sess_", 22) && session.TokenDigest == digest && validUUID(session.OrganizationID) &&
		validUUID(session.ActorID) && session.ActorRevision > 0 && len(session.IssuerDigest) == 71 && len(session.SubjectDigest) == 71 &&
		validOpaque(session.KeyID, 1, 128) && (session.Algorithm == "EdDSA" || session.Algorithm == "ES256" || session.Algorithm == "RS256") &&
		session.KeyRevision > 0 && session.ProfileKind == service.Config.ProfileKind &&
		session.ProfileDecisionDigest == service.Config.ProfileDecisionDigest && !session.IssuedAt.IsZero() &&
		session.ExpiresAt.After(session.IssuedAt) && session.ExpiresAt.Sub(session.IssuedAt) <= maximumSessionTTL &&
		(session.RevokedAt.IsZero() || !session.RevokedAt.Before(session.IssuedAt))
}

func validSessionToken(token string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	return err == nil && len(decoded) == 32
}

func authorizationRequestDigest(request localidentity.Request) string {
	encoded, err := json.Marshal(request)
	if err != nil {
		panic("local identity request contains only JSON-safe fields")
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
