package oidcauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
	"github.com/ArronJablonowski/COH/internal/domain/oidcidentity"
)

const (
	defaultStateTTL   = 5 * time.Minute
	maximumStateTTL   = 10 * time.Minute
	defaultSessionTTL = 10 * time.Minute
	maximumSessionTTL = 15 * time.Minute
	auditTimeout      = 5 * time.Second
)

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func (service Service) Begin(ctx context.Context, request BeginRequest) (LoginState, error) {
	now := service.now()
	event := service.baseEvent("login_state", now)
	if err := service.ready(); err != nil {
		return LoginState{}, service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	if err := contextError(ctx); err != nil {
		return LoginState{}, service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	if !validUUID(request.OrganizationID) || !slices.Contains(service.Config.Audiences, request.Audience) {
		err := authError(localidentity.InvalidInput, "login_context_invalid")
		return LoginState{}, service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	event.OrganizationID = request.OrganizationID
	stateTTL := boundedDuration(service.StateTTL, defaultStateTTL, maximumStateTTL)
	if stateTTL == 0 {
		err := authError(localidentity.InvalidInput, "authentication_configuration_invalid")
		return LoginState{}, service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	stateBytes, nonceBytes, err := service.randomState()
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "random_unavailable")
		return LoginState{}, service.recordEvent(ctx, eventOutcome(event, resultErr), resultErr)
	}
	defer zero(stateBytes)
	defer zero(nonceBytes)
	stateID := "oidc_" + encodeRaw(stateBytes)
	nonce := encodeRaw(nonceBytes)
	expiresAt := now.Add(stateTTL)
	record := LoginStateRecord{ID: stateID, OrganizationID: request.OrganizationID, Issuer: service.Config.Issuer,
		Audience: request.Audience, NonceDigest: digestString(nonce), ProfileKind: service.Config.ProfileKind,
		ProfileDecisionDigest: service.Config.ProfileDecisionDigest, CreatedAt: now, ExpiresAt: expiresAt}
	if err := service.States.SaveLoginState(ctx, record); err != nil {
		resultErr := authError(localidentity.Unavailable, "login_state_unavailable")
		if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return LoginState{}, service.recordEvent(ctx, eventOutcome(event, resultErr), resultErr)
	}
	event.StateID, event.Outcome, event.ReasonCode = stateID, "allowed", "login_state_issued"
	if err := service.recordEvent(ctx, event, nil); err != nil {
		_, _ = service.States.TakeLoginState(context.WithoutCancel(ctx), stateID)
		return LoginState{}, err
	}
	return LoginState{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion, ID: stateID,
		Issuer: service.Config.Issuer, Audience: request.Audience, Nonce: nonce, ExpiresAt: expiresAt}, nil
}

func (service Service) Complete(ctx context.Context, stateID string, compactToken []byte) (*IssuedSession, error) {
	now := service.now()
	event := service.baseEvent("login_complete", now)
	if err := service.ready(); err != nil {
		return nil, service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	if err := contextError(ctx); err != nil {
		return nil, service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	if !validOpaqueID(stateID, "oidc_", 22) {
		err := authError(localidentity.Denied, "authentication_failed")
		return nil, service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	event.StateID = stateID
	state, err := service.States.TakeLoginState(ctx, stateID)
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "login_state_unavailable")
		if errors.Is(err, ErrNotFound) {
			resultErr = authError(localidentity.Denied, "authentication_failed")
		} else if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return nil, service.recordEvent(ctx, eventOutcome(event, resultErr), resultErr)
	}
	if !service.validState(state) || !now.Before(state.ExpiresAt) {
		resultErr := authError(localidentity.Denied, "login_state_expired")
		return nil, service.recordEvent(ctx, eventOutcome(event, resultErr), resultErr)
	}
	ownedToken := append([]byte(nil), compactToken...)
	defer zero(ownedToken)
	claims, key, err := service.verifyToken(ctx, ownedToken, now)
	if err != nil {
		return nil, service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	event.IssuerDigest, event.KeyIDDigest, event.KeyRevision, event.Algorithm = digestString(claims.Issuer), digestString(key.ID), key.Revision, key.Algorithm
	if err := service.validateClaims(state, claims, now); err != nil {
		return nil, service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	actor, err := service.Actors.LookupOIDCActor(ctx, claims.Issuer, claims.Subject)
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "identity_unavailable")
		if errors.Is(err, ErrNotFound) {
			resultErr = authError(localidentity.Denied, "authentication_failed")
		} else if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return nil, service.recordEvent(ctx, eventOutcome(event, resultErr), resultErr)
	}
	if err := validateActorAssertion(actor, claims); err != nil {
		return nil, service.recordEvent(ctx, eventOutcome(event, err), err)
	}
	event.OrganizationID, event.ActorID, event.ActorRevision = actor.OrganizationID, actor.ID, actor.Revision
	event.SubjectDigest = digestString(claims.Subject)
	sessionTTL := boundedDuration(service.SessionTTL, defaultSessionTTL, maximumSessionTTL)
	if sessionTTL == 0 {
		resultErr := authError(localidentity.InvalidInput, "authentication_configuration_invalid")
		return nil, service.recordEvent(ctx, eventOutcome(event, resultErr), resultErr)
	}
	expiresAt := now.Add(sessionTTL)
	tokenExpiry := time.Unix(claims.ExpiresAt, 0).UTC()
	if tokenExpiry.Before(expiresAt) {
		expiresAt = tokenExpiry
	}
	if !expiresAt.After(now) {
		resultErr := authError(localidentity.Denied, "token_expired")
		return nil, service.recordEvent(ctx, eventOutcome(event, resultErr), resultErr)
	}
	session, err := service.newSession(actor, claims, key, now, expiresAt)
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "random_unavailable")
		return nil, service.recordEvent(ctx, eventOutcome(event, resultErr), resultErr)
	}
	if err := service.Sessions.SaveSession(ctx, session.record); err != nil {
		session.issued.Destroy()
		resultErr := authError(localidentity.Unavailable, "session_unavailable")
		if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return nil, service.recordEvent(ctx, eventOutcome(event, resultErr), resultErr)
	}
	event.SessionID, event.Outcome, event.ReasonCode = session.record.ID, "allowed", "session_issued"
	if err := service.recordEvent(ctx, event, nil); err != nil {
		_ = service.Sessions.RevokeSession(context.WithoutCancel(ctx), session.record.TokenDigest, now)
		session.issued.Destroy()
		return nil, err
	}
	return session.issued, nil
}

type newSessionResult struct {
	record SessionRecord
	issued *IssuedSession
}

func (service Service) newSession(actor localidentity.Actor, claims oidcidentity.Claims, key KeyRecord, issuedAt, expiresAt time.Time) (newSessionResult, error) {
	tokenBytes := make([]byte, 32)
	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(service.random(), tokenBytes); err != nil {
		zero(tokenBytes)
		return newSessionResult{}, err
	}
	defer zero(tokenBytes)
	if _, err := io.ReadFull(service.random(), idBytes); err != nil {
		zero(idBytes)
		return newSessionResult{}, err
	}
	defer zero(idBytes)
	token := []byte(encodeRaw(tokenBytes))
	record := SessionRecord{ID: "sess_" + encodeRaw(idBytes), TokenDigest: digestString(string(token)),
		OrganizationID: actor.OrganizationID, ActorID: actor.ID, ActorRevision: actor.Revision,
		IssuerDigest: digestString(claims.Issuer), SubjectDigest: digestString(claims.Subject), KeyID: key.ID,
		Algorithm: key.Algorithm, KeyRevision: key.Revision,
		ProfileKind: service.Config.ProfileKind, ProfileDecisionDigest: service.Config.ProfileDecisionDigest,
		IssuedAt: issuedAt, ExpiresAt: expiresAt}
	issued := &IssuedSession{ID: record.ID, ExpiresAt: expiresAt, token: token}
	return newSessionResult{record: record, issued: issued}, nil
}

func (service Service) validateClaims(state LoginStateRecord, claims oidcidentity.Claims, now time.Time) error {
	if claims.Issuer != service.Config.Issuer || claims.Issuer != state.Issuer || len(claims.Audiences) != 1 ||
		claims.Audiences[0] != state.Audience || claims.OrganizationID != state.OrganizationID {
		return authError(localidentity.Denied, "token_scope_mismatch")
	}
	skew := time.Duration(service.Config.ClockSkewSeconds) * time.Second
	issuedAt, notBefore, expiresAt := time.Unix(claims.IssuedAt, 0).UTC(), time.Unix(claims.NotBefore, 0).UTC(), time.Unix(claims.ExpiresAt, 0).UTC()
	maximumAge := time.Duration(service.Config.MaximumTokenAgeSeconds) * time.Second
	if issuedAt.After(now.Add(skew)) || notBefore.After(now.Add(skew)) || !expiresAt.After(now.Add(-skew)) ||
		now.Sub(issuedAt) > maximumAge+skew || expiresAt.Sub(issuedAt) > maximumAge+skew {
		return authError(localidentity.Denied, "token_time_invalid")
	}
	if subtle.ConstantTimeCompare([]byte(digestString(claims.Nonce)), []byte(state.NonceDigest)) != 1 {
		return authError(localidentity.Denied, "token_nonce_mismatch")
	}
	return nil
}

func validateActorAssertion(actor localidentity.Actor, claims oidcidentity.Claims) error {
	if localidentity.ValidateActor(actor) != nil || !actor.Active || actor.OrganizationID != claims.OrganizationID || actor.ID != claims.ActorID {
		return authError(localidentity.Denied, "actor_assertion_mismatch")
	}
	if !slices.Equal(actor.Roles, claims.Roles) || !slices.Equal(actorTenantIDs(actor), claims.TenantIDs) {
		return authError(localidentity.Denied, "actor_assertion_stale")
	}
	return nil
}

func actorTenantIDs(actor localidentity.Actor) []string {
	result := make([]string, 0, len(actor.Grants))
	for _, grant := range actor.Grants {
		if !slices.Contains(result, grant.TenantID) {
			result = append(result, grant.TenantID)
		}
	}
	slices.Sort(result)
	return result
}

func (service Service) ready() error {
	if oidcidentity.ValidateProviderConfig(service.Config) != nil || service.Actors == nil || service.States == nil ||
		service.Sessions == nil || service.Replay == nil || service.Keys == nil || service.Audit == nil || service.random() == nil || service.clock() == nil {
		return authError(localidentity.Unavailable, "authentication_unavailable")
	}
	return nil
}

func (service Service) validState(state LoginStateRecord) bool {
	return validOpaqueID(state.ID, "oidc_", 22) && validUUID(state.OrganizationID) && state.Issuer == service.Config.Issuer &&
		slices.Contains(service.Config.Audiences, state.Audience) && len(state.NonceDigest) == 71 &&
		state.ProfileKind == service.Config.ProfileKind && state.ProfileDecisionDigest == service.Config.ProfileDecisionDigest &&
		!state.CreatedAt.IsZero() && state.ExpiresAt.After(state.CreatedAt) && state.ExpiresAt.Sub(state.CreatedAt) <= maximumStateTTL
}

func (service Service) baseEvent(name string, now time.Time) Event {
	return Event{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion, Event: name,
		ProfileKind: service.Config.ProfileKind, ProfileDecisionDigest: service.Config.ProfileDecisionDigest, OccurredAt: now}
}

func (service Service) recordEvent(ctx context.Context, event Event, resultErr error) error {
	if service.Audit == nil {
		return authError(localidentity.Unavailable, "audit_unavailable")
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditTimeout)
	defer cancel()
	if err := service.Audit.AppendOIDCEvent(auditCtx, finalizeEvent(event)); err != nil {
		return authError(localidentity.Unavailable, "audit_unavailable")
	}
	return resultErr
}

func eventOutcome(event Event, err error) Event {
	event.Outcome, event.ReasonCode = "unavailable", reason(err)
	switch localidentity.Code(err) {
	case localidentity.InvalidInput:
		event.Outcome = "invalid"
	case localidentity.Denied, localidentity.Conflict:
		event.Outcome = "denied"
	case localidentity.Canceled:
		event.Outcome = "canceled"
	case localidentity.Timeout:
		event.Outcome = "timeout"
	}
	return event
}

func (service Service) randomState() ([]byte, []byte, error) {
	state, nonce := make([]byte, 16), make([]byte, 32)
	if _, err := io.ReadFull(service.random(), state); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(service.random(), nonce); err != nil {
		zero(state)
		return nil, nil, err
	}
	return state, nonce, nil
}

func (service Service) random() io.Reader {
	if service.Random != nil {
		return service.Random
	}
	return rand.Reader
}

func (service Service) clock() Clock {
	if service.Clock != nil {
		return service.Clock
	}
	return systemClock{}
}

func (service Service) now() time.Time { return service.clock().Now().UTC() }

func boundedDuration(value, fallback, maximum time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	if value < 0 || value > maximum {
		return 0
	}
	return value
}

func validOpaqueID(value, prefix string, encodedLength int) bool {
	if len(value) != len(prefix)+encodedLength || value[:len(prefix)] != prefix {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value[len(prefix):])
	return err == nil && len(decoded) > 0
}

func validUUID(value string) bool {
	if len(value) != 36 || value[14] != '7' || !slices.Contains([]byte("89ab"), value[19]) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
