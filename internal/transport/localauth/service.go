package localauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

const (
	defaultChallengeTTL = 2 * time.Minute
	defaultSessionTTL   = 8 * time.Hour
	maximumChallengeTTL = 10 * time.Minute
	maximumSessionTTL   = 24 * time.Hour
)

var uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func (service Service) Begin(ctx context.Context, request BeginRequest) (Challenge, error) {
	now := service.now()
	event := AuthenticationEvent{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		OccurredAt: now,
	}
	if err := service.ready(); err != nil {
		return Challenge{}, service.record(ctx, unavailable(event, "authentication_unavailable"), err)
	}
	if err := contextError(ctx); err != nil {
		return Challenge{}, service.record(ctx, outcome(event, err), err)
	}
	if !uuidV7Pattern.MatchString(request.OrganizationID) || !uuidV7Pattern.MatchString(request.ActorID) {
		err := authError(localidentity.InvalidInput, "identity_context_invalid")
		return Challenge{}, service.record(ctx, outcome(event, err), err)
	}
	event.OrganizationID, event.ActorID = request.OrganizationID, request.ActorID
	actor, err := service.Actors.LookupActor(ctx, request.OrganizationID, request.ActorID)
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "identity_unavailable")
		if errors.Is(err, ErrNotFound) {
			resultErr = authError(localidentity.Denied, "authentication_failed")
		} else if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return Challenge{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	if validationErr := localidentity.ValidateActor(actor); validationErr != nil || actor.OrganizationID != request.OrganizationID || actor.ID != request.ActorID {
		resultErr := authError(localidentity.Denied, "authentication_failed")
		return Challenge{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	event.ActorRevision = actor.Revision
	if !actor.Active {
		resultErr := authError(localidentity.Denied, "actor_revoked")
		return Challenge{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	challengeTTL := duration(service.ChallengeTTL, defaultChallengeTTL, maximumChallengeTTL)
	if challengeTTL == 0 {
		resultErr := authError(localidentity.InvalidInput, "authentication_configuration_invalid")
		return Challenge{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	idBytes, nonce, err := service.randomChallenge()
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "random_unavailable")
		return Challenge{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	id := "ch_" + encodeRaw(idBytes)
	expiresAt := now.Add(challengeTTL)
	message := signingMessage(id, actor.OrganizationID, actor.ID, encodeRaw(nonce), expiresAt)
	record := ChallengeRecord{
		ID: id, OrganizationID: actor.OrganizationID, ActorID: actor.ID, ActorRevision: actor.Revision,
		PublicKey: actor.PublicKey, Message: message, CreatedAt: now, ExpiresAt: expiresAt,
	}
	if err := service.Challenges.SaveChallenge(ctx, record); err != nil {
		resultErr := authError(localidentity.Unavailable, "challenge_unavailable")
		if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return Challenge{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	event.ChallengeID = id
	event.Outcome, event.ReasonCode = "allowed", "challenge_issued"
	if err := service.record(ctx, event, nil); err != nil {
		_, _ = service.Challenges.TakeChallenge(ctx, id)
		return Challenge{}, err
	}
	return Challenge{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion, ID: id,
		OrganizationID: actor.OrganizationID, ActorID: actor.ID,
		SigningMessage: encodeRaw(message), ExpiresAt: expiresAt,
	}, nil
}

func (service Service) Complete(ctx context.Context, request CompleteRequest) (IssuedSession, error) {
	now := service.now()
	event := AuthenticationEvent{SchemaVersion: SchemaVersion, ContractVersion: ContractVersion, OccurredAt: now}
	if err := service.ready(); err != nil {
		return IssuedSession{}, service.record(ctx, unavailable(event, "authentication_unavailable"), err)
	}
	if err := contextError(ctx); err != nil {
		return IssuedSession{}, service.record(ctx, outcome(event, err), err)
	}
	if !validOpaqueID(request.ChallengeID, "ch_", 22) {
		resultErr := authError(localidentity.Denied, "authentication_failed")
		return IssuedSession{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	event.ChallengeID = request.ChallengeID
	record, err := service.Challenges.TakeChallenge(ctx, request.ChallengeID)
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "challenge_unavailable")
		if errors.Is(err, ErrNotFound) {
			resultErr = authError(localidentity.Denied, "authentication_failed")
		} else if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return IssuedSession{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	event.OrganizationID, event.ActorID, event.ActorRevision = record.OrganizationID, record.ActorID, record.ActorRevision
	if !validChallengeRecord(record, request.ChallengeID) {
		resultErr := authError(localidentity.Denied, "authentication_failed")
		return IssuedSession{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	if !now.Before(record.ExpiresAt) {
		resultErr := authError(localidentity.Denied, "challenge_expired")
		return IssuedSession{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	actor, err := service.Actors.LookupActor(ctx, record.OrganizationID, record.ActorID)
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "identity_unavailable")
		if errors.Is(err, ErrNotFound) {
			resultErr = authError(localidentity.Denied, "authentication_failed")
		} else if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return IssuedSession{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	if validationErr := localidentity.ValidateActor(actor); validationErr != nil || actor.ID != record.ActorID || actor.OrganizationID != record.OrganizationID {
		resultErr := authError(localidentity.Denied, "authentication_failed")
		return IssuedSession{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	if !actor.Active || actor.Revision != record.ActorRevision || actor.PublicKey != record.PublicKey {
		resultErr := authError(localidentity.Denied, "actor_revoked")
		return IssuedSession{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	publicKey, _ := base64.RawURLEncoding.DecodeString(actor.PublicKey)
	signature, signatureErr := base64.RawURLEncoding.DecodeString(request.Signature)
	if signatureErr != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(publicKey), record.Message, signature) {
		resultErr := authError(localidentity.Denied, "authentication_failed")
		return IssuedSession{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	sessionTTL := duration(service.SessionTTL, defaultSessionTTL, maximumSessionTTL)
	if sessionTTL == 0 {
		resultErr := authError(localidentity.InvalidInput, "authentication_configuration_invalid")
		return IssuedSession{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	tokenBytes, sessionIDBytes, err := service.randomSession()
	if err != nil {
		resultErr := authError(localidentity.Unavailable, "random_unavailable")
		return IssuedSession{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	token := encodeRaw(tokenBytes)
	sessionID := "sess_" + encodeRaw(sessionIDBytes)
	session := SessionRecord{
		ID: sessionID, TokenDigest: tokenDigest(token), OrganizationID: actor.OrganizationID,
		ActorID: actor.ID, ActorRevision: actor.Revision, IssuedAt: now, ExpiresAt: now.Add(sessionTTL),
	}
	if err := service.Sessions.SaveSession(ctx, session); err != nil {
		resultErr := authError(localidentity.Unavailable, "session_unavailable")
		if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return IssuedSession{}, service.record(ctx, outcome(event, resultErr), resultErr)
	}
	event.SessionID = sessionID
	event.Outcome, event.ReasonCode = "allowed", "session_issued"
	if err := service.record(ctx, event, nil); err != nil {
		_ = service.Sessions.RevokeSession(ctx, session.TokenDigest, now)
		return IssuedSession{}, err
	}
	return IssuedSession{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		ID: sessionID, Token: token, ExpiresAt: session.ExpiresAt,
	}, nil
}

func (service Service) ready() error {
	if service.Actors == nil || service.Challenges == nil || service.Sessions == nil || service.Audit == nil || service.random() == nil || service.clock() == nil {
		return authError(localidentity.Unavailable, "authentication_unavailable")
	}
	return nil
}

func (service Service) record(ctx context.Context, event AuthenticationEvent, resultErr error) error {
	if service.Audit == nil {
		return authError(localidentity.Unavailable, "audit_unavailable")
	}
	event = finalizeEvent(event)
	if err := service.Audit.AppendAuthenticationEvent(ctx, event); err != nil {
		return authError(localidentity.Unavailable, "audit_unavailable")
	}
	return resultErr
}

func (service Service) randomChallenge() ([]byte, []byte, error) {
	id := make([]byte, 16)
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(service.random(), id); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(service.random(), nonce); err != nil {
		return nil, nil, err
	}
	return id, nonce, nil
}

func (service Service) randomSession() ([]byte, []byte, error) {
	token := make([]byte, 32)
	id := make([]byte, 16)
	if _, err := io.ReadFull(service.random(), token); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(service.random(), id); err != nil {
		return nil, nil, err
	}
	return token, id, nil
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

func duration(configured, fallback, maximum time.Duration) time.Duration {
	if configured == 0 {
		return fallback
	}
	if configured < 0 || configured > maximum {
		return 0
	}
	return configured
}

func validOpaqueID(value, prefix string, encodedLength int) bool {
	if len(value) != len(prefix)+encodedLength || len(value) > 128 {
		return false
	}
	if len(value) < len(prefix) || value[:len(prefix)] != prefix {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value[len(prefix):])
	return err == nil && len(decoded) > 0
}

func validChallengeRecord(record ChallengeRecord, expectedID string) bool {
	if record.ID != expectedID || !uuidV7Pattern.MatchString(record.OrganizationID) ||
		!uuidV7Pattern.MatchString(record.ActorID) || record.ActorRevision == 0 ||
		record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) ||
		record.ExpiresAt.Sub(record.CreatedAt) > maximumChallengeTTL {
		return false
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(record.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	parts := strings.Split(string(record.Message), "\n")
	if len(parts) != 6 || parts[0] != "coh.local-auth.challenge/v1" {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[5])
	if err != nil || len(nonce) != 32 {
		return false
	}
	expected := signingMessage(record.ID, record.OrganizationID, record.ActorID, parts[5], record.ExpiresAt)
	return bytes.Equal(record.Message, expected)
}

func outcome(event AuthenticationEvent, err error) AuthenticationEvent {
	event.Outcome = "unavailable"
	switch localidentity.Code(err) {
	case localidentity.InvalidInput:
		event.Outcome = "invalid"
	case localidentity.Denied:
		event.Outcome = "denied"
	case localidentity.Canceled:
		event.Outcome = "canceled"
	case localidentity.Timeout:
		event.Outcome = "timeout"
	}
	event.ReasonCode = reason(err)
	return event
}

func unavailable(event AuthenticationEvent, reasonCode string) AuthenticationEvent {
	event.Outcome, event.ReasonCode = "unavailable", reasonCode
	return event
}
