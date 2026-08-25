package localauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

const (
	testOrganizationID = "0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e"
	testTenantID       = "0198d6c4-22dc-7b3c-af2c-75c1b8eb4f16"
	testCaseID         = "0198d6c4-7618-7d31-8e0a-9da53cae8ca2"
	testActorID        = "0198d6c4-1111-7111-8111-111111111111"
)

type fixedClock struct{ current time.Time }

func (clock *fixedClock) Now() time.Time { return clock.current }

type actorMemory struct {
	actor localidentity.Actor
	err   error
}

func (memory *actorMemory) LookupActor(_ context.Context, organizationID, actorID string) (localidentity.Actor, error) {
	if memory.err != nil {
		return localidentity.Actor{}, memory.err
	}
	if memory.actor.OrganizationID != organizationID || memory.actor.ID != actorID {
		return localidentity.Actor{}, ErrNotFound
	}
	return memory.actor, nil
}

type challengeMemory struct {
	records map[string]ChallengeRecord
	saveErr error
	takeErr error
}

func (memory *challengeMemory) SaveChallenge(_ context.Context, record ChallengeRecord) error {
	if memory.saveErr != nil {
		return memory.saveErr
	}
	if _, exists := memory.records[record.ID]; exists {
		return ErrConflict
	}
	record.Message = bytes.Clone(record.Message)
	memory.records[record.ID] = record
	return nil
}

func (memory *challengeMemory) TakeChallenge(_ context.Context, id string) (ChallengeRecord, error) {
	if memory.takeErr != nil {
		return ChallengeRecord{}, memory.takeErr
	}
	record, exists := memory.records[id]
	if !exists {
		return ChallengeRecord{}, ErrNotFound
	}
	delete(memory.records, id)
	record.Message = bytes.Clone(record.Message)
	return record, nil
}

type sessionMemory struct {
	records map[string]SessionRecord
	saveErr error
}

func (memory *sessionMemory) SaveSession(_ context.Context, record SessionRecord) error {
	if memory.saveErr != nil {
		return memory.saveErr
	}
	if _, exists := memory.records[record.TokenDigest]; exists {
		return ErrConflict
	}
	memory.records[record.TokenDigest] = record
	return nil
}

func (memory *sessionMemory) LookupSession(_ context.Context, digest string) (SessionRecord, error) {
	record, exists := memory.records[digest]
	if !exists {
		return SessionRecord{}, ErrNotFound
	}
	return record, nil
}

func (memory *sessionMemory) RevokeSession(_ context.Context, digest string, revokedAt time.Time) error {
	record, exists := memory.records[digest]
	if !exists {
		return ErrNotFound
	}
	record.RevokedAt = revokedAt
	memory.records[digest] = record
	return nil
}

type auditMemory struct {
	events []AuthenticationEvent
	err    error
}

func (memory *auditMemory) AppendAuthenticationEvent(_ context.Context, event AuthenticationEvent) error {
	if memory.err != nil {
		return memory.err
	}
	memory.events = append(memory.events, event)
	return nil
}

func TestChallengeProofIssuesDigestOnlySessionAndAudits(t *testing.T) {
	service, privateKey, actors, challenges, sessions, audit, _ := authenticationFixture(t)
	challenge, err := service.Begin(context.Background(), BeginRequest{OrganizationID: testOrganizationID, ActorID: testActorID})
	if err != nil || challenge.ID == "" || challenge.SigningMessage == "" || len(challenges.records) != 1 {
		t.Fatalf("challenge = %+v, records = %+v, err = %v", challenge, challenges.records, err)
	}
	message, err := base64.RawURLEncoding.DecodeString(challenge.SigningMessage)
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	issued, err := service.Complete(context.Background(), CompleteRequest{ChallengeID: challenge.ID, Signature: signature})
	if err != nil || issued.Token == "" || issued.ID == "" || len(challenges.records) != 0 || len(sessions.records) != 1 {
		t.Fatalf("issued = %+v, challenges = %+v, sessions = %+v, err = %v", issued, challenges.records, sessions.records, err)
	}
	stored, ok := sessions.records[tokenDigest(issued.Token)]
	if !ok || stored.ID != issued.ID || stored.TokenDigest == issued.Token || !stored.RevokedAt.IsZero() {
		t.Fatalf("stored session = %+v", stored)
	}
	if len(audit.events) != 2 || audit.events[0].ReasonCode != "challenge_issued" || audit.events[1].ReasonCode != "session_issued" {
		t.Fatalf("audit events = %+v", audit.events)
	}
	encoded, err := json.Marshal(audit.events)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{issued.Token, signature, actors.actor.PublicKey, challenge.SigningMessage, stored.TokenDigest} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("audit contains credential material %q: %s", secret, encoded)
		}
	}
	_, err = service.Complete(context.Background(), CompleteRequest{ChallengeID: challenge.ID, Signature: signature})
	if localidentity.Code(err) != localidentity.Denied || reason(err) != "authentication_failed" || len(audit.events) != 3 {
		t.Fatalf("replay err = %v, audit = %+v", err, audit.events)
	}
}

func TestInvalidProofConsumesChallenge(t *testing.T) {
	service, privateKey, _, challenges, sessions, audit, _ := authenticationFixture(t)
	challenge, err := service.Begin(context.Background(), BeginRequest{OrganizationID: testOrganizationID, ActorID: testActorID})
	if err != nil {
		t.Fatal(err)
	}
	invalid := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err := service.Complete(context.Background(), CompleteRequest{ChallengeID: challenge.ID, Signature: invalid}); localidentity.Code(err) != localidentity.Denied {
		t.Fatalf("invalid proof err = %v", err)
	}
	message, _ := base64.RawURLEncoding.DecodeString(challenge.SigningMessage)
	valid := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	if _, err := service.Complete(context.Background(), CompleteRequest{ChallengeID: challenge.ID, Signature: valid}); localidentity.Code(err) != localidentity.Denied {
		t.Fatalf("consumed challenge err = %v", err)
	}
	if len(challenges.records) != 0 || len(sessions.records) != 0 || len(audit.events) != 3 {
		t.Fatalf("challenges = %+v, sessions = %+v, audit = %+v", challenges.records, sessions.records, audit.events)
	}
}

func TestTamperedChallengeRecordDenies(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ChallengeRecord)
	}{
		{"message", func(record *ChallengeRecord) { record.Message = append(record.Message, 'x') }},
		{"actor", func(record *ChallengeRecord) { record.ActorID = "0198d6c4-aaaa-7aaa-8aaa-aaaaaaaaaaaa" }},
		{"expiry", func(record *ChallengeRecord) { record.ExpiresAt = record.ExpiresAt.Add(time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, privateKey, _, challenges, sessions, _, _ := authenticationFixture(t)
			challenge, err := service.Begin(context.Background(), BeginRequest{OrganizationID: testOrganizationID, ActorID: testActorID})
			if err != nil {
				t.Fatal(err)
			}
			record := challenges.records[challenge.ID]
			test.mutate(&record)
			challenges.records[challenge.ID] = record
			message, _ := base64.RawURLEncoding.DecodeString(challenge.SigningMessage)
			signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
			_, err = service.Complete(context.Background(), CompleteRequest{ChallengeID: challenge.ID, Signature: signature})
			if localidentity.Code(err) != localidentity.Denied || reason(err) != "authentication_failed" || len(sessions.records) != 0 {
				t.Fatalf("sessions = %+v, err = %v", sessions.records, err)
			}
		})
	}
}

func TestMalformedCallerValuesAreNotCopiedToAudit(t *testing.T) {
	service, _, _, _, _, audit, _ := authenticationFixture(t)
	secret := "secret-value-that-must-not-reach-audit"
	if _, err := service.Begin(context.Background(), BeginRequest{OrganizationID: secret, ActorID: secret}); localidentity.Code(err) != localidentity.InvalidInput {
		t.Fatalf("begin err = %v", err)
	}
	if _, err := service.Complete(context.Background(), CompleteRequest{ChallengeID: secret, Signature: secret}); localidentity.Code(err) != localidentity.Denied {
		t.Fatalf("complete err = %v", err)
	}
	encoded, err := json.Marshal(audit.events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("audit contains malformed caller value: %s", encoded)
	}
}

func TestChallengeExpiryRevisionAndRevocationDeny(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*actorMemory, *fixedClock)
		reason string
	}{
		{"expired", func(_ *actorMemory, clock *fixedClock) { clock.current = clock.current.Add(3 * time.Minute) }, "challenge_expired"},
		{"revision", func(actors *actorMemory, _ *fixedClock) { actors.actor.Revision++ }, "actor_revoked"},
		{"revoked", func(actors *actorMemory, _ *fixedClock) { actors.actor.Active = false }, "actor_revoked"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, privateKey, actors, _, sessions, audit, clock := authenticationFixture(t)
			challenge, err := service.Begin(context.Background(), BeginRequest{OrganizationID: testOrganizationID, ActorID: testActorID})
			if err != nil {
				t.Fatal(err)
			}
			test.mutate(actors, clock)
			message, _ := base64.RawURLEncoding.DecodeString(challenge.SigningMessage)
			signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
			_, err = service.Complete(context.Background(), CompleteRequest{ChallengeID: challenge.ID, Signature: signature})
			if localidentity.Code(err) != localidentity.Denied || reason(err) != test.reason || len(sessions.records) != 0 || len(audit.events) != 2 {
				t.Fatalf("sessions = %+v, audit = %+v, err = %v", sessions.records, audit.events, err)
			}
		})
	}
}

func TestAuthenticationFailsClosedWhenAuditUnavailable(t *testing.T) {
	service, privateKey, _, challenges, sessions, audit, clock := authenticationFixture(t)
	audit.err = errors.New("private audit backend detail")
	_, err := service.Begin(context.Background(), BeginRequest{OrganizationID: testOrganizationID, ActorID: testActorID})
	if localidentity.Code(err) != localidentity.Unavailable || reason(err) != "audit_unavailable" || len(challenges.records) != 0 || errors.Is(err, audit.err) {
		t.Fatalf("begin records = %+v, err = %v", challenges.records, err)
	}
	audit.err = nil
	challenge, err := service.Begin(context.Background(), BeginRequest{OrganizationID: testOrganizationID, ActorID: testActorID})
	if err != nil {
		t.Fatal(err)
	}
	message, _ := base64.RawURLEncoding.DecodeString(challenge.SigningMessage)
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	audit.err = errors.New("another private audit detail")
	_, err = service.Complete(context.Background(), CompleteRequest{ChallengeID: challenge.ID, Signature: signature})
	if localidentity.Code(err) != localidentity.Unavailable || reason(err) != "audit_unavailable" || errors.Is(err, audit.err) || len(sessions.records) != 1 {
		t.Fatalf("sessions = %+v, err = %v", sessions.records, err)
	}
	for _, record := range sessions.records {
		if !record.RevokedAt.Equal(clock.current) {
			t.Fatalf("orphan session not revoked: %+v", record)
		}
	}
}

func TestAuthenticationCancellationTimeoutAndRecovery(t *testing.T) {
	service, _, _, _, _, audit, _ := authenticationFixture(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := service.Begin(canceled, BeginRequest{OrganizationID: testOrganizationID, ActorID: testActorID})
	if localidentity.Code(err) != localidentity.Canceled || reason(err) != "request_canceled" {
		t.Fatalf("canceled err = %v", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	_, err = service.Begin(expired, BeginRequest{OrganizationID: testOrganizationID, ActorID: testActorID})
	if localidentity.Code(err) != localidentity.Timeout || reason(err) != "request_timeout" {
		t.Fatalf("timeout err = %v", err)
	}
	if _, err = service.Begin(context.Background(), BeginRequest{OrganizationID: testOrganizationID, ActorID: testActorID}); err != nil {
		t.Fatalf("recovery err = %v", err)
	}
	if len(audit.events) != 3 || audit.events[0].Outcome != "canceled" || audit.events[1].Outcome != "timeout" || audit.events[2].Outcome != "allowed" {
		t.Fatalf("audit = %+v", audit.events)
	}
}

func authenticationFixture(t *testing.T) (Service, ed25519.PrivateKey, *actorMemory, *challengeMemory, *sessionMemory, *auditMemory, *fixedClock) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actors := &actorMemory{actor: localidentity.Actor{
		SchemaVersion: localidentity.SchemaVersion, ContractVersion: localidentity.ContractVersion,
		ID: testActorID, OrganizationID: testOrganizationID, Name: "analyst.one",
		Roles:     []localidentity.Role{localidentity.Analyst},
		Grants:    []localidentity.ScopeGrant{{TenantID: testTenantID, CaseIDs: []string{testCaseID}}},
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), Revision: 1, Active: true,
	}}
	challenges := &challengeMemory{records: make(map[string]ChallengeRecord)}
	sessions := &sessionMemory{records: make(map[string]SessionRecord)}
	audit := &auditMemory{}
	clock := &fixedClock{current: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
	randomBytes := make([]byte, 1024)
	for index := range randomBytes {
		randomBytes[index] = byte(index)
	}
	return Service{
		Actors: actors, Challenges: challenges, Sessions: sessions, Audit: audit,
		Random: bytes.NewReader(randomBytes), Clock: clock,
	}, privateKey, actors, challenges, sessions, audit, clock
}
