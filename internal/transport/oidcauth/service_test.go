package oidcauth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
	"github.com/ArronJablonowski/COH/internal/domain/oidcidentity"
)

type fixedClock struct{ now time.Time }

func (clock *fixedClock) Now() time.Time { return clock.now }

type auditStub struct {
	mu        sync.Mutex
	events    []Event
	decisions []localidentity.Decision
	err       error
}

func (audit *auditStub) AppendOIDCEvent(_ context.Context, event Event) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.events = append(audit.events, event)
	return audit.err
}

func (audit *auditStub) AppendAuthorizationDecision(_ context.Context, decision localidentity.Decision) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	audit.decisions = append(audit.decisions, decision)
	return audit.err
}

type authFixture struct {
	service    Service
	repository *MemoryRepository
	keys       *MemoryKeySource
	audit      *auditStub
	clock      *fixedClock
	actor      localidentity.Actor
	publicKey  any
	privateKey any
}

func TestServerProfilesAuthenticateAndAuthorizeEveryRequest(t *testing.T) {
	for _, profile := range []string{"native_server", "compose"} {
		t.Run(profile, func(t *testing.T) {
			fixture := newAuthFixture(t, profile, "EdDSA")
			issued, token := fixture.login(t, nil)
			encoded, err := json.Marshal(issued)
			if err != nil || strings.Contains(string(encoded), token) || strings.Contains(strings.ToLower(string(encoded)), "token") {
				t.Fatalf("serialized session = %s, err = %v", encoded, err)
			}
			request := validAuthorizationRequest(fixture.actor)
			decision, err := fixture.service.Authorize(context.Background(), token, request)
			if err != nil || decision.Outcome != "allowed" || decision.ReasonCode != "role_scope_allowed" || decision.SessionID != issued.ID {
				t.Fatalf("decision = %+v, err = %v", decision, err)
			}
			if len(fixture.audit.events) != 2 || len(fixture.audit.decisions) != 1 {
				t.Fatalf("events = %d, decisions = %d", len(fixture.audit.events), len(fixture.audit.decisions))
			}
			serialized := mustJSON(t, fixture.audit.events)
			for _, forbidden := range []string{token, "subject-analyst", "key-1", "token-001", "AAAAAAAAAAAAAAAA"} {
				if strings.Contains(serialized, forbidden) {
					t.Fatalf("audit leaked %q: %s", forbidden, serialized)
				}
			}
		})
	}
}

func TestSupportedSignatureAlgorithms(t *testing.T) {
	for _, algorithm := range []string{"EdDSA", "ES256", "RS256"} {
		t.Run(algorithm, func(t *testing.T) {
			fixture := newAuthFixture(t, "native_server", algorithm)
			_, token := fixture.login(t, nil)
			decision, err := fixture.service.Authorize(context.Background(), token, validAuthorizationRequest(fixture.actor))
			if err != nil || decision.Outcome != "allowed" {
				t.Fatalf("decision = %+v, err = %v", decision, err)
			}
		})
	}
}

func TestAuthorizationRechecksFullScopeRoleAndReplay(t *testing.T) {
	fixture := newAuthFixture(t, "native_server", "EdDSA")
	_, token := fixture.login(t, nil)
	base := validAuthorizationRequest(fixture.actor)
	first, err := fixture.service.Authorize(context.Background(), token, base)
	if err != nil || first.Outcome != "allowed" {
		t.Fatal(err)
	}
	replayed, err := fixture.service.Authorize(context.Background(), token, base)
	if err != nil || !replayed.Replayed {
		t.Fatalf("replayed = %+v, err = %v", replayed, err)
	}
	changed := base
	changed.PayloadDigest = digest("f")
	conflict, err := fixture.service.Authorize(context.Background(), token, changed)
	if localidentity.Code(err) != localidentity.Conflict || reason(err) != "idempotency_conflict" || conflict.Outcome != "denied" {
		t.Fatalf("conflict = %+v, err = %v", conflict, err)
	}
	tests := []struct {
		name   string
		mutate func(*localidentity.Request)
		reason string
	}{
		{"organization", func(request *localidentity.Request) { request.Context.OrganizationID = uuid("9") }, "session_scope_mismatch"},
		{"actor", func(request *localidentity.Request) { request.Context.ActorID = uuid("9") }, "session_scope_mismatch"},
		{"tenant", func(request *localidentity.Request) { request.Context.TenantID = uuid("9") }, "case_scope_denied"},
		{"case", func(request *localidentity.Request) { request.Context.CaseID = uuid("9") }, "case_scope_denied"},
		{"role", func(request *localidentity.Request) { request.Permission = localidentity.IdentityManage }, "role_permission_denied"},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			request.IdempotencyKey = "scope-" + string(rune('a'+index))
			test.mutate(&request)
			decision, err := fixture.service.Authorize(context.Background(), token, request)
			if localidentity.Code(err) != localidentity.Denied || reason(err) != test.reason || decision.Outcome != "denied" {
				t.Fatalf("decision = %+v, err = %v", decision, err)
			}
		})
	}
}

func TestCurrentActorAndKeyStateInvalidateSession(t *testing.T) {
	t.Run("actor-revision", func(t *testing.T) {
		fixture := newAuthFixture(t, "native_server", "EdDSA")
		_, token := fixture.login(t, nil)
		actor := fixture.actor
		actor.Revision++
		actor.Roles = []localidentity.Role{localidentity.Administrator}
		if err := fixture.repository.ReplaceActor(context.Background(), actor); err != nil {
			t.Fatal(err)
		}
		decision, err := fixture.service.Authorize(context.Background(), token, validAuthorizationRequest(fixture.actor))
		if localidentity.Code(err) != localidentity.Denied || reason(err) != "actor_revoked" || decision.Outcome != "denied" {
			t.Fatalf("decision = %+v, err = %v", decision, err)
		}
	})
	t.Run("key-rotation", func(t *testing.T) {
		fixture := newAuthFixture(t, "compose", "EdDSA")
		_, token := fixture.login(t, nil)
		record, err := fixture.keys.LookupKey(context.Background(), fixture.service.Config.Issuer, fixture.service.Config.JWKSReference, "key-1")
		if err != nil {
			t.Fatal(err)
		}
		record.Revision++
		if err := fixture.keys.Replace(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		decision, err := fixture.service.Authorize(context.Background(), token, validAuthorizationRequest(fixture.actor))
		if localidentity.Code(err) != localidentity.Denied || reason(err) != "signing_key_revoked" || decision.Outcome != "denied" {
			t.Fatalf("decision = %+v, err = %v", decision, err)
		}
	})
	t.Run("session-revocation", func(t *testing.T) {
		fixture := newAuthFixture(t, "native_server", "EdDSA")
		_, token := fixture.login(t, nil)
		if err := fixture.service.Revoke(context.Background(), token); err != nil {
			t.Fatal(err)
		}
		decision, err := fixture.service.Authorize(context.Background(), token, validAuthorizationRequest(fixture.actor))
		if localidentity.Code(err) != localidentity.Denied || reason(err) != "session_revoked" || decision.Outcome != "denied" {
			t.Fatalf("decision = %+v, err = %v", decision, err)
		}
	})
}

func newAuthFixture(t *testing.T, profile, algorithm string) *authFixture {
	t.Helper()
	clock := &fixedClock{now: time.Date(2026, 8, 25, 22, 0, 0, 0, time.UTC)}
	_, actorPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actorPublic := actorPrivate.Public().(ed25519.PublicKey)
	actor := localidentity.Actor{SchemaVersion: localidentity.SchemaVersion, ContractVersion: localidentity.ContractVersion,
		ID: uuid("2"), OrganizationID: uuid("1"), Name: "analyst.one", Roles: []localidentity.Role{localidentity.Analyst},
		Grants:    []localidentity.ScopeGrant{{TenantID: uuid("3"), CaseIDs: []string{uuid("4")}}},
		PublicKey: base64.RawURLEncoding.EncodeToString(actorPublic), Revision: 1, Active: true}
	issuer := "https://identity.example.invalid/tenant-a"
	repository, err := NewMemoryRepository([]ActorBinding{{Issuer: issuer, Subject: "subject-analyst-001", Actor: actor}})
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := generateSigningKey(t, algorithm)
	keyRecord := KeyRecord{Issuer: issuer, SourceReference: "identity.primary", ID: "key-1", Algorithm: algorithm,
		Revision: 1, Active: true, PublicKey: publicKey, NotBefore: clock.now.Add(-time.Hour), ExpiresAt: clock.now.Add(time.Hour)}
	keys, err := NewMemoryKeySource([]KeyRecord{keyRecord})
	if err != nil {
		t.Fatal(err)
	}
	audit := &auditStub{}
	config := oidcidentity.ProviderConfig{SchemaVersion: oidcidentity.SchemaVersion, ContractVersion: oidcidentity.ContractVersion,
		ProfileKind: profile, Issuer: issuer, Audiences: []string{"coh-server"}, AllowedAlgorithms: []string{algorithm},
		JWKSReference: "identity.primary", TransportSecurity: "mtls", ProfileDecisionDigest: digest("a"),
		MaximumTokenAgeSeconds: 300, ClockSkewSeconds: 30}
	service := Service{Config: config, Actors: repository, States: repository, Sessions: repository, Replay: repository,
		Keys: keys, Audit: audit, Clock: clock, Random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096))}
	return &authFixture{service: service, repository: repository, keys: keys, audit: audit, clock: clock,
		actor: actor, publicKey: publicKey, privateKey: privateKey}
}

func (fixture *authFixture) login(t *testing.T, mutate func(*oidcidentity.Claims)) (*IssuedSession, string) {
	t.Helper()
	state, err := fixture.service.Begin(context.Background(), BeginRequest{OrganizationID: fixture.actor.OrganizationID, Audience: "coh-server"})
	if err != nil {
		t.Fatal(err)
	}
	claims := validClaims(fixture, state.Nonce)
	if mutate != nil {
		mutate(&claims)
	}
	compact := signToken(t, fixture.service.Config.AllowedAlgorithms[0], "key-1", claims, fixture.privateKey)
	issued, err := fixture.service.Complete(context.Background(), state.ID, compact)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	var token string
	if err := issued.UseToken(func(value string) error { token = value; return nil }); err != nil {
		t.Fatal(err)
	}
	return issued, token
}

func validClaims(fixture *authFixture, nonce string) oidcidentity.Claims {
	now := fixture.clock.now.Unix()
	return oidcidentity.Claims{Issuer: fixture.service.Config.Issuer, Subject: "subject-analyst-001",
		Audiences: []string{"coh-server"}, ExpiresAt: now + 300, IssuedAt: now, NotBefore: now,
		JWTID: "token-001", Nonce: nonce, OrganizationID: fixture.actor.OrganizationID, ActorID: fixture.actor.ID,
		Roles: append([]localidentity.Role(nil), fixture.actor.Roles...), TenantIDs: []string{fixture.actor.Grants[0].TenantID}}
}

func validAuthorizationRequest(actor localidentity.Actor) localidentity.Request {
	return localidentity.Request{SchemaVersion: localidentity.SchemaVersion, ContractVersion: localidentity.ContractVersion,
		RequestID: uuid("5"), IdempotencyKey: "server-request", PayloadDigest: digest("b"), Channel: localidentity.API,
		Context: localidentity.Context{OrganizationID: actor.OrganizationID, TenantID: actor.Grants[0].TenantID,
			CaseID: actor.Grants[0].CaseIDs[0], ActorID: actor.ID}, Permission: localidentity.QueryExecute}
}

func generateSigningKey(t *testing.T, algorithm string) (any, any) {
	t.Helper()
	switch algorithm {
	case "EdDSA":
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return publicKey, privateKey
	case "ES256":
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return &privateKey.PublicKey, privateKey
	case "RS256":
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return &privateKey.PublicKey, privateKey
	default:
		t.Fatalf("unknown algorithm %q", algorithm)
		return nil, nil
	}
}

func signToken(t *testing.T, algorithm, keyID string, claims oidcidentity.Claims, privateKey any) []byte {
	t.Helper()
	header, err := json.Marshal(joseHeader{Algorithm: algorithm, KeyID: keyID, Type: "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encodedHeader, encodedPayload := encodeRaw(header), encodeRaw(payload)
	signed := []byte(encodedHeader + "." + encodedPayload)
	var signature []byte
	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		signature = ed25519.Sign(key, signed)
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(signed)
		r, s, signErr := ecdsa.Sign(rand.Reader, key, digest[:])
		if signErr != nil {
			t.Fatal(signErr)
		}
		signature = append(padded32(r), padded32(s)...)
	case *rsa.PrivateKey:
		digest := sha256.Sum256(signed)
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported private key %T", privateKey)
	}
	return []byte(string(signed) + "." + encodeRaw(signature))
}

func padded32(value *big.Int) []byte {
	result := make([]byte, 32)
	value.FillBytes(result)
	return result
}

func uuid(fill string) string {
	return "0198d6c4-" + strings.Repeat(fill, 4) + "-7" + strings.Repeat(fill, 3) + "-8" + strings.Repeat(fill, 3) + "-" + strings.Repeat(fill, 12)
}

func digest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
