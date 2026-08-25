package oidcauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
	"github.com/ArronJablonowski/COH/internal/domain/oidcidentity"
)

func TestTokenClaimsFailClosed(t *testing.T) {
	otherNonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	tests := []struct {
		name   string
		mutate func(*oidcidentity.Claims)
		reason string
	}{
		{"issuer", func(claims *oidcidentity.Claims) { claims.Issuer = "https://other.example.invalid" }, "token_scope_mismatch"},
		{"audience", func(claims *oidcidentity.Claims) { claims.Audiences = []string{"other-server"} }, "token_scope_mismatch"},
		{"organization", func(claims *oidcidentity.Claims) { claims.OrganizationID = uuid("9") }, "token_scope_mismatch"},
		{"actor", func(claims *oidcidentity.Claims) { claims.ActorID = uuid("9") }, "actor_assertion_mismatch"},
		{"roles", func(claims *oidcidentity.Claims) { claims.Roles = []localidentity.Role{localidentity.Auditor} }, "actor_assertion_stale"},
		{"tenants", func(claims *oidcidentity.Claims) { claims.TenantIDs = []string{uuid("9")} }, "actor_assertion_stale"},
		{"nonce", func(claims *oidcidentity.Claims) { claims.Nonce = otherNonce }, "token_nonce_mismatch"},
		{"future", func(claims *oidcidentity.Claims) {
			claims.IssuedAt += 31
			claims.ExpiresAt = claims.IssuedAt + 299
		}, "token_time_invalid"},
		{"too-old", func(claims *oidcidentity.Claims) {
			claims.IssuedAt -= 331
			claims.NotBefore = claims.IssuedAt
		}, "token_time_invalid"},
		{"expired", func(claims *oidcidentity.Claims) {
			claims.IssuedAt -= 100
			claims.NotBefore = claims.IssuedAt
			claims.ExpiresAt = time.Unix(claims.ExpiresAt, 0).Add(-331 * time.Second).Unix()
		}, "token_time_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuthFixture(t, "native_server", "EdDSA")
			_, err := completeLogin(t, fixture, test.mutate)
			if localidentity.Code(err) != localidentity.Denied || reason(err) != test.reason {
				t.Fatalf("code = %s, reason = %s, err = %v", localidentity.Code(err), reason(err), err)
			}
		})
	}
}

func TestJOSEAndSignatureValidationFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		header string
		alter  func([]byte) []byte
	}{
		{"none-algorithm", `{"alg":"none","kid":"key-1","typ":"JWT"}`, nil},
		{"algorithm-substitution", `{"alg":"RS256","kid":"key-1","typ":"JWT"}`, nil},
		{"unknown-key", `{"alg":"EdDSA","kid":"key-2","typ":"JWT"}`, nil},
		{"wrong-type", `{"alg":"EdDSA","kid":"key-1","typ":"JWS"}`, nil},
		{"unknown-header", `{"alg":"EdDSA","kid":"key-1","typ":"JWT","jku":"https://attacker.invalid/jwks"}`, nil},
		{"duplicate-header", `{"alg":"EdDSA","alg":"EdDSA","kid":"key-1","typ":"JWT"}`, nil},
		{"wrong-signature", `{"alg":"EdDSA","kid":"key-1","typ":"JWT"}`, corruptSignature},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuthFixture(t, "native_server", "EdDSA")
			state, err := fixture.service.Begin(context.Background(), BeginRequest{OrganizationID: fixture.actor.OrganizationID, Audience: "coh-server"})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(validClaims(fixture, state.Nonce))
			if err != nil {
				t.Fatal(err)
			}
			token := signRawToken(t, []byte(test.header), payload, fixture.privateKey)
			if test.alter != nil {
				token = test.alter(token)
			}
			_, err = fixture.service.Complete(context.Background(), state.ID, token)
			if localidentity.Code(err) != localidentity.Denied || reason(err) != "token_invalid" {
				t.Fatalf("code = %s, reason = %s, err = %v", localidentity.Code(err), reason(err), err)
			}
		})
	}
}

func TestClaimsDecoderRejectsAmbiguityAndOversize(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload func([]byte) []byte
	}{
		{"unknown-claim", func(input []byte) []byte { return append(input[:len(input)-1], []byte(`,"admin":true}`)...) }},
		{"duplicate-claim", func(input []byte) []byte {
			return append(input[:len(input)-1], []byte(`,"iss":"https://identity.example.invalid/tenant-a"}`)...)
		}},
		{"trailing-json", func(input []byte) []byte { return append(input, []byte(` {}`)...) }},
		{"oversize", func(input []byte) []byte { return append(input, make([]byte, maximumCompactTokenBytes)...) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAuthFixture(t, "native_server", "EdDSA")
			state, err := fixture.service.Begin(context.Background(), BeginRequest{OrganizationID: fixture.actor.OrganizationID, Audience: "coh-server"})
			if err != nil {
				t.Fatal(err)
			}
			payload, err := json.Marshal(validClaims(fixture, state.Nonce))
			if err != nil {
				t.Fatal(err)
			}
			token := signRawToken(t, []byte(`{"alg":"EdDSA","kid":"key-1","typ":"JWT"}`), test.payload(payload), fixture.privateKey)
			_, err = fixture.service.Complete(context.Background(), state.ID, token)
			if localidentity.Code(err) != localidentity.Denied || reason(err) != "token_invalid" {
				t.Fatalf("code = %s, reason = %s, err = %v", localidentity.Code(err), reason(err), err)
			}
		})
	}
}

func TestLoginStateIsSingleUseAndAtomic(t *testing.T) {
	fixture := newAuthFixture(t, "native_server", "EdDSA")
	state, err := fixture.service.Begin(context.Background(), BeginRequest{OrganizationID: fixture.actor.OrganizationID, Audience: "coh-server"})
	if err != nil {
		t.Fatal(err)
	}
	token := signToken(t, "EdDSA", "key-1", validClaims(fixture, state.Nonce), fixture.privateKey)
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			issued, completeErr := fixture.service.Complete(context.Background(), state.ID, token)
			if issued != nil {
				issued.Destroy()
			}
			errorsSeen <- completeErr
		}()
	}
	wait.Wait()
	close(errorsSeen)
	successes, denials := 0, 0
	for completeErr := range errorsSeen {
		switch {
		case completeErr == nil:
			successes++
		case localidentity.Code(completeErr) == localidentity.Denied && reason(completeErr) == "authentication_failed":
			denials++
		default:
			t.Fatalf("unexpected completion error: %v", completeErr)
		}
	}
	if successes != 1 || denials != 1 {
		t.Fatalf("successes = %d, denials = %d", successes, denials)
	}
}

func TestExpiredStateSessionAndInactiveKeyAreDenied(t *testing.T) {
	t.Run("login-state", func(t *testing.T) {
		fixture := newAuthFixture(t, "native_server", "EdDSA")
		state, err := fixture.service.Begin(context.Background(), BeginRequest{OrganizationID: fixture.actor.OrganizationID, Audience: "coh-server"})
		if err != nil {
			t.Fatal(err)
		}
		fixture.clock.now = fixture.clock.now.Add(defaultStateTTL)
		token := signToken(t, "EdDSA", "key-1", validClaims(fixture, state.Nonce), fixture.privateKey)
		_, err = fixture.service.Complete(context.Background(), state.ID, token)
		if localidentity.Code(err) != localidentity.Denied || reason(err) != "login_state_expired" {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("session", func(t *testing.T) {
		fixture := newAuthFixture(t, "native_server", "EdDSA")
		_, token := fixture.login(t, nil)
		fixture.clock.now = fixture.clock.now.Add(5 * time.Minute)
		decision, err := fixture.service.Authorize(context.Background(), token, validAuthorizationRequest(fixture.actor))
		if localidentity.Code(err) != localidentity.Denied || reason(err) != "session_expired" || decision.Outcome != "denied" {
			t.Fatalf("decision = %+v, err = %v", decision, err)
		}
	})
	t.Run("inactive-signing-key", func(t *testing.T) {
		fixture := newAuthFixture(t, "native_server", "EdDSA")
		record, err := fixture.keys.LookupKey(context.Background(), fixture.service.Config.Issuer, fixture.service.Config.JWKSReference, "key-1")
		if err != nil {
			t.Fatal(err)
		}
		record.Revision++
		record.Active = false
		if err := fixture.keys.Replace(context.Background(), record); err != nil {
			t.Fatal(err)
		}
		_, err = completeLogin(t, fixture, nil)
		if localidentity.Code(err) != localidentity.Denied || reason(err) != "signing_key_revoked" {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestAuditFailureCannotIssueOrAuthorize(t *testing.T) {
	t.Run("begin", func(t *testing.T) {
		fixture := newAuthFixture(t, "native_server", "EdDSA")
		fixture.audit.err = errors.New("audit offline with secret subject-analyst-001")
		state, err := fixture.service.Begin(context.Background(), BeginRequest{OrganizationID: fixture.actor.OrganizationID, Audience: "coh-server"})
		if localidentity.Code(err) != localidentity.Unavailable || reason(err) != "audit_unavailable" || state.ID != "" || strings.Contains(err.Error(), "secret") {
			t.Fatalf("state = %+v, err = %v", state, err)
		}
	})
	t.Run("complete", func(t *testing.T) {
		fixture := newAuthFixture(t, "native_server", "EdDSA")
		state, err := fixture.service.Begin(context.Background(), BeginRequest{OrganizationID: fixture.actor.OrganizationID, Audience: "coh-server"})
		if err != nil {
			t.Fatal(err)
		}
		token := signToken(t, "EdDSA", "key-1", validClaims(fixture, state.Nonce), fixture.privateKey)
		fixture.audit.err = errors.New("offline")
		issued, err := fixture.service.Complete(context.Background(), state.ID, token)
		if localidentity.Code(err) != localidentity.Unavailable || reason(err) != "audit_unavailable" || issued != nil {
			t.Fatalf("issued = %+v, err = %v", issued, err)
		}
	})
	t.Run("authorize", func(t *testing.T) {
		fixture := newAuthFixture(t, "native_server", "EdDSA")
		_, token := fixture.login(t, nil)
		fixture.audit.err = errors.New("offline")
		decision, err := fixture.service.Authorize(context.Background(), token, validAuthorizationRequest(fixture.actor))
		if localidentity.Code(err) != localidentity.Unavailable || reason(err) != "audit_unavailable" || decision.Outcome != "unavailable" {
			t.Fatalf("decision = %+v, err = %v", decision, err)
		}
	})
}

func TestCancellationIsRecordedWithoutContinuing(t *testing.T) {
	fixture := newAuthFixture(t, "native_server", "EdDSA")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state, err := fixture.service.Begin(ctx, BeginRequest{OrganizationID: fixture.actor.OrganizationID, Audience: "coh-server"})
	if localidentity.Code(err) != localidentity.Canceled || reason(err) != "request_canceled" || state.ID != "" {
		t.Fatalf("state = %+v, err = %v", state, err)
	}
	if len(fixture.audit.events) != 1 || fixture.audit.events[0].Outcome != "canceled" {
		t.Fatalf("events = %+v", fixture.audit.events)
	}
}

func completeLogin(t *testing.T, fixture *authFixture, mutate func(*oidcidentity.Claims)) (*IssuedSession, error) {
	t.Helper()
	state, err := fixture.service.Begin(context.Background(), BeginRequest{OrganizationID: fixture.actor.OrganizationID, Audience: "coh-server"})
	if err != nil {
		t.Fatal(err)
	}
	claims := validClaims(fixture, state.Nonce)
	if mutate != nil {
		mutate(&claims)
	}
	return fixture.service.Complete(context.Background(), state.ID, signToken(t, fixture.service.Config.AllowedAlgorithms[0], "key-1", claims, fixture.privateKey))
}

func signRawToken(t *testing.T, header, payload []byte, privateKey any) []byte {
	t.Helper()
	signed := []byte(encodeRaw(header) + "." + encodeRaw(payload))
	var signature []byte
	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		signature = ed25519.Sign(key, signed)
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(signed)
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		signature = append(fill32(r), fill32(s)...)
	case *rsa.PrivateKey:
		digest := sha256.Sum256(signed)
		var err error
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported private key %T", privateKey)
	}
	return []byte(string(signed) + "." + encodeRaw(signature))
}

func fill32(value *big.Int) []byte {
	result := make([]byte, 32)
	value.FillBytes(result)
	return result
}

func corruptSignature(token []byte) []byte {
	parts := strings.Split(string(token), ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	signature[0] ^= 0xff
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return []byte(strings.Join(parts, "."))
}
