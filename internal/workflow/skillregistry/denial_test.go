package skillregistry

import (
	"bytes"
	"context"
	"testing"
)

func TestStrictDecodingAndSignatureDenials(t *testing.T) {
	fixture := newFixture(t)
	manifest := fixture.manifest(t, "1.0.0", "", "2")
	envelope, digest := fixture.envelope(t, manifest)

	t.Run("unknown envelope field", func(t *testing.T) {
		mutated := append(append([]byte(nil), envelope[:len(envelope)-1]...), []byte(`,"unknown":true}`)...)
		if _, err := decodeEnvelope(context.Background(), mutated); CodeOf(err) != InvalidInput {
			t.Fatalf("unknown field accepted: %v", err)
		}
	})
	t.Run("duplicate envelope field", func(t *testing.T) {
		mutated := append(append([]byte(nil), envelope[:len(envelope)-1]...),
			[]byte(`,"schema_version":"coh.signed-skill-manifest/v1"}`)...)
		if _, err := decodeEnvelope(context.Background(), mutated); CodeOf(err) != InvalidInput {
			t.Fatalf("duplicate field accepted: %v", err)
		}
	})
	t.Run("semantic byte drift", func(t *testing.T) {
		mutated := bytes.Replace(envelope, []byte("2026-08-26T18:00:00.000000000Z"),
			[]byte("2026-08-26T18:00:00+00:00"), 1)
		if _, err := decodeEnvelope(context.Background(), mutated); CodeOf(err) != Denied ||
			Reason(err) != "manifest_byte_drift" {
			t.Fatalf("byte drift accepted: %v", err)
		}
	})
	t.Run("manifest tamper", func(t *testing.T) {
		mutated := bytes.Replace(envelope, []byte(testDigest("2")), []byte(testDigest("4")), 1)
		if _, err := verifyEnvelope(context.Background(), mutated, fixture.publisher,
			[]SigningAuthority{fixture.reviewer}, fixture.review); CodeOf(err) != Denied {
			t.Fatalf("tamper accepted: %v", err)
		}
	})
	t.Run("revoked publisher", func(t *testing.T) {
		publisher := fixture.publisher
		publisher.Active = false
		if _, err := verifyEnvelope(context.Background(), envelope, publisher,
			[]SigningAuthority{fixture.reviewer}, fixture.review); CodeOf(err) != Denied {
			t.Fatalf("revoked publisher accepted: %v", err)
		}
	})
	t.Run("approval rollback", func(t *testing.T) {
		publisher := fixture.publisher
		publisher.ApprovalRevision++
		if _, err := verifyEnvelope(context.Background(), envelope, publisher,
			[]SigningAuthority{fixture.reviewer}, fixture.review); CodeOf(err) != Denied ||
			Reason(err) != "signature_authority_mismatch" {
			t.Fatalf("stale signature accepted: %v", err)
		}
	})
	t.Run("revoked reviewer", func(t *testing.T) {
		reviewer := fixture.reviewer
		reviewer.Active = false
		if _, err := verifyEnvelope(context.Background(), envelope, fixture.publisher,
			[]SigningAuthority{reviewer}, fixture.review); CodeOf(err) != Denied {
			t.Fatalf("revoked reviewer accepted: %v", err)
		}
	})

	request := fixture.changeRequest(t, "strict-command", Promote, envelope, digest, "", 0)
	t.Run("unknown command field", func(t *testing.T) {
		mutated := append(append([]byte(nil), request.SignedCommand[:len(request.SignedCommand)-1]...),
			[]byte(`,"unknown":true}`)...)
		if _, err := verifyChange(context.Background(), mutated, fixture.owner); CodeOf(err) != InvalidInput {
			t.Fatalf("unknown command field accepted: %v", err)
		}
	})
	t.Run("command signature tamper", func(t *testing.T) {
		mutated := bytes.Replace(request.SignedCommand, []byte(testDigest("d")), []byte(testDigest("8")), 1)
		if _, err := verifyChange(context.Background(), mutated, fixture.owner); CodeOf(err) != Denied {
			t.Fatalf("command tamper accepted: %v", err)
		}
	})
}

func TestPolicyAuditScopePermissionAndAuthorityFailClosed(t *testing.T) {
	fixture := newFixture(t)
	manifest := fixture.manifest(t, "1.0.0", "", "2")
	envelope, digest := fixture.envelope(t, manifest)

	t.Run("policy scope mismatch", func(t *testing.T) {
		store, auditor := newMemoryStore(), newMemoryAuditor()
		registry, _ := New(store, auditor, fixedClock{fixture.now})
		request := fixture.changeRequest(t, "policy-mismatch", Promote, envelope, digest, "", 0)
		request.Policy.TaskID = deterministicUUID("wrong", "task")
		request.Policy.DecisionDigest, _ = policyDecisionDigest(request.Policy)
		if _, err := registry.Change(context.Background(), request); CodeOf(err) != Denied ||
			Reason(err) != "policy_scope_mismatch" || store.commits != 0 || auditor.count != 0 {
			t.Fatalf("policy mismatch did not fail closed: %v", err)
		}
	})

	t.Run("policy digest tamper", func(t *testing.T) {
		store, auditor := newMemoryStore(), newMemoryAuditor()
		registry, _ := New(store, auditor, fixedClock{fixture.now})
		request := fixture.changeRequest(t, "policy-digest", Promote, envelope, digest, "", 0)
		request.Policy.DecisionDigest = testDigest("7")
		if _, err := registry.Change(context.Background(), request); CodeOf(err) != Denied ||
			Reason(err) != "policy_decision_digest_invalid" || store.commits != 0 || auditor.count != 0 {
			t.Fatalf("policy digest tamper did not fail closed: %v", err)
		}
	})

	t.Run("audit unavailable before visibility", func(t *testing.T) {
		store, auditor := newMemoryStore(), newMemoryAuditor()
		auditor.fail = true
		registry, _ := New(store, auditor, fixedClock{fixture.now})
		request := fixture.changeRequest(t, "audit-fail", Promote, envelope, digest, "", 0)
		if _, err := registry.Change(context.Background(), request); CodeOf(err) != Unavailable ||
			store.commits != 0 || store.stateFound {
			t.Fatalf("audit failure became visible: %v", err)
		}
	})

	t.Run("permission and scope denied", func(t *testing.T) {
		store, auditor := newMemoryStore(), newMemoryAuditor()
		registry, _ := New(store, auditor, fixedClock{fixture.now})
		request := fixture.changeRequest(t, "resolve-denials", Promote, envelope, digest, "", 0)
		if _, err := registry.Change(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		resolve := resolutionRequest(fixture, digest, "permission")
		resolve.RequiredPermission = "secrets.read"
		access := accessDecision(fixture, digest, "permission")
		access.Permission = "secrets.read"
		access.DecisionDigest, _ = accessDecisionDigest(access)
		if _, err := registry.Resolve(context.Background(), resolve, access,
			resolutionAuthority(fixture)); CodeOf(err) != Denied || Reason(err) != "permission_not_promoted" {
			t.Fatalf("unpromoted permission resolved: %v", err)
		}

		resolve = resolutionRequest(fixture, digest, "access-digest")
		access = accessDecision(fixture, digest, "access-digest")
		access.DecisionDigest = testDigest("7")
		if _, err := registry.Resolve(context.Background(), resolve, access,
			resolutionAuthority(fixture)); CodeOf(err) != Denied ||
			Reason(err) != "access_decision_digest_invalid" {
			t.Fatalf("access digest tamper accepted: %v", err)
		}

		resolve = resolutionRequest(fixture, digest, "scope")
		access = accessDecision(fixture, digest, "scope")
		access.CaseID = deterministicUUID("wrong", "case")
		access.DecisionDigest, _ = accessDecisionDigest(access)
		if _, err := registry.Resolve(context.Background(), resolve, access,
			resolutionAuthority(fixture)); CodeOf(err) != Denied || Reason(err) != "access_scope_mismatch" {
			t.Fatalf("cross-scope resolution accepted: %v", err)
		}

		auditor.fail = true
		resolve = resolutionRequest(fixture, digest, "audit-resolution")
		access = accessDecision(fixture, digest, "audit-resolution")
		if _, err := registry.Resolve(context.Background(), resolve, access,
			resolutionAuthority(fixture)); CodeOf(err) != Unavailable {
			t.Fatalf("resolution ignored audit failure: %v", err)
		}

		auditor.fail = false
		authority := resolutionAuthority(fixture)
		authority.Publisher.Active = false
		resolve = resolutionRequest(fixture, digest, "revoked-publisher")
		access = accessDecision(fixture, digest, "revoked-publisher")
		if _, err := registry.Resolve(context.Background(), resolve, access, authority); CodeOf(err) != Denied || Reason(err) != "publisher_authority_invalid" {
			t.Fatalf("revoked publisher still resolved: %v", err)
		}
	})
}

func TestCancellationTimeoutAndStaleState(t *testing.T) {
	fixture := newFixture(t)
	manifest := fixture.manifest(t, "1.0.0", "", "2")
	envelope, digest := fixture.envelope(t, manifest)
	store, auditor := newMemoryStore(), newMemoryAuditor()
	registry, _ := New(store, auditor, fixedClock{fixture.now})
	request := fixture.changeRequest(t, "canceled", Promote, envelope, digest, "", 0)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := registry.Change(canceled, request); CodeOf(err) != Canceled {
		t.Fatalf("cancellation not preserved: %v", err)
	}
	deadline, stop := context.WithDeadline(context.Background(), fixture.now.Add(-1))
	defer stop()
	if _, err := registry.Change(deadline, request); CodeOf(err) != Timeout {
		t.Fatalf("timeout not preserved: %v", err)
	}

	request = fixture.changeRequest(t, "initial", Promote, envelope, digest, "", 0)
	if _, err := registry.Change(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	stale := fixture.changeRequest(t, "stale", Revoke, nil, digest, digest, 99)
	if _, err := registry.Change(context.Background(), stale); CodeOf(err) != Conflict ||
		Reason(err) != "expected_state_stale" {
		t.Fatalf("stale state accepted: %v", err)
	}
}
