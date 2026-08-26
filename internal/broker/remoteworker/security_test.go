package remoteworker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

func TestLeaseReplayTamperExpiryAndRecovery(t *testing.T) {
	broker, store, audit, clock := setupBroker(t)
	record, enrollmentAuthority, _ := enrollWorker(t, broker, clock)
	request, authority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	handle, _, err := broker.Issue(context.Background(), request, authority)
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, _, duplicateErr := broker.Issue(context.Background(), request, authority); duplicate != nil ||
		workercontract.Reason(duplicateErr) != "lease_issuance_replay" {
		t.Fatalf("duplicate=%v err=%v", duplicate, duplicateErr)
	}
	handle.mu.Lock()
	handle.token[0] ^= 0xff
	handle.mu.Unlock()
	dispatch := dispatchFixture(handle.LeaseID, request.Scope)
	called := false
	if _, err = broker.Use(context.Background(), handle, dispatch, authority,
		func(context.Context, workercontract.DispatchEnvelope) error { called = true; return nil }); workercontract.Reason(err) != "capability_invalid" || called {
		t.Fatalf("tamper called=%v err=%v", called, err)
	}

	request.IdempotencyKey, request.RequestID = "lease-expiry", "018f47a6-4b2c-7a1e-8a12-123456789ac2"
	expiring, _, err := broker.Issue(context.Background(), request, authority)
	if err != nil {
		t.Fatal(err)
	}
	clock.Add(31 * time.Second)
	if _, err = broker.Use(context.Background(), expiring,
		dispatchFixture(expiring.LeaseID, request.Scope), authority,
		func(context.Context, workercontract.DispatchEnvelope) error { called = true; return nil }); workercontract.Reason(err) != "lease_expired" {
		t.Fatalf("expiry err=%v", err)
	}

	// A new broker using the same durable-store interface preserves consumed
	// state. Reconstructing a broker never recreates capability bytes.
	recovered, err := NewWithDependencies(store, audit, clock, &repeatReader{value: 90}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = recovered.Use(context.Background(), expiring,
		dispatchFixture(expiring.LeaseID, request.Scope), authority,
		func(context.Context, workercontract.DispatchEnvelope) error { called = true; return nil }); workercontract.Reason(err) != "capability_destroyed" {
		t.Fatalf("recovery replay err=%v", err)
	}
}

func TestDispatchAuditAndCallbackFailure(t *testing.T) {
	broker, _, audit, clock := setupBroker(t)
	record, enrollmentAuthority, _ := enrollWorker(t, broker, clock)
	request, authority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	handle, _, err := broker.Issue(context.Background(), request, authority)
	if err != nil {
		t.Fatal(err)
	}
	audit.fail = true
	called := false
	_, err = broker.Use(context.Background(), handle,
		dispatchFixture(handle.LeaseID, request.Scope), authority,
		func(context.Context, workercontract.DispatchEnvelope) error { called = true; return nil })
	if workercontract.Reason(err) != "audit_unavailable" || called {
		t.Fatalf("audit called=%v err=%v", called, err)
	}

	audit.fail = false
	request.IdempotencyKey, request.RequestID = "lease-callback", "018f47a6-4b2c-7a1e-8a12-123456789ac2"
	handle, _, err = broker.Issue(context.Background(), request, authority)
	if err != nil {
		t.Fatal(err)
	}
	_, err = broker.Use(context.Background(), handle,
		dispatchFixture(handle.LeaseID, request.Scope), authority,
		func(context.Context, workercontract.DispatchEnvelope) error { return errors.New("runner disconnected") })
	if workercontract.Reason(err) != "runner_callback_failed" {
		t.Fatalf("callback err=%v", err)
	}
	last := audit.decisions[len(audit.decisions)-1]
	if last.Event != "runner_dispatch_completion" || last.Outcome != "unavailable" || last.ReasonCode != "runner_callback_failed" {
		t.Fatalf("completion=%#v", last)
	}
}

func TestCertificateRotationRevokesOutstandingLease(t *testing.T) {
	broker, _, _, clock := setupBroker(t)
	record, enrollmentAuthority, privateKey := enrollWorker(t, broker, clock)
	leaseRequest, leaseAuthority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	handle, _, err := broker.Issue(context.Background(), leaseRequest, leaseAuthority)
	if err != nil {
		t.Fatal(err)
	}
	rotatedAuthority, rotatedRequest := enrollmentFixture(t, clock.Now(), privateKey)
	rotatedAuthority.ExpectedCurrentRevision = record.Revision
	rotatedAuthority.ExpectedEnrollmentNonce = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("r", 16)))
	rotatedAuthority.Transport.CertificateRevision++
	rotatedAuthority.Transport.CertificateFingerprint = digest("certificate-rotated")
	rotatedAuthority.Transport.IdentityDigest = digest("transport-rotated")
	rotatedRequest.IdempotencyKey = "enroll-rotated"
	rotatedRequest.RequestID = "018f47a6-4b2c-7a1e-8a12-123456789ac2"
	rotatedRequest.EnrollmentNonce = rotatedAuthority.ExpectedEnrollmentNonce
	var envelope workercontract.SignedCapabilityAttestation
	if err = json.Unmarshal(rotatedRequest.SignedAttestation, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Attestation.EnrollmentNonce = rotatedRequest.EnrollmentNonce
	envelope.Attestation.CertificateRevision = rotatedAuthority.Transport.CertificateRevision
	envelope.Attestation.CertificateFingerprint = rotatedAuthority.Transport.CertificateFingerprint
	envelope.Attestation.TransportIdentityDigest = rotatedAuthority.Transport.IdentityDigest
	rotatedRequest.SignedAttestation = signedAttestation(t, envelope.Attestation, rotatedAuthority, privateKey)
	rotated, _, err := broker.Enroll(context.Background(), rotatedRequest, rotatedAuthority)
	if err != nil || rotated.Revision != 2 {
		t.Fatalf("rotated=%#v err=%v", rotated, err)
	}
	called := false
	_, err = broker.Use(context.Background(), handle,
		dispatchFixture(handle.LeaseID, leaseRequest.Scope), leaseAuthority,
		func(context.Context, workercontract.DispatchEnvelope) error { called = true; return nil })
	if workercontract.Reason(err) != "lease_revoked" || called {
		t.Fatalf("called=%v err=%v", called, err)
	}
}

func TestPolicyApprovalCancellationAndRedaction(t *testing.T) {
	broker, _, audit, clock := setupBroker(t)
	record, enrollmentAuthority, _ := enrollWorker(t, broker, clock)
	request, authority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
	tests := []struct {
		name   string
		mutate func(*workercontract.LeaseAuthority)
	}{
		{"policy", func(value *workercontract.LeaseAuthority) { value.PolicyAllowed = false }},
		{"approval", func(value *workercontract.LeaseAuthority) { value.ApprovalAllowed = false }},
		{"actor", func(value *workercontract.LeaseAuthority) { value.ActorActive = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := authority
			test.mutate(&changed)
			if handle, _, err := broker.Issue(context.Background(), request, changed); handle != nil ||
				workercontract.Code(err) != workercontract.Denied {
				t.Fatalf("handle=%v err=%v", handle, err)
			}
		})
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if handle, _, err := broker.Issue(canceled, request, authority); handle != nil || workercontract.Code(err) != workercontract.Canceled {
		t.Fatalf("canceled handle=%v err=%v", handle, err)
	}
	timedOut, timeoutCancel := context.WithDeadline(context.Background(), clock.Now().Add(-time.Second))
	defer timeoutCancel()
	if handle, _, err := broker.Issue(timedOut, request, authority); handle != nil || workercontract.Code(err) != workercontract.Timeout {
		t.Fatalf("timeout handle=%v err=%v", handle, err)
	}
	encoded, err := json.Marshal(audit.decisions)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"signature", "enrollment_nonce", "lease_token", "private_key"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("audit contains %q: %s", forbidden, encoded)
		}
	}
}

func TestDirectLeaseAndCertificateRevocation(t *testing.T) {
	for _, kind := range []string{"lease", "certificate", "attestation"} {
		t.Run(kind, func(t *testing.T) {
			broker, _, _, clock := setupBroker(t)
			record, enrollmentAuthority, _ := enrollWorker(t, broker, clock)
			request, authority := leaseFixture(record, enrollmentAuthority.Transport, clock.Now())
			handle, _, err := broker.Issue(context.Background(), request, authority)
			if err != nil {
				t.Fatal(err)
			}
			revocation := revocationFixture(kind, record.Scope, workerID, "", kind+"_revoked")
			if kind == "lease" {
				revocation.WorkerID, revocation.LeaseID, revocation.Reason = "", handle.LeaseID, "operator_revoked"
			}
			if _, err = broker.Revoke(context.Background(), revocation); err != nil {
				t.Fatal(err)
			}
			called := false
			_, err = broker.Use(context.Background(), handle,
				dispatchFixture(handle.LeaseID, request.Scope), authority,
				func(context.Context, workercontract.DispatchEnvelope) error { called = true; return nil })
			if workercontract.Reason(err) != "lease_revoked" || called {
				t.Fatalf("called=%v err=%v", called, err)
			}
		})
	}
}

func TestAttestationKeyRotationRequiresNewKeyMaterial(t *testing.T) {
	broker, _, _, clock := setupBroker(t)
	record, _, privateKey := enrollWorker(t, broker, clock)
	authority, request := enrollmentFixture(t, clock.Now(), privateKey)
	authority.ExpectedCurrentRevision = record.Revision
	authority.ExpectedEnrollmentNonce = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("k", 16)))
	authority.AttestationKeyRevision++
	request.IdempotencyKey = "same-key-new-revision"
	request.EnrollmentNonce = authority.ExpectedEnrollmentNonce
	var envelope workercontract.SignedCapabilityAttestation
	if err := json.Unmarshal(request.SignedAttestation, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Attestation.EnrollmentNonce = request.EnrollmentNonce
	request.SignedAttestation = signedAttestation(t, envelope.Attestation, authority, privateKey)
	if _, _, err := broker.Enroll(context.Background(), request, authority); workercontract.Reason(err) != "attestation_key_rotation_invalid" {
		t.Fatalf("same key rotation err=%v", err)
	}
}
