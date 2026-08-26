package remoteworker

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

func TestEnrollSuccessExactReplayAndConflict(t *testing.T) {
	broker, _, audit, clock := setupBroker(t)
	privateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("w", ed25519.SeedSize)))
	authority, request := enrollmentFixture(t, clock.Now(), privateKey)
	first, decision, err := broker.Enroll(context.Background(), request, authority)
	if err != nil || first.Revision != 1 || decision.Outcome != "allowed" {
		t.Fatalf("first=%#v decision=%#v err=%v", first, decision, err)
	}
	replayed, _, err := broker.Enroll(context.Background(), request, authority)
	if err != nil || replayed.Revision != first.Revision {
		t.Fatalf("replay=%#v err=%v", replayed, err)
	}
	request.WorkerID = "worker-02"
	if _, _, err = broker.Enroll(context.Background(), request, authority); workercontract.Code(err) != workercontract.Denied {
		t.Fatalf("scope mismatch err=%v", err)
	}
	if len(audit.decisions) != 3 {
		t.Fatalf("audit decisions=%d", len(audit.decisions))
	}
}

func TestEnrollmentAuditFailureRevokesWorker(t *testing.T) {
	broker, store, audit, clock := setupBroker(t)
	privateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("w", ed25519.SeedSize)))
	authority, request := enrollmentFixture(t, clock.Now(), privateKey)
	audit.fail = true
	if _, _, err := broker.Enroll(context.Background(), request, authority); workercontract.Reason(err) != "audit_unavailable" {
		t.Fatalf("err=%v", err)
	}
	current, err := store.CurrentWorker(context.Background(), authority.Scope, authority.WorkerID)
	if err != nil || current.Active || current.RevocationReason != "audit_unavailable" {
		t.Fatalf("current=%#v err=%v", current, err)
	}
}

func TestEnrollmentRotationContinuity(t *testing.T) {
	broker, _, _, clock := setupBroker(t)
	record, oldAuthority, privateKey := enrollWorker(t, broker, clock)
	authority, request := enrollmentFixture(t, clock.Now(), privateKey)
	authority.ExpectedCurrentRevision = record.Revision
	authority.ExpectedEnrollmentNonce = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("r", 16)))
	request.IdempotencyKey, request.EnrollmentNonce = "enroll-2", authority.ExpectedEnrollmentNonce
	var envelope workercontract.SignedCapabilityAttestation
	if err := json.Unmarshal(request.SignedAttestation, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Attestation.EnrollmentNonce = request.EnrollmentNonce
	envelope.Attestation.CertificateRevision++
	authority.Transport.CertificateRevision++
	// Reusing a fingerprint while increasing its revision is forbidden.
	request.SignedAttestation = signedAttestation(t, envelope.Attestation, authority, privateKey)
	if _, _, err := broker.Enroll(context.Background(), request, authority); workercontract.Reason(err) != "certificate_rotation_invalid" {
		t.Fatalf("err=%v old=%#v", err, oldAuthority)
	}
}
