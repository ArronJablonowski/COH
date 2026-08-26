package remoteworker

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	organizationID = "018f47a6-4b2c-7a1e-8a12-123456789abc"
	tenantID       = "018f47a6-4b2c-7a1e-8a12-123456789abd"
	caseID         = "018f47a6-4b2c-7a1e-8a12-123456789abe"
	actorID        = "018f47a6-4b2c-7a1e-8a12-123456789abf"
	taskID         = "018f47a6-4b2c-7a1e-8a12-123456789ac0"
	requestID      = "018f47a6-4b2c-7a1e-8a12-123456789ac1"
	workerID       = "worker-01"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) Add(value time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(value)
}

type fakeAudit struct {
	mu        sync.Mutex
	decisions []workercontract.Decision
	fail      bool
}

func (audit *fakeAudit) AppendRemoteWorkerDecision(_ context.Context, decision workercontract.Decision) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if audit.fail {
		return errors.New("audit unavailable")
	}
	audit.decisions = append(audit.decisions, decision)
	return nil
}

func setupBroker(t *testing.T) (*Broker, *MemoryStore, *fakeAudit, *fakeClock) {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 8, 26, 4, 0, 0, 0, time.UTC)}
	audit := &fakeAudit{}
	store := NewMemoryStore()
	broker, err := NewWithDependencies(store, audit, clock, &repeatReader{value: 7}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return broker, store, audit, clock
}

type repeatReader struct{ value byte }

func (reader *repeatReader) Read(output []byte) (int, error) {
	for index := range output {
		output[index] = reader.value
		reader.value++
	}
	return len(output), nil
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }

type failingStore struct {
	*MemoryStore
	failLeaseCreate bool
}

func (store *failingStore) CreateLease(ctx context.Context, record LeaseRecord) (LeaseCreateResult, error) {
	if store.failLeaseCreate {
		return "", errors.New("store unavailable")
	}
	return store.MemoryStore.CreateLease(ctx, record)
}

func enrollWorker(t *testing.T, broker *Broker, clock *fakeClock) (workercontract.WorkerRecord, workercontract.EnrollmentAuthority, ed25519.PrivateKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("w", ed25519.SeedSize)))
	authority, request := enrollmentFixture(t, clock.Now(), privateKey)
	record, _, err := broker.Enroll(context.Background(), request, authority)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	return record, authority, privateKey
}

func enrollmentFixture(t *testing.T, now time.Time, privateKey ed25519.PrivateKey) (workercontract.EnrollmentAuthority, workercontract.EnrollmentRequest) {
	t.Helper()
	scope := workercontract.Scope{OrganizationID: organizationID, TenantID: tenantID}
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 16)))
	transport := workercontract.TransportIdentity{Kind: "remote_mtls", IdentityDigest: digest("transport"), ObservedAt: now,
		MutualTLS: true, CertificateFingerprint: digest("certificate"), CertificateRevision: 3,
		CertificateNotBefore: now.Add(-time.Hour), CertificateNotAfter: now.Add(time.Hour),
		URISAN: workercontract.ExpectedWorkerURISAN(scope, workerID)}
	attestation := workercontract.CapabilityAttestation{SchemaVersion: workercontract.AttestationSchemaVersion,
		ContractVersion: workercontract.ContractVersion, Scope: scope, WorkerID: workerID, EnrollmentNonce: nonce,
		TransportIdentityDigest: transport.IdentityDigest, CertificateFingerprint: transport.CertificateFingerprint,
		CertificateRevision: transport.CertificateRevision, PlatformOS: "linux", PlatformArchitecture: "amd64",
		ExecutorDigest: digest("executor"), RuntimeDigest: digest("runtime"), ToolRegistryDigest: digest("registry"),
		IsolationClasses: []string{"oci_sandbox", "remote_isolated"}, MaximumActionTier: "T3",
		Resources: workercontract.ResourceCapacity{WallTimeMilliseconds: 60_000, CPUMilliseconds: 30_000,
			MemoryBytes: 1 << 30, OutputBytes: 1 << 20, EphemeralStorageBytes: 1 << 30, ProcessCount: 32, OpenFileCount: 256},
		NetworkModes: []string{"brokered_egress", "none"}, IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(4 * time.Minute).Format(time.RFC3339Nano)}
	authority := workercontract.EnrollmentAuthority{Scope: scope, WorkerID: workerID, EnrollmentAllowed: true,
		EnrollmentDecisionDigest: digest("enrollment-decision"), ExpectedEnrollmentNonce: nonce,
		AttestationKeyID: "worker.attestation", AttestationKeyRevision: 5,
		AttestationPublicKey: privateKey.Public().(ed25519.PublicKey), Transport: transport}
	request := workercontract.EnrollmentRequest{SchemaVersion: workercontract.EnrollmentSchemaVersion,
		ContractVersion: workercontract.ContractVersion, RequestID: requestID, IdempotencyKey: "enroll-1",
		Scope: scope, WorkerID: workerID, EnrollmentNonce: nonce,
		SignedAttestation: signedAttestation(t, attestation, authority, privateKey)}
	return authority, request
}

func signedAttestation(t *testing.T, attestation workercontract.CapabilityAttestation, authority workercontract.EnrollmentAuthority, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	encoded, _ := json.Marshal(attestation)
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	envelope := workercontract.SignedCapabilityAttestation{SchemaVersion: workercontract.EnvelopeSchemaVersion,
		ContractVersion: workercontract.ContractVersion, Attestation: attestation,
		AttestationDigest: "sha256:" + hex.EncodeToString(sum[:]), AttestationKeyID: authority.AttestationKeyID,
		AttestationKeyRevision: authority.AttestationKeyRevision, SignatureAlgorithm: workercontract.SignatureAlgorithm,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey,
			append([]byte(workercontract.SignatureDomain), canonical...)))}
	result, _ := json.Marshal(envelope)
	return result
}

func leaseFixture(record workercontract.WorkerRecord, transport workercontract.TransportIdentity, now time.Time) (workercontract.LeaseRequest, workercontract.LeaseAuthority) {
	resources := workercontract.ResourceCapacity{WallTimeMilliseconds: 10_000, CPUMilliseconds: 5_000,
		MemoryBytes: 1 << 28, OutputBytes: 1 << 18, EphemeralStorageBytes: 1 << 28, ProcessCount: 8, OpenFileCount: 64}
	scope := workercontract.LeaseScope{OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID,
		ActorID: actorID, TaskID: taskID, ActionDigest: digest("action"), TargetDigests: []string{digest("target")},
		ToolName: "collector", ToolVersion: "v1", ToolDigest: digest("tool"),
		ToolRegistryDigest: record.Attestation.ToolRegistryDigest, Operation: "collect",
		RequiredTier: "T2", IsolationClass: "remote_isolated", Resources: resources, NetworkMode: "none",
		ResourcePolicyDigest: digest("resource-policy"), NetworkPolicyDigest: digest("network-policy")}
	request := workercontract.LeaseRequest{SchemaVersion: workercontract.LeaseSchemaVersion,
		ContractVersion: workercontract.ContractVersion, RequestID: requestID, IdempotencyKey: "lease-1",
		Scope: scope, WorkerID: workerID, RequestedTTLSeconds: 30}
	authority := workercontract.LeaseAuthority{Scope: scope, ActorActive: true, ActorRevision: 3, TaskActive: true,
		AuthorizationAllowed: true, AuthorizationDecisionDigest: digest("authorization"), PolicyAllowed: true,
		PolicyDecisionDigest: digest("policy"), ApprovalRequired: true, ApprovalAllowed: true,
		ApprovalDecisionDigest: digest("approval"), Worker: record, Transport: transport, ObservedAt: now}
	return request, authority
}

func dispatchFixture(leaseID string, scope workercontract.LeaseScope) workercontract.DispatchRequest {
	return workercontract.DispatchRequest{SchemaVersion: workercontract.DispatchSchemaVersion,
		ContractVersion: workercontract.ContractVersion, LeaseID: leaseID, Scope: scope, WorkerID: workerID}
}

func revocationFixture(kind string, scope workercontract.Scope, workerIDValue, leaseID, reason string) workercontract.RevocationRequest {
	return workercontract.RevocationRequest{SchemaVersion: workercontract.RevocationSchemaVersion,
		ContractVersion: workercontract.ContractVersion, RequestID: "018f47a6-4b2c-7a1e-8a12-123456789ac3",
		Kind: kind, Scope: scope, WorkerID: workerIDValue, LeaseID: leaseID, Reason: reason}
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
