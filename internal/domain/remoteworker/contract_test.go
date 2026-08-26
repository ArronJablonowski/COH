package remoteworker

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	testOrganizationID = "018f47a6-4b2c-7a1e-8a12-123456789abc"
	testTenantID       = "018f47a6-4b2c-7a1e-8a12-123456789abd"
	testWorkerID       = "worker-01"
)

func TestVerifyCapabilityAttestationAndDefensiveCopy(t *testing.T) {
	now, authority, privateKey, attestation := testAttestation(t)
	input := signAttestation(t, attestation, authority, privateKey)
	verified, err := VerifyCapabilityAttestation(context.Background(), input, authority, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Value().WorkerID != testWorkerID || verified.Digest == "" {
		t.Fatalf("unexpected verified attestation: %#v", verified)
	}
	value := verified.Value()
	value.IsolationClasses[0] = "mutated"
	if verified.Value().IsolationClasses[0] != "oci_sandbox" {
		t.Fatal("verified value was not defensively copied")
	}
}

func TestAttestationDenials(t *testing.T) {
	now, authority, privateKey, attestation := testAttestation(t)
	tests := []struct {
		name   string
		mutate func(*CapabilityAttestation, *AttestationAuthority)
		reason string
	}{
		{"t4", func(value *CapabilityAttestation, _ *AttestationAuthority) { value.MaximumActionTier = "T4" }, "tier_capability_invalid"},
		{"certificate", func(value *CapabilityAttestation, _ *AttestationAuthority) { value.CertificateRevision++ }, "attestation_authority_mismatch"},
		{"nonce", func(value *CapabilityAttestation, _ *AttestationAuthority) {
			value.EnrollmentNonce = base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 16)))
		}, "attestation_authority_mismatch"},
		{"non-mtls", func(_ *CapabilityAttestation, auth *AttestationAuthority) { auth.Transport.MutualTLS = false }, "mutual_tls_identity_invalid"},
		{"local-downgrade", func(_ *CapabilityAttestation, auth *AttestationAuthority) {
			auth.Transport.Kind = "local_socket_authenticated"
		}, "remote_mtls_required"},
		{"expired", func(value *CapabilityAttestation, _ *AttestationAuthority) {
			value.ExpiresAt = now.Format(time.RFC3339Nano)
		}, "attestation_stale"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed, auth := attestation, authority
			test.mutate(&changed, &auth)
			_, err := VerifyCapabilityAttestation(context.Background(), signAttestation(t, changed, auth, privateKey), auth, now)
			if Reason(err) != test.reason {
				t.Fatalf("reason=%q err=%v", Reason(err), err)
			}
		})
	}
}

func TestAttestationTamperUnknownAndDuplicateDenied(t *testing.T) {
	now, authority, privateKey, attestation := testAttestation(t)
	input := signAttestation(t, attestation, authority, privateKey)
	var envelope map[string]any
	if err := json.Unmarshal(input, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["attestation"].(map[string]any)["worker_id"] = "worker-02"
	tampered, _ := json.Marshal(envelope)
	if _, err := VerifyCapabilityAttestation(context.Background(), tampered, authority, now); Reason(err) != "attestation_authority_mismatch" {
		t.Fatalf("tamper err=%v", err)
	}
	unknown := append(input[:len(input)-1], []byte(`,"unknown":true}`)...)
	if _, err := VerifyCapabilityAttestation(context.Background(), unknown, authority, now); Code(err) != InvalidInput {
		t.Fatalf("unknown err=%v", err)
	}
	duplicate := []byte(strings.Replace(string(input), `"schema_version":`, `"schema_version":"duplicate","schema_version":`, 1))
	if _, err := VerifyCapabilityAttestation(context.Background(), duplicate, authority, now); Code(err) != InvalidInput {
		t.Fatalf("duplicate err=%v", err)
	}
}

func TestTransportIdentityContracts(t *testing.T) {
	now, authority, _, _ := testAttestation(t)
	if err := ValidateTransportIdentity(authority.Transport, now); err != nil {
		t.Fatalf("remote identity: %v", err)
	}
	local := TransportIdentity{Kind: "local_socket_authenticated", IdentityDigest: digest("local"), ObservedAt: now,
		SocketPath: "/run/coh/worker.sock", SocketMode: 0660, SocketOwnerUID: 1000, SocketOwnerGID: 1000,
		PeerUID: 1000, PeerGID: 1000, PeerPID: 42, PeerAuthenticated: true, PlatformPeerAuth: true}
	if err := ValidateTransportIdentity(local, now); err != nil {
		t.Fatalf("local identity: %v", err)
	}
	local.SocketMode = 0666
	if err := ValidateTransportIdentity(local, now); Reason(err) != "local_peer_identity_invalid" {
		t.Fatalf("permissive local socket err=%v", err)
	}
	local.SocketMode = 0660
	local.PeerUID = 2000
	if err := ValidateTransportIdentity(local, now); Reason(err) != "local_peer_identity_invalid" {
		t.Fatalf("wrong local peer err=%v", err)
	}
}

func TestStrictRequestDecoders(t *testing.T) {
	now, authority, privateKey, attestation := testAttestation(t)
	request := EnrollmentRequest{SchemaVersion: EnrollmentSchemaVersion, ContractVersion: ContractVersion,
		RequestID: "018f47a6-4b2c-7a1e-8a12-123456789abe", IdempotencyKey: "enroll-1", Scope: authority.Scope,
		WorkerID: testWorkerID, EnrollmentNonce: authority.EnrollmentNonce,
		SignedAttestation: signAttestation(t, attestation, authority, privateKey)}
	encoded, _ := json.Marshal(request)
	if _, err := DecodeEnrollmentRequest(encoded); err != nil {
		t.Fatalf("decode enrollment: %v", err)
	}
	unknown := append(encoded[:len(encoded)-1], []byte(`,"secret":"no"}`)...)
	if _, err := DecodeEnrollmentRequest(unknown); Code(err) != InvalidInput {
		t.Fatalf("unknown field err=%v", err)
	}
	_ = now
}

func TestDispatchRevocationAndDecisionContracts(t *testing.T) {
	resources := ResourceCapacity{WallTimeMilliseconds: 1000, CPUMilliseconds: 500, MemoryBytes: 1 << 20,
		OutputBytes: 1024, EphemeralStorageBytes: 4096, ProcessCount: 1, OpenFileCount: 8}
	scope := LeaseScope{OrganizationID: testOrganizationID, TenantID: testTenantID,
		CaseID: "018f47a6-4b2c-7a1e-8a12-123456789abe", ActorID: "018f47a6-4b2c-7a1e-8a12-123456789abf",
		TaskID: "018f47a6-4b2c-7a1e-8a12-123456789ac0", ActionDigest: digest("action"),
		TargetDigests: []string{digest("target")}, ToolName: "tool", ToolVersion: "v1", ToolDigest: digest("tool"),
		ToolRegistryDigest: digest("registry"), Operation: "run", RequiredTier: "T1", IsolationClass: "remote_isolated",
		Resources: resources, NetworkMode: "none", ResourcePolicyDigest: digest("resources"), NetworkPolicyDigest: digest("network")}
	dispatch := DispatchRequest{SchemaVersion: DispatchSchemaVersion, ContractVersion: ContractVersion,
		LeaseID: "018f47a6-4b2c-7a1e-8a12-123456789ac1", Scope: scope, WorkerID: testWorkerID}
	encoded, _ := json.Marshal(dispatch)
	if _, err := DecodeDispatchRequest(encoded); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	revocation := RevocationRequest{SchemaVersion: RevocationSchemaVersion, ContractVersion: ContractVersion,
		RequestID: "018f47a6-4b2c-7a1e-8a12-123456789ac2", Kind: "lease",
		Scope: Scope{OrganizationID: testOrganizationID, TenantID: testTenantID}, LeaseID: dispatch.LeaseID, Reason: "operator_revoked"}
	encoded, _ = json.Marshal(revocation)
	if _, err := DecodeRevocationRequest(encoded); err != nil {
		t.Fatalf("revocation: %v", err)
	}
	first := FinalizeDecision(Decision{Event: "runner_dispatch", Outcome: "allowed", ReasonCode: "dispatch_authorized",
		OccurredAt: time.Date(2026, 8, 26, 4, 0, 0, 0, time.UTC)})
	changed := first
	changed.ReasonCode = "changed"
	changed = FinalizeDecision(changed)
	if first.SchemaVersion != DecisionSchemaVersion || first.DecisionDigest == changed.DecisionDigest {
		t.Fatalf("decision digests first=%s changed=%s", first.DecisionDigest, changed.DecisionDigest)
	}
}

func testAttestation(t *testing.T) (time.Time, AttestationAuthority, ed25519.PrivateKey, CapabilityAttestation) {
	t.Helper()
	now := time.Date(2026, 8, 26, 4, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("w", ed25519.SeedSize)))
	nonce := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 16)))
	transport := TransportIdentity{Kind: "remote_mtls", IdentityDigest: digest("transport"), ObservedAt: now,
		MutualTLS: true, CertificateFingerprint: digest("certificate"), CertificateRevision: 3,
		CertificateNotBefore: now.Add(-time.Hour), CertificateNotAfter: now.Add(time.Hour),
		URISAN: ExpectedWorkerURISAN(Scope{OrganizationID: testOrganizationID, TenantID: testTenantID}, testWorkerID)}
	authority := AttestationAuthority{Scope: Scope{OrganizationID: testOrganizationID, TenantID: testTenantID},
		WorkerID: testWorkerID, EnrollmentNonce: nonce, KeyID: "worker.attestation", KeyRevision: 5,
		Active: true, PublicKey: privateKey.Public().(ed25519.PublicKey), Transport: transport}
	attestation := CapabilityAttestation{SchemaVersion: AttestationSchemaVersion, ContractVersion: ContractVersion,
		Scope: authority.Scope, WorkerID: testWorkerID, EnrollmentNonce: nonce,
		TransportIdentityDigest: transport.IdentityDigest, CertificateFingerprint: transport.CertificateFingerprint,
		CertificateRevision: transport.CertificateRevision, PlatformOS: "linux", PlatformArchitecture: "amd64",
		ExecutorDigest: digest("executor"), RuntimeDigest: digest("runtime"), ToolRegistryDigest: digest("registry"),
		IsolationClasses: []string{"oci_sandbox", "remote_isolated"}, MaximumActionTier: "T3",
		Resources: ResourceCapacity{WallTimeMilliseconds: 60_000, CPUMilliseconds: 30_000, MemoryBytes: 1 << 30,
			OutputBytes: 1 << 20, EphemeralStorageBytes: 1 << 30, ProcessCount: 32, OpenFileCount: 256},
		NetworkModes: []string{"brokered_egress", "none"}, IssuedAt: now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(4 * time.Minute).Format(time.RFC3339Nano)}
	return now, authority, privateKey, attestation
}

func signAttestation(t *testing.T, attestation CapabilityAttestation, authority AttestationAuthority, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	encoded, _ := json.Marshal(attestation)
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(canonical)
	envelope := SignedCapabilityAttestation{SchemaVersion: EnvelopeSchemaVersion, ContractVersion: ContractVersion,
		Attestation: attestation, AttestationDigest: "sha256:" + hex.EncodeToString(sum[:]), AttestationKeyID: authority.KeyID,
		AttestationKeyRevision: authority.KeyRevision, SignatureAlgorithm: SignatureAlgorithm,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, append([]byte(SignatureDomain), canonical...)))}
	result, _ := json.Marshal(envelope)
	return result
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
