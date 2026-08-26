package workeridentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

func TestFromVerifiedTLS(t *testing.T) {
	now := time.Date(2026, 8, 26, 4, 0, 0, 0, time.UTC)
	authority := MTLSAuthority{Scope: workercontract.Scope{
		OrganizationID: "018f47a6-4b2c-7a1e-8a12-123456789abc",
		TenantID:       "018f47a6-4b2c-7a1e-8a12-123456789abd"}, WorkerID: "worker-01", CertificateRevision: 3, ObservedAt: now}
	state := verifiedState(t, authority, now)
	identity, err := FromVerifiedTLS(state, authority)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if !identity.MutualTLS || identity.URISAN != workercontract.ExpectedWorkerURISAN(authority.Scope, authority.WorkerID) ||
		identity.CertificateFingerprint == "" || identity.IdentityDigest == "" {
		t.Fatalf("identity=%#v", identity)
	}
}

func TestTLSStateDenials(t *testing.T) {
	now := time.Date(2026, 8, 26, 4, 0, 0, 0, time.UTC)
	authority := MTLSAuthority{Scope: workercontract.Scope{
		OrganizationID: "018f47a6-4b2c-7a1e-8a12-123456789abc",
		TenantID:       "018f47a6-4b2c-7a1e-8a12-123456789abd"}, WorkerID: "worker-01", CertificateRevision: 3, ObservedAt: now}
	tests := []struct {
		name   string
		mutate func(*tls.ConnectionState, *MTLSAuthority)
		reason string
	}{
		{"no verified chain", func(state *tls.ConnectionState, _ *MTLSAuthority) { state.VerifiedChains = nil }, "mtls_peer_unverified"},
		{"tls 1.2", func(state *tls.ConnectionState, _ *MTLSAuthority) { state.Version = tls.VersionTLS12 }, "mtls_peer_unverified"},
		{"not complete", func(state *tls.ConnectionState, _ *MTLSAuthority) { state.HandshakeComplete = false }, "mtls_peer_unverified"},
		{"wrong worker", func(_ *tls.ConnectionState, auth *MTLSAuthority) { auth.WorkerID = "worker-02" }, "worker_uri_san_mismatch"},
		{"expired", func(_ *tls.ConnectionState, auth *MTLSAuthority) { auth.ObservedAt = now.Add(2 * time.Hour) }, "mtls_certificate_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state, changed := verifiedState(t, authority, now), authority
			test.mutate(&state, &changed)
			if _, err := FromVerifiedTLS(state, changed); workercontract.Reason(err) != test.reason {
				t.Fatalf("reason=%q err=%v", workercontract.Reason(err), err)
			}
		})
	}
}

func verifiedState(t *testing.T, authority MTLSAuthority, now time.Time) tls.ConnectionState {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityURI, err := url.Parse(workercontract.ExpectedWorkerURISAN(authority.Scope, authority.WorkerID))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: authority.WorkerID},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), URIs: []*url.URL{identityURI},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true,
		PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}
}
