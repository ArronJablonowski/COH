// Package workeridentity derives remote-worker transport identity exclusively
// from an already verified TLS connection and broker-owned revision state.
package workeridentity

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

type MTLSAuthority struct {
	Scope               workercontract.Scope
	WorkerID            string
	CertificateRevision uint64
	ObservedAt          time.Time
}

func FromVerifiedTLS(state tls.ConnectionState, authority MTLSAuthority) (workercontract.TransportIdentity, error) {
	if err := workercontract.ValidateScope(authority.Scope); err != nil || authority.WorkerID == "" ||
		authority.CertificateRevision == 0 || authority.ObservedAt.IsZero() {
		return workercontract.TransportIdentity{}, workercontract.NewError(workercontract.InvalidInput, "mtls_authority_invalid")
	}
	if !state.HandshakeComplete || state.Version < tls.VersionTLS13 || len(state.PeerCertificates) == 0 ||
		len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return workercontract.TransportIdentity{}, workercontract.NewError(workercontract.Denied, "mtls_peer_unverified")
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || state.VerifiedChains[0][0] == nil || !bytes.Equal(leaf.Raw, state.VerifiedChains[0][0].Raw) ||
		authority.ObservedAt.Before(leaf.NotBefore.UTC()) || !authority.ObservedAt.Before(leaf.NotAfter.UTC()) {
		return workercontract.TransportIdentity{}, workercontract.NewError(workercontract.Denied, "mtls_certificate_invalid")
	}
	expectedURI := workercontract.ExpectedWorkerURISAN(authority.Scope, authority.WorkerID)
	if len(leaf.URIs) != 1 || leaf.URIs[0] == nil || leaf.URIs[0].String() != expectedURI {
		return workercontract.TransportIdentity{}, workercontract.NewError(workercontract.Denied, "worker_uri_san_mismatch")
	}
	fingerprintBytes := sha256.Sum256(leaf.Raw)
	fingerprint := "sha256:" + hex.EncodeToString(fingerprintBytes[:])
	binding, err := json.Marshal(struct {
		Scope                  workercontract.Scope `json:"scope"`
		WorkerID               string               `json:"worker_id"`
		CertificateFingerprint string               `json:"certificate_fingerprint"`
		CertificateRevision    uint64               `json:"certificate_revision"`
		URISAN                 string               `json:"uri_san"`
	}{authority.Scope, authority.WorkerID, fingerprint, authority.CertificateRevision, expectedURI})
	if err != nil {
		return workercontract.TransportIdentity{}, workercontract.NewError(workercontract.Unavailable, "mtls_identity_encoding")
	}
	identityBytes := sha256.Sum256(binding)
	identity := workercontract.TransportIdentity{Kind: "remote_mtls",
		IdentityDigest: "sha256:" + hex.EncodeToString(identityBytes[:]), ObservedAt: authority.ObservedAt.UTC(), MutualTLS: true,
		CertificateFingerprint: fingerprint, CertificateRevision: authority.CertificateRevision,
		CertificateNotBefore: leaf.NotBefore.UTC(), CertificateNotAfter: leaf.NotAfter.UTC(), URISAN: expectedURI}
	if err := workercontract.ValidateTransportIdentity(identity, authority.ObservedAt.UTC()); err != nil {
		return workercontract.TransportIdentity{}, err
	}
	return identity, nil
}
