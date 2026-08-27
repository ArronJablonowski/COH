package evidencesigning

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func TestAdapterSignsVerifiesAndClearsOwnedPrivateKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 27, 5, 0, 0, 0, time.UTC)
	resolver := &signingResolver{private: append([]byte(nil), private...), public: public, now: now}
	adapter, err := New(resolver)
	if err != nil {
		t.Fatal(err)
	}
	canonical := []byte(`{"manifest":"canonical"}`)
	signed, err := adapter.SignManifest(t.Context(), evidencelifecycle.SignRequest{
		ManifestDigest: signingDigest("manifest"), CanonicalBytes: canonical, KeyID: "evidence.primary",
		KeyRevision: 3, DecisionDigest: signingDigest("decision")})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range resolver.private {
		if value != 0 {
			t.Fatal("owned private key copy was not cleared")
		}
	}
	request := evidencelifecycle.VerifySignatureRequest{ManifestDigest: signed.ManifestDigest,
		CanonicalBytes: canonical, Signature: signed, TrustSnapshotDigest: signingDigest("trust"),
		RevocationDigest: signingDigest("revocation"), At: now}
	if err = adapter.VerifyDetachedSignature(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	request.CanonicalBytes = []byte(`{"manifest":"tampered"}`)
	if err = adapter.VerifyDetachedSignature(t.Context(), request); err == nil {
		t.Fatal("tampered canonical manifest verified")
	}
}

func TestAdapterRejectsRevokedAndDriftedAuthority(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 8, 27, 5, 0, 0, 0, time.UTC)
	resolver := &signingResolver{private: append([]byte(nil), private...), public: public, now: now, revoked: true}
	adapter, _ := New(resolver)
	canonical := []byte(`{"manifest":"canonical"}`)
	signed, err := adapter.SignManifest(t.Context(), evidencelifecycle.SignRequest{
		ManifestDigest: signingDigest("manifest"), CanonicalBytes: canonical, KeyID: "evidence.primary",
		KeyRevision: 3, DecisionDigest: signingDigest("decision")})
	if err != nil {
		t.Fatal(err)
	}
	if err = adapter.VerifyDetachedSignature(t.Context(), evidencelifecycle.VerifySignatureRequest{
		ManifestDigest: signed.ManifestDigest, CanonicalBytes: canonical, Signature: signed,
		TrustSnapshotDigest: signingDigest("trust"), RevocationDigest: signingDigest("revocation"), At: now}); err == nil {
		t.Fatal("revoked key verified")
	}
}

type signingResolver struct {
	private []byte
	public  []byte
	now     time.Time
	revoked bool
}

func (resolver *signingResolver) ResolveSigningKey(context.Context, string, uint64, string) (SigningKey, error) {
	return SigningKey{KeyID: "evidence.primary", KeyRevision: 3, PrivateKey: resolver.private}, nil
}

func (resolver *signingResolver) ResolveVerificationKey(context.Context, string, uint64, string, string,
	time.Time) (VerificationKey, error) {
	return VerificationKey{KeyID: "evidence.primary", KeyRevision: 3, PublicKey: resolver.public,
		TrustSnapshotDigest: signingDigest("trust"), RevocationDigest: signingDigest("revocation"),
		ValidFrom: resolver.now.Add(-time.Hour), ValidUntil: resolver.now.Add(time.Hour), Revoked: resolver.revoked}, nil
}

func signingDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
