// Package evidencesigning implements the narrow Ed25519 evidence-manifest
// signing and verification adapters. Key storage and trust decisions remain in
// the injected resolver.
package evidencesigning

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

const signatureDomain = "COH-EVIDENCE-MANIFEST-SIGNATURE-V1\x00"

type SigningKey struct {
	KeyID       string
	KeyRevision uint64
	PrivateKey  []byte
}

type VerificationKey struct {
	KeyID               string
	KeyRevision         uint64
	PublicKey           []byte
	TrustSnapshotDigest string
	RevocationDigest    string
	ValidFrom           time.Time
	ValidUntil          time.Time
	Revoked             bool
}

type KeyResolver interface {
	ResolveSigningKey(context.Context, string, uint64, string) (SigningKey, error)
	ResolveVerificationKey(context.Context, string, uint64, string, string, time.Time) (VerificationKey, error)
}

type Adapter struct{ resolver KeyResolver }

func New(resolver KeyResolver) (*Adapter, error) {
	if resolver == nil {
		return nil, errors.New("evidence signing key resolver is required")
	}
	return &Adapter{resolver: resolver}, nil
}

func (adapter *Adapter) SignManifest(ctx context.Context,
	request evidencelifecycle.SignRequest) (evidencelifecycle.DetachedSignature, error) {
	if ctx == nil || request.KeyID == "" || request.KeyRevision == 0 || request.ManifestDigest == "" ||
		request.DecisionDigest == "" || len(request.CanonicalBytes) == 0 || len(request.CanonicalBytes) > 16<<20 {
		return evidencelifecycle.DetachedSignature{}, errors.New("evidence signing request is invalid")
	}
	key, err := adapter.resolver.ResolveSigningKey(ctx, request.KeyID, request.KeyRevision, request.DecisionDigest)
	if err != nil {
		return evidencelifecycle.DetachedSignature{}, errors.New("evidence signing key is unavailable")
	}
	defer clear(key.PrivateKey)
	if key.KeyID != request.KeyID || key.KeyRevision != request.KeyRevision || len(key.PrivateKey) != ed25519.PrivateKeySize {
		return evidencelifecycle.DetachedSignature{}, errors.New("evidence signing key is invalid")
	}
	message := signatureMessage(request.CanonicalBytes)
	value := evidencelifecycle.DetachedSignature{SchemaVersion: evidencelifecycle.DetachedSignatureSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion, Algorithm: evidencelifecycle.SigningAlgorithm,
		KeyID: key.KeyID, KeyRevision: key.KeyRevision, ManifestDigest: request.ManifestDigest,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(key.PrivateKey), message))}
	if evidencelifecycle.ValidateDetachedSignature(value) != nil {
		return evidencelifecycle.DetachedSignature{}, errors.New("evidence signature is invalid")
	}
	return value, nil
}

func (adapter *Adapter) VerifyDetachedSignature(ctx context.Context,
	request evidencelifecycle.VerifySignatureRequest) error {
	if ctx == nil || request.ManifestDigest == "" || len(request.CanonicalBytes) == 0 ||
		len(request.CanonicalBytes) > 16<<20 || request.Signature.ManifestDigest != request.ManifestDigest ||
		evidencelifecycle.ValidateDetachedSignature(request.Signature) != nil || request.TrustSnapshotDigest == "" ||
		request.RevocationDigest == "" || request.At.IsZero() {
		return errors.New("evidence signature verification request is invalid")
	}
	key, err := adapter.resolver.ResolveVerificationKey(ctx, request.Signature.KeyID,
		request.Signature.KeyRevision, request.TrustSnapshotDigest, request.RevocationDigest, request.At)
	if err != nil {
		return errors.New("evidence verification key is unavailable")
	}
	if key.KeyID != request.Signature.KeyID || key.KeyRevision != request.Signature.KeyRevision ||
		key.TrustSnapshotDigest != request.TrustSnapshotDigest || key.RevocationDigest != request.RevocationDigest ||
		len(key.PublicKey) != ed25519.PublicKeySize || key.Revoked || request.At.Before(key.ValidFrom) ||
		!request.At.Before(key.ValidUntil) {
		return errors.New("evidence verification key is invalid")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(request.Signature.Signature)
	if err != nil || len(encoded) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key.PublicKey),
		signatureMessage(request.CanonicalBytes), encoded) {
		return errors.New("evidence signature verification failed")
	}
	return nil
}

func signatureMessage(canonical []byte) []byte {
	message := make([]byte, len(signatureDomain)+len(canonical))
	copy(message, signatureDomain)
	copy(message[len(signatureDomain):], canonical)
	return message
}

var _ evidencelifecycle.Signer = (*Adapter)(nil)
var _ evidencelifecycle.SignatureVerifier = (*Adapter)(nil)
