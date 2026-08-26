package remoteworker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func VerifyCapabilityAttestation(ctx context.Context, input []byte, authority AttestationAuthority, now time.Time) (VerifiedAttestation, error) {
	if err := contextError(ctx); err != nil {
		return VerifiedAttestation{}, err
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil || len(input) == 0 || len(input) > MaximumInputBytes {
		return VerifiedAttestation{}, NewError(InvalidInput, "attestation_decoding")
	}
	var envelope SignedCapabilityAttestation
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return VerifiedAttestation{}, NewError(InvalidInput, "attestation_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return VerifiedAttestation{}, NewError(InvalidInput, "attestation_decoding")
	}
	if envelope.SchemaVersion != EnvelopeSchemaVersion || envelope.ContractVersion != ContractVersion ||
		envelope.SignatureAlgorithm != SignatureAlgorithm {
		return VerifiedAttestation{}, NewError(Denied, "unsupported_signature_contract")
	}
	if err := ValidateAttestation(envelope.Attestation); err != nil {
		return VerifiedAttestation{}, err
	}
	if err := validateAttestationAuthority(envelope, authority, now); err != nil {
		return VerifiedAttestation{}, err
	}
	attestationBytes, err := json.Marshal(envelope.Attestation)
	if err != nil {
		return VerifiedAttestation{}, NewError(InvalidInput, "attestation_encoding")
	}
	canonicalAttestation, err := domaincontract.Canonicalize(attestationBytes)
	if err != nil {
		return VerifiedAttestation{}, NewError(InvalidInput, "attestation_encoding")
	}
	digestBytes := sha256.Sum256(canonicalAttestation)
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	if subtle.ConstantTimeCompare([]byte(digest), []byte(envelope.AttestationDigest)) != 1 {
		return VerifiedAttestation{}, NewError(Denied, "attestation_digest_mismatch")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return VerifiedAttestation{}, NewError(InvalidInput, "signature_value")
	}
	message := append([]byte(SignatureDomain), canonicalAttestation...)
	if !ed25519.Verify(authority.PublicKey, message, signature) {
		return VerifiedAttestation{}, NewError(Denied, "signature_invalid")
	}
	return VerifiedAttestation{Digest: digest, KeyID: envelope.AttestationKeyID,
		KeyRevision: envelope.AttestationKeyRevision, attestation: cloneAttestation(envelope.Attestation),
		canonicalBytes: append([]byte(nil), canonicalAttestation...), canonicalEnvelope: append([]byte(nil), canonical...)}, nil
}

func validateAttestationAuthority(envelope SignedCapabilityAttestation, authority AttestationAuthority, now time.Time) error {
	if err := ValidateScope(authority.Scope); err != nil || !authority.Active || !validToken(authority.WorkerID) ||
		!validNonce(authority.EnrollmentNonce) || !validToken(authority.KeyID) || authority.KeyRevision == 0 ||
		len(authority.PublicKey) != ed25519.PublicKeySize {
		return NewError(Denied, "attestation_authority_invalid")
	}
	if authority.Transport.Kind != "remote_mtls" {
		return NewError(Denied, "remote_mtls_required")
	}
	if err := ValidateTransportIdentity(authority.Transport, now); err != nil {
		return err
	}
	if authority.Transport.URISAN != ExpectedWorkerURISAN(authority.Scope, authority.WorkerID) {
		return NewError(Denied, "worker_uri_san_mismatch")
	}
	attestation := envelope.Attestation
	if envelope.AttestationKeyID != authority.KeyID || envelope.AttestationKeyRevision != authority.KeyRevision ||
		attestation.Scope != authority.Scope || attestation.WorkerID != authority.WorkerID ||
		attestation.EnrollmentNonce != authority.EnrollmentNonce ||
		attestation.TransportIdentityDigest != authority.Transport.IdentityDigest ||
		attestation.CertificateFingerprint != authority.Transport.CertificateFingerprint ||
		attestation.CertificateRevision != authority.Transport.CertificateRevision {
		return NewError(Denied, "attestation_authority_mismatch")
	}
	issued, _ := time.Parse(time.RFC3339Nano, attestation.IssuedAt)
	expires, _ := time.Parse(time.RFC3339Nano, attestation.ExpiresAt)
	if issued.After(now.Add(5*time.Second)) || !now.Before(expires) || now.Sub(issued) > MaximumAttestationAge {
		return NewError(Denied, "attestation_stale")
	}
	return nil
}

func cloneAttestation(value CapabilityAttestation) CapabilityAttestation {
	cloned := value
	cloned.IsolationClasses = append([]string(nil), value.IsolationClasses...)
	cloned.NetworkModes = append([]string(nil), value.NetworkModes...)
	return cloned
}
