package toolregistry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
)

var envelopeFields = []string{"schema_version", "contract_version", "manifest", "manifest_digest", "publisher_id",
	"publisher_key_id", "publisher_key_revision", "signature_algorithm", "signature"}

func Verify(ctx context.Context, input []byte, authority PublisherAuthority) (VerifiedEnvelope, error) {
	if err := contextError(ctx); err != nil {
		return VerifiedEnvelope{}, err
	}
	canonicalEnvelope, err := canonicalize(input)
	if err != nil {
		return VerifiedEnvelope{}, err
	}
	envelopeObject, err := exactObject(canonicalEnvelope, envelopeFields)
	if err != nil {
		return VerifiedEnvelope{}, NewError(InvalidInput, "envelope_decoding")
	}
	if err := validateJSONShape(envelopeObject["manifest"]); err != nil {
		return VerifiedEnvelope{}, err
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(canonicalEnvelope))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return VerifiedEnvelope{}, NewError(InvalidInput, "envelope_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return VerifiedEnvelope{}, NewError(InvalidInput, "envelope_decoding")
	}
	if envelope.SchemaVersion != EnvelopeSchemaVersion || envelope.ContractVersion != ContractVersion ||
		envelope.SignatureAlgorithm != SignatureAlgorithm {
		return VerifiedEnvelope{}, NewError(Denied, "unsupported_signature_contract")
	}
	manifestJSON, err := json.Marshal(envelope.Manifest)
	if err != nil {
		return VerifiedEnvelope{}, NewError(InvalidInput, "manifest_decoding")
	}
	validated, err := Decode(ctx, manifestJSON)
	if err != nil {
		return VerifiedEnvelope{}, err
	}
	if subtle.ConstantTimeCompare([]byte(envelope.ManifestDigest), []byte(validated.Digest)) != 1 {
		return VerifiedEnvelope{}, NewError(Denied, "manifest_digest_mismatch")
	}
	if !validPublisherAuthority(authority) || envelope.PublisherID != validated.manifest.PublisherID ||
		envelope.PublisherID != authority.PublisherID || envelope.PublisherKeyID != authority.KeyID ||
		envelope.PublisherKeyRevision != authority.KeyRevision {
		return VerifiedEnvelope{}, NewError(Denied, "publisher_authority")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return VerifiedEnvelope{}, NewError(InvalidInput, "signature_value")
	}
	message := append([]byte(SignatureDomain), validated.bytes...)
	if !ed25519.Verify(authority.PublicKey, message, signature) {
		return VerifiedEnvelope{}, NewError(Denied, "signature_invalid")
	}
	if err := contextError(ctx); err != nil {
		return VerifiedEnvelope{}, err
	}
	return VerifiedEnvelope{ManifestDigest: validated.Digest, PublisherID: envelope.PublisherID,
		PublisherKeyID: envelope.PublisherKeyID, PublisherKeyRevision: envelope.PublisherKeyRevision,
		manifest: validated.Value(), manifestBytes: validated.CanonicalBytes(),
		envelopeBytes: append([]byte(nil), canonicalEnvelope...)}, nil
}

func validPublisherAuthority(authority PublisherAuthority) bool {
	return uuidPattern.MatchString(authority.PublisherID) && tokenPattern.MatchString(authority.KeyID) &&
		authority.KeyRevision > 0 && authority.ApprovalRevision > 0 && authority.Active && authority.Approved &&
		len(authority.PublicKey) == ed25519.PublicKeySize
}
