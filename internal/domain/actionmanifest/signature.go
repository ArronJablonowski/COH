package actionmanifest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"io"
)

func Verify(ctx context.Context, input []byte, authority SignerAuthority) (VerifiedEnvelope, error) {
	if err := contextError(ctx); err != nil {
		return VerifiedEnvelope{}, err
	}
	canonicalEnvelope, err := canonicalize(input)
	if err != nil {
		return VerifiedEnvelope{}, err
	}
	var envelope Envelope
	decoder := json.NewDecoder(bytes.NewReader(canonicalEnvelope))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return VerifiedEnvelope{}, contractError(InvalidInput, "envelope_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return VerifiedEnvelope{}, contractError(InvalidInput, "envelope_decoding")
	}
	if envelope.SchemaVersion != EnvelopeSchemaVersion || envelope.ContractVersion != ContractVersion || envelope.SignatureAlgorithm != "ed25519" {
		return VerifiedEnvelope{}, contractError(Denied, "unsupported_signature_contract")
	}
	if !uuidPattern.MatchString(envelope.SignerActorID) || !tokenPattern.MatchString(envelope.KeyID) || envelope.SignerKeyRevision == 0 {
		return VerifiedEnvelope{}, contractError(InvalidInput, "signature_authority")
	}
	manifestJSON, err := json.Marshal(envelope.Manifest)
	if err != nil {
		return VerifiedEnvelope{}, contractError(InvalidInput, "manifest_decoding")
	}
	validated, err := Decode(ctx, manifestJSON)
	if err != nil {
		return VerifiedEnvelope{}, err
	}
	if subtle.ConstantTimeCompare([]byte(envelope.ManifestDigest), []byte(validated.Digest)) != 1 {
		return VerifiedEnvelope{}, contractError(Denied, "manifest_digest_mismatch")
	}
	if envelope.SignerActorID != validated.manifest.RequestorActorID || !authority.Active ||
		authority.ActorID != envelope.SignerActorID || authority.KeyID != envelope.KeyID ||
		authority.KeyRevision != envelope.SignerKeyRevision || len(authority.PublicKey) != ed25519.PublicKeySize {
		return VerifiedEnvelope{}, contractError(Denied, "signature_authority")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return VerifiedEnvelope{}, contractError(InvalidInput, "signature_value")
	}
	message := make([]byte, 0, len(SignatureDomain)+len(validated.bytes))
	message = append(message, SignatureDomain...)
	message = append(message, validated.bytes...)
	if !ed25519.Verify(authority.PublicKey, message, signature) {
		return VerifiedEnvelope{}, contractError(Denied, "signature_invalid")
	}
	if err := contextError(ctx); err != nil {
		return VerifiedEnvelope{}, err
	}
	return VerifiedEnvelope{manifest: cloneManifest(validated.manifest), ManifestDigest: validated.Digest,
		SignerActorID: envelope.SignerActorID, SignerKeyRevision: envelope.SignerKeyRevision, KeyID: envelope.KeyID,
		manifestBytes: validated.CanonicalBytes(), envelopeBytes: append([]byte(nil), canonicalEnvelope...)}, nil
}
