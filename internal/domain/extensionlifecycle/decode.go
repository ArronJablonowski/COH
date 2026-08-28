package extensionlifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type ValidatedEnvelope struct {
	bytes          []byte
	manifestBytes  []byte
	manifestDigest string
}

func (value ValidatedEnvelope) CanonicalBytes() []byte { return append([]byte(nil), value.bytes...) }
func (value ValidatedEnvelope) CanonicalManifestBytes() []byte {
	return append([]byte(nil), value.manifestBytes...)
}
func (value ValidatedEnvelope) ManifestDigest() string { return value.manifestDigest }
func (value ValidatedEnvelope) Value() Envelope {
	var result Envelope
	_ = json.Unmarshal(value.bytes, &result)
	return result
}

type ValidatedIntent struct {
	bytes  []byte
	digest string
}

func (value ValidatedIntent) CanonicalBytes() []byte { return append([]byte(nil), value.bytes...) }
func (value ValidatedIntent) Digest() string         { return value.digest }
func (value ValidatedIntent) Value() ActivationIntent {
	var result ActivationIntent
	_ = json.Unmarshal(value.bytes, &result)
	return result
}

func DecodeEnvelope(ctx context.Context, input []byte) (ValidatedEnvelope, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedEnvelope{}, err
	}
	canonical, err := decodeCanonical(input, &Envelope{})
	if err != nil {
		return ValidatedEnvelope{}, err
	}
	var envelope Envelope
	_ = json.Unmarshal(canonical, &envelope)
	if err := validateEnvelope(envelope); err != nil {
		return ValidatedEnvelope{}, err
	}
	manifestBytes, digest, err := CanonicalManifest(envelope.Manifest)
	if err != nil {
		return ValidatedEnvelope{}, err
	}
	if digest != envelope.ManifestDigest {
		return ValidatedEnvelope{}, newError(Denied, "manifest_digest_mismatch")
	}
	if err := contextError(ctx); err != nil {
		return ValidatedEnvelope{}, err
	}
	return ValidatedEnvelope{bytes: append([]byte(nil), canonical...), manifestBytes: manifestBytes, manifestDigest: digest}, nil
}

func DecodeIntent(ctx context.Context, input []byte) (ValidatedIntent, error) {
	if err := contextError(ctx); err != nil {
		return ValidatedIntent{}, err
	}
	canonical, err := decodeCanonical(input, &ActivationIntent{})
	if err != nil {
		return ValidatedIntent{}, err
	}
	var intent ActivationIntent
	_ = json.Unmarshal(canonical, &intent)
	if err := validateIntent(intent); err != nil {
		return ValidatedIntent{}, err
	}
	digest, err := calculateIntentDigest(intent)
	if err != nil {
		return ValidatedIntent{}, err
	}
	if digest != intent.IntentDigest {
		return ValidatedIntent{}, newError(Denied, "intent_digest_mismatch")
	}
	if err := contextError(ctx); err != nil {
		return ValidatedIntent{}, err
	}
	return ValidatedIntent{bytes: append([]byte(nil), canonical...), digest: digest}, nil
}

func CanonicalManifest(manifest Manifest) ([]byte, string, error) {
	if manifest.SchemaVersion != ManifestSchemaVersion || manifest.ContractVersion != ContractVersion {
		return nil, "", newError(Unsupported, "unsupported_contract")
	}
	if err := validateManifest(manifest); err != nil {
		return nil, "", err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, "", newError(InvalidInput, "manifest_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, "", newError(InvalidInput, "manifest_encoding")
	}
	return canonical, digestBytes(manifestDigestDomain, canonical), nil
}

func SealIntent(intent ActivationIntent) (ActivationIntent, error) {
	intent.IntentDigest = ""
	intent.AdministratorSignature = Signature{}
	digest, err := calculateIntentDigest(intent)
	if err != nil {
		return ActivationIntent{}, err
	}
	intent.IntentDigest = digest
	intent.AdministratorSignature = Signature{ActorID: intent.ActorID, KeyID: "placeholder", KeyRevision: 1,
		ApprovalRevision: 1, Algorithm: SignatureAlgorithm, Value: string(bytes.Repeat([]byte{'A'}, 86))}
	if err := validateIntent(intent); err != nil {
		return ActivationIntent{}, err
	}
	intent.AdministratorSignature = Signature{}
	return intent, nil
}

func calculateIntentDigest(intent ActivationIntent) (string, error) {
	encoded, err := json.Marshal(intent)
	if err != nil {
		return "", newError(InvalidInput, "intent_encoding")
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		return "", newError(InvalidInput, "intent_encoding")
	}
	delete(object, "intent_digest")
	delete(object, "administrator_signature")
	encoded, err = json.Marshal(object)
	if err != nil {
		return "", newError(InvalidInput, "intent_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newError(InvalidInput, "intent_encoding")
	}
	return digestBytes(intentDigestDomain, canonical), nil
}

func ScopeDigest(scope ExactScope) (string, error) {
	if !validScope(scope) {
		return "", newError(InvalidInput, "scope")
	}
	return canonicalDigest(scopeDigestDomain, scope)
}
func PermissionsDigest(permissions []string) (string, error) {
	if !validTokenSet(permissions, 128) {
		return "", newError(InvalidInput, "permissions")
	}
	return canonicalDigest(permissionsDigestDomain, permissions)
}
func canonicalDigest(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", newError(InvalidInput, "canonical_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newError(InvalidInput, "canonical_encoding")
	}
	return digestBytes(domain, canonical), nil
}

func decodeCanonical(input []byte, target any) ([]byte, error) {
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return nil, newError(InvalidInput, "document_size")
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return nil, newError(InvalidInput, "document_decoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return nil, newError(InvalidInput, "document_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, newError(InvalidInput, "document_decoding")
	}
	reencoded, err := json.Marshal(target)
	if err != nil {
		return nil, newError(InvalidInput, "document_encoding")
	}
	complete, err := domaincontract.Canonicalize(reencoded)
	if err != nil || !bytes.Equal(canonical, complete) {
		return nil, newError(InvalidInput, "document_shape")
	}
	return canonical, nil
}

func digestBytes(domain string, canonical []byte) string {
	message := append([]byte(domain), canonical...)
	sum := sha256.Sum256(message)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_missing")
	}
	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return newError(Timeout, "deadline_exceeded")
		}
		return newError(Canceled, "context_canceled")
	default:
		return nil
	}
}
