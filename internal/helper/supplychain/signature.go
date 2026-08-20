package supplychain

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"slices"
)

var releaseRequirements = []string{"SEC-033", "SEC-034", "NFR-025", "EVAL-029"}

const releaseIssue = "COH-E02-04 / CYB-37"

func SignFile(ctx context.Context, input, name string, privatePEM []byte, role string) (Signature, error) {
	if err := ctx.Err(); err != nil {
		return Signature{}, contextError(err, "signature")
	}
	if role != "release" && role != "ci-fixture" {
		return Signature{}, errorf(CodeInvalidInput, "role", "unsupported signing role", nil)
	}
	privateKey, publicKey, err := parsePrivateKey(privatePEM)
	if err != nil {
		return Signature{}, err
	}
	subject, _, err := artifactFor(input, name)
	if err != nil {
		return Signature{}, err
	}
	keyID := publicKeyID(publicKey)
	signature := Signature{
		SchemaVersion: SignatureSchema, Algorithm: "ed25519", KeyID: keyID, Role: role,
		Issue: releaseIssue, Requirements: slices.Clone(releaseRequirements), Subject: subject,
	}
	payload, err := signaturePayload(signature)
	if err != nil {
		return Signature{}, err
	}
	signature.Value = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return signature, nil
}

// VerifyPrivateKeyAuthority confirms that privatePEM belongs to the selected
// policy authority without exposing key material to callers or diagnostics.
func VerifyPrivateKeyAuthority(privatePEM []byte, trusted TrustedKey) error {
	_, publicKey, err := parsePrivateKey(privatePEM)
	if err != nil {
		return err
	}
	trustedPublic, err := parsePublicKey(trusted.PublicPEM)
	if err != nil {
		return err
	}
	if trusted.Role != "release" && trusted.Role != "ci-fixture" ||
		publicKeyID(publicKey) != trusted.KeyID || !publicKey.Equal(trustedPublic) {
		return errorf(CodeDenied, "signing_key", "private key is not authorized for the selected role", nil)
	}
	return nil
}

func VerifyFile(ctx context.Context, input, name string, encoded []byte, trusted TrustedKey) error {
	if err := ctx.Err(); err != nil {
		return contextError(err, "signature")
	}
	var signature Signature
	if err := decodeStrict(encoded, &signature); err != nil {
		return errorf(CodeInvalidInput, "signature", "invalid signature document", err)
	}
	if signature.SchemaVersion != SignatureSchema || signature.Algorithm != "ed25519" ||
		signature.Issue != releaseIssue || !slices.Equal(signature.Requirements, releaseRequirements) ||
		signature.Role != trusted.Role || signature.KeyID != trusted.KeyID {
		return errorf(CodeDenied, "signature", "signature authority or contract differs", nil)
	}
	publicKey, err := parsePublicKey(trusted.PublicPEM)
	if err != nil {
		return err
	}
	if publicKeyID(publicKey) != trusted.KeyID {
		return errorf(CodeDenied, "trusted_key", "trusted key identifier differs", nil)
	}
	actual, _, err := artifactFor(input, name)
	if err != nil {
		return err
	}
	if actual != signature.Subject || filepath.Base(signature.Subject.Path) != signature.Subject.Path {
		return errorf(CodeDenied, "signature.subject", "signed subject differs from input", nil)
	}
	value, err := base64.StdEncoding.Strict().DecodeString(signature.Value)
	if err != nil || len(value) != ed25519.SignatureSize {
		return errorf(CodeInvalidInput, "signature", "signature value is invalid", err)
	}
	payload, err := signaturePayload(signature)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, value) {
		return errorf(CodeDenied, "signature", "signature verification failed", nil)
	}
	return nil
}

func EncodeSignature(signature Signature) ([]byte, error) {
	encoded, err := json.MarshalIndent(signature, "", "  ")
	if err != nil {
		return nil, errorf(CodeToolFailure, "signature", "cannot encode signature", err)
	}
	return append(encoded, '\n'), nil
}

func signaturePayload(signature Signature) ([]byte, error) {
	unsigned := signature
	unsigned.Value = ""
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return nil, errorf(CodeToolFailure, "signature", "cannot canonicalize signature subject", err)
	}
	return append([]byte("COH-RELEASE-SIGNATURE-V1\x00"), encoded...), nil
}

func parsePrivateKey(encoded []byte) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "PRIVATE KEY" {
		return nil, nil, errorf(CodeInvalidInput, "private_key", "expected one PKCS#8 private key", nil)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, errorf(CodeInvalidInput, "private_key", "cannot parse private key", err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, errorf(CodeDenied, "private_key", "only Ed25519 keys are accepted", nil)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return privateKey, publicKey, nil
}

func parsePublicKey(encoded []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		return nil, errorf(CodeInvalidInput, "public_key", "expected one PKIX public key", nil)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errorf(CodeInvalidInput, "public_key", "cannot parse public key", err)
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, errorf(CodeDenied, "public_key", "only Ed25519 keys are accepted", nil)
	}
	return publicKey, nil
}

func publicKeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(digest[:])
}
