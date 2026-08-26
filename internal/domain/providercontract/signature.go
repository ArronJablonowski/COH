package providercontract

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	SignedQualificationSchemaVersion = "coh.signed-provider-qualification/v1"
	SignatureAlgorithm               = "ed25519"
	signedQualificationDomain        = "COH-SIGNED-PROVIDER-QUALIFICATION-V1\x00"
)

type SignedQualification struct {
	SchemaVersion             string              `json:"schema_version"`
	ContractVersion           string              `json:"contract_version"`
	Qualification             QualificationRecord `json:"qualification"`
	QualificationDigest       string              `json:"qualification_digest"`
	QualifierIdentityDigest   string              `json:"qualifier_identity_digest"`
	QualifierKeyID            string              `json:"qualifier_key_id"`
	QualifierKeyRevision      uint64              `json:"qualifier_key_revision"`
	QualifierApprovalRevision uint64              `json:"qualifier_approval_revision"`
	SignatureAlgorithm        string              `json:"signature_algorithm"`
	Signature                 string              `json:"signature"`
}

type QualifierAuthority struct {
	IdentityDigest   string
	KeyID            string
	KeyRevision      uint64
	ApprovalRevision uint64
	Active           bool
	Approved         bool
	PublicKey        ed25519.PublicKey
}

type VerifiedQualification struct {
	qualification    ValidatedQualification
	envelopeBytes    []byte
	envelopeDigest   string
	keyID            string
	keyRevision      uint64
	approvalRevision uint64
}

func (verified VerifiedQualification) Qualification() ValidatedQualification {
	return ValidatedQualification{validatedDocument[QualificationRecord]{
		digest: verified.qualification.digest,
		bytes:  verified.qualification.CanonicalBytes(),
	}}
}
func (verified VerifiedQualification) CanonicalEnvelopeBytes() []byte {
	return append([]byte(nil), verified.envelopeBytes...)
}
func (verified VerifiedQualification) EnvelopeDigest() string   { return verified.envelopeDigest }
func (verified VerifiedQualification) KeyID() string            { return verified.keyID }
func (verified VerifiedQualification) KeyRevision() uint64      { return verified.keyRevision }
func (verified VerifiedQualification) ApprovalRevision() uint64 { return verified.approvalRevision }

func VerifyQualification(ctx context.Context, input []byte, authority QualifierAuthority) (VerifiedQualification, error) {
	if err := contextError(ctx); err != nil {
		return VerifiedQualification{}, err
	}
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return VerifiedQualification{}, NewError(InvalidInput, "qualification_envelope_size")
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return VerifiedQualification{}, NewError(InvalidInput, "qualification_envelope_decoding")
	}
	if err := validateSignedQualificationShape(canonical); err != nil {
		return VerifiedQualification{}, err
	}
	var envelope SignedQualification
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return VerifiedQualification{}, NewError(InvalidInput, "qualification_envelope_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return VerifiedQualification{}, NewError(InvalidInput, "qualification_envelope_decoding")
	}
	if envelope.SchemaVersion != SignedQualificationSchemaVersion || envelope.ContractVersion != ContractVersion ||
		envelope.SignatureAlgorithm != SignatureAlgorithm {
		return VerifiedQualification{}, NewError(Unsupported, "unsupported_qualification_envelope")
	}
	qualificationBytes, err := json.Marshal(envelope.Qualification)
	if err != nil {
		return VerifiedQualification{}, NewError(InvalidInput, "qualification_envelope_decoding")
	}
	qualification, err := DecodeQualification(ctx, qualificationBytes)
	if err != nil {
		return VerifiedQualification{}, err
	}
	if envelope.QualificationDigest != qualification.Digest() ||
		envelope.QualifierIdentityDigest != envelope.Qualification.QualifierIdentityDigest {
		return VerifiedQualification{}, NewError(Denied, "qualification_digest_mismatch")
	}
	if !authority.Active || !authority.Approved || !digestPattern.MatchString(authority.IdentityDigest) ||
		authority.IdentityDigest != envelope.QualifierIdentityDigest || authority.KeyID != envelope.QualifierKeyID ||
		authority.KeyRevision != envelope.QualifierKeyRevision || authority.ApprovalRevision != envelope.QualifierApprovalRevision ||
		!tokenPattern.MatchString(authority.KeyID) || authority.KeyRevision == 0 || authority.ApprovalRevision == 0 ||
		len(authority.PublicKey) != ed25519.PublicKeySize {
		return VerifiedQualification{}, NewError(Denied, "qualifier_authority")
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(authority.PublicKey, signatureMessage(qualification.CanonicalBytes(), envelope.QualifierIdentityDigest,
			envelope.QualifierKeyID, envelope.QualifierKeyRevision, envelope.QualifierApprovalRevision), signature) {
		return VerifiedQualification{}, NewError(Denied, "qualification_signature")
	}
	if err := contextError(ctx); err != nil {
		return VerifiedQualification{}, err
	}
	sum := sha256.Sum256(append([]byte(signedQualificationDomain), canonical...))
	return VerifiedQualification{qualification: qualification, envelopeBytes: append([]byte(nil), canonical...),
		envelopeDigest: "sha256:" + hex.EncodeToString(sum[:]), keyID: authority.KeyID,
		keyRevision: authority.KeyRevision, approvalRevision: authority.ApprovalRevision}, nil
}

func signatureMessage(qualification []byte, identityDigest, keyID string, keyRevision, approvalRevision uint64) []byte {
	message := make([]byte, 0, len(signedQualificationDomain)+len(qualification)+len(identityDigest)+len(keyID)+48)
	message = append(message, signedQualificationDomain...)
	message = append(message, qualification...)
	message = append(message, 0)
	message = append(message, identityDigest...)
	message = append(message, 0)
	message = append(message, keyID...)
	message = append(message, 0)
	message = strconv.AppendUint(message, keyRevision, 10)
	message = append(message, 0)
	return strconv.AppendUint(message, approvalRevision, 10)
}

func validateSignedQualificationShape(input []byte) error {
	root, err := exactObject(input, []string{"schema_version", "contract_version", "qualification", "qualification_digest",
		"qualifier_identity_digest", "qualifier_key_id", "qualifier_key_revision", "qualifier_approval_revision",
		"signature_algorithm", "signature"})
	if err != nil || validateQualificationMap(root["qualification"]) != nil {
		return NewError(InvalidInput, "qualification_envelope_decoding")
	}
	return nil
}

func validateQualificationMap(value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return NewError(InvalidInput, "qualification_envelope_decoding")
	}
	return validateQualificationShape(encoded)
}
