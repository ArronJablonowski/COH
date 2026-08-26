package providercontract

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignedQualificationVerificationReplayAndCollision(t *testing.T) {
	capability := decodeCapabilityFixture(t)
	qualification := decodeQualificationFixture(t)
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("q", 128)))
	if err != nil {
		t.Fatal(err)
	}
	authority := QualifierAuthority{IdentityDigest: qualification.Value().QualifierIdentityDigest,
		KeyID: "qualifier-2026", KeyRevision: 3, ApprovalRevision: 9, Active: true, Approved: true, PublicKey: publicKey}
	verified := verifyEnvelope(t, qualification, privateKey, authority)
	registry := NewQualificationRegistry()
	admission, err := registry.Admit(context.Background(), capability, verified, mustTime(t, "2026-08-26T06:00:00.000000000Z"))
	if err != nil || admission.Replayed || admission.QualifierKeyID != authority.KeyID {
		t.Fatalf("admission=%+v err=%v", admission, err)
	}
	replay, err := registry.Admit(context.Background(), capability, verified, mustTime(t, "2026-08-26T06:00:00.000000000Z"))
	if err != nil || !replay.Replayed || replay.EnvelopeDigest != admission.EnvelopeDigest {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	resolved, err := registry.Resolve(context.Background(), qualification.Value().QualificationID, capability,
		mustTime(t, "2026-08-26T06:00:00.000000000Z"))
	if err != nil || resolved.EnvelopeDigest() != verified.EnvelopeDigest() {
		t.Fatalf("resolve digest=%s err=%v", resolved.EnvelopeDigest(), err)
	}

	changed := qualification.Value()
	changed.SuiteDigest = digest("c")
	changedEncoded := marshal(t, changed)
	changedQualification, err := DecodeQualification(context.Background(), changedEncoded)
	if err != nil {
		t.Fatal(err)
	}
	changedVerified := verifyEnvelope(t, changedQualification, privateKey, authority)
	if _, err := registry.Admit(context.Background(), capability, changedVerified, mustTime(t, "2026-08-26T06:00:00.000000000Z")); Code(err) != Conflict || Reason(err) != "qualification_id_collision" {
		t.Fatalf("collision err=%v", err)
	}
}

func TestSignedQualificationDenials(t *testing.T) {
	qualification := decodeQualificationFixture(t)
	publicKey, privateKey, err := ed25519.GenerateKey(strings.NewReader(strings.Repeat("s", 128)))
	if err != nil {
		t.Fatal(err)
	}
	authority := QualifierAuthority{IdentityDigest: qualification.Value().QualifierIdentityDigest,
		KeyID: "qualifier-2026", KeyRevision: 3, ApprovalRevision: 9, Active: true, Approved: true, PublicKey: publicKey}
	envelope := signedEnvelope(t, qualification, privateKey, authority)

	tampered := envelope
	tampered.Signature = "A" + tampered.Signature[1:]
	if _, err := VerifyQualification(context.Background(), marshal(t, tampered), authority); Code(err) != Denied {
		t.Fatalf("signature tamper err=%v", err)
	}
	stale := authority
	stale.KeyRevision++
	if _, err := VerifyQualification(context.Background(), marshal(t, envelope), stale); Code(err) != Denied || Reason(err) != "qualifier_authority" {
		t.Fatalf("stale authority err=%v", err)
	}
	inactive := authority
	inactive.Active = false
	if _, err := VerifyQualification(context.Background(), marshal(t, envelope), inactive); Code(err) != Denied {
		t.Fatalf("inactive authority err=%v", err)
	}
	digestTamper := envelope
	digestTamper.QualificationDigest = digest("d")
	if _, err := VerifyQualification(context.Background(), marshal(t, digestTamper), authority); Code(err) != Denied || Reason(err) != "qualification_digest_mismatch" {
		t.Fatalf("digest tamper err=%v", err)
	}
}

func verifyEnvelope(t *testing.T, qualification ValidatedQualification, privateKey ed25519.PrivateKey,
	authority QualifierAuthority) VerifiedQualification {
	t.Helper()
	envelope := signedEnvelope(t, qualification, privateKey, authority)
	verified, err := VerifyQualification(context.Background(), marshal(t, envelope), authority)
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func signedEnvelope(t *testing.T, qualification ValidatedQualification, privateKey ed25519.PrivateKey,
	authority QualifierAuthority) SignedQualification {
	t.Helper()
	signature := ed25519.Sign(privateKey, signatureMessage(qualification.CanonicalBytes(), authority.IdentityDigest,
		authority.KeyID, authority.KeyRevision, authority.ApprovalRevision))
	return SignedQualification{SchemaVersion: SignedQualificationSchemaVersion, ContractVersion: ContractVersion,
		Qualification: qualification.Value(), QualificationDigest: qualification.Digest(),
		QualifierIdentityDigest: authority.IdentityDigest, QualifierKeyID: authority.KeyID,
		QualifierKeyRevision: authority.KeyRevision, QualifierApprovalRevision: authority.ApprovalRevision,
		SignatureAlgorithm: SignatureAlgorithm, Signature: base64.RawURLEncoding.EncodeToString(signature)}
}

func TestSignedQualificationJSONDoesNotExposePrivateKey(t *testing.T) {
	encoded, err := json.Marshal(SignedQualification{})
	if err != nil || strings.Contains(string(encoded), "private") {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
}
