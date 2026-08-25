package actionmanifest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type denialCorpus struct {
	Cases []denialCase `json:"cases"`
}

type denialCase struct {
	Name      string          `json:"name"`
	Operation string          `json:"operation"`
	Path      string          `json:"path"`
	Value     json.RawMessage `json:"value"`
	Reason    string          `json:"reason"`
}

func TestCanonicalManifestFixture(t *testing.T) {
	input := manifestFixture(t)
	validated, err := Decode(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(validated.CanonicalBytes(), input) {
		t.Fatalf("fixture is not canonical:\n%s", validated.CanonicalBytes())
	}
	if !strings.HasPrefix(validated.Digest, "sha256:") || len(validated.Digest) != 71 {
		t.Fatalf("digest = %q", validated.Digest)
	}
	reordered := []byte(" \n" + strings.Replace(string(input), `{"action_owner_actor_id"`, `{"schema_version":"coh.action-manifest/v1","action_owner_actor_id"`, 1))
	reordered = bytes.Replace(reordered, []byte(`,"schema_version":"coh.action-manifest/v1"`), nil, 1)
	again, err := Decode(context.Background(), reordered)
	if err != nil || again.Digest != validated.Digest || !bytes.Equal(again.CanonicalBytes(), input) {
		t.Fatalf("reordered digest = %q, err = %v", again.Digest, err)
	}
	copyOfBytes := validated.CanonicalBytes()
	copyOfBytes[0] = '['
	if validated.CanonicalBytes()[0] != '{' {
		t.Fatal("caller mutated owned canonical bytes")
	}
}

func TestFrozenDenialCorpus(t *testing.T) {
	var corpus denialCorpus
	decodeFixture(t, "denial-corpus.json", &corpus)
	if len(corpus.Cases) != 24 {
		t.Fatalf("denials = %d", len(corpus.Cases))
	}
	seen := make(map[string]bool)
	for _, test := range corpus.Cases {
		t.Run(test.Name, func(t *testing.T) {
			if seen[test.Name] {
				t.Fatalf("duplicate denial name %q", test.Name)
			}
			seen[test.Name] = true
			mutated := mutateManifest(t, manifestFixture(t), test)
			_, err := Decode(context.Background(), mutated)
			if err == nil || Reason(err) != test.Reason {
				t.Fatalf("code = %s, reason = %s, want %s, err = %v", Code(err), Reason(err), test.Reason, err)
			}
		})
	}
}

func TestStrictRepresentationFailures(t *testing.T) {
	fixture := manifestFixture(t)
	for _, test := range []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"duplicate", bytes.Replace(fixture, []byte(`{"action_owner_actor_id"`), []byte(`{"action_owner_actor_id":"0198d6c4-2222-7222-8222-222222222222","action_owner_actor_id"`), 1)},
		{"trailing", append(append([]byte(nil), fixture...), []byte(` {}`)...)},
		{"float", bytes.Replace(fixture, []byte(`"policy_revision":7`), []byte(`"policy_revision":7.0`), 1)},
		{"missing-nullable", bytes.Replace(fixture, []byte(`,"roe_digest":null`), nil, 1)},
		{"oversize", bytes.Repeat([]byte{'x'}, MaximumInputBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Decode(context.Background(), test.input); Code(err) != InvalidInput {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestSignatureEnvelopeAndBoundMutation(t *testing.T) {
	validated, err := Decode(context.Background(), manifestFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := deterministicKey(t)
	authority := SignerAuthority{ActorID: validated.Value().RequestorActorID, KeyID: "requestor.primary",
		KeyRevision: 4, Active: true, PublicKey: publicKey}
	envelope := signedEnvelope(t, validated, authority, privateKey)
	fixtureEnvelope := signedFixture(t)
	if !bytes.Equal(envelope, fixtureEnvelope) {
		t.Fatalf("signed fixture drift:\n%s", envelope)
	}
	verified, err := Verify(context.Background(), envelope, authority)
	if err != nil || verified.ManifestDigest != validated.Digest || !bytes.Equal(verified.CanonicalManifestBytes(), validated.CanonicalBytes()) {
		t.Fatalf("verified = %+v, err = %v", verified, err)
	}
	manifestCopy := verified.Manifest()
	manifestCopy.TargetDigests[0] = digest("9")
	if verified.Manifest().TargetDigests[0] == digest("9") {
		t.Fatal("caller mutated verified manifest")
	}

	var changed Envelope
	if err := json.Unmarshal(envelope, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Manifest.ArgumentsDigest = digest("8")
	changedBytes, err := json.Marshal(changed.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	changedValidated, err := Decode(context.Background(), changedBytes)
	if err != nil {
		t.Fatal(err)
	}
	changed.ManifestDigest = changedValidated.Digest
	tampered, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Verify(context.Background(), tampered, authority); Code(err) != Denied || Reason(err) != "signature_invalid" {
		t.Fatalf("tampered err = %v", err)
	}
}

func TestSignerAuthorityFailsClosed(t *testing.T) {
	validated, err := Decode(context.Background(), manifestFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := deterministicKey(t)
	authority := SignerAuthority{ActorID: validated.Value().RequestorActorID, KeyID: "requestor.primary",
		KeyRevision: 4, Active: true, PublicKey: publicKey}
	envelope := signedEnvelope(t, validated, authority, privateKey)
	for _, test := range []struct {
		name   string
		mutate func(*SignerAuthority)
	}{
		{"inactive", func(value *SignerAuthority) { value.Active = false }},
		{"actor", func(value *SignerAuthority) { value.ActorID = uuid("9") }},
		{"key-id", func(value *SignerAuthority) { value.KeyID = "requestor.rotated" }},
		{"revision", func(value *SignerAuthority) { value.KeyRevision++ }},
		{"public-key", func(value *SignerAuthority) { value.PublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := authority
			test.mutate(&changed)
			_, err := Verify(context.Background(), envelope, changed)
			if Code(err) != Denied {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestSignatureEnvelopeFailsClosed(t *testing.T) {
	validated, err := Decode(context.Background(), manifestFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := deterministicKey(t)
	authority := SignerAuthority{ActorID: validated.Value().RequestorActorID, KeyID: "requestor.primary",
		KeyRevision: 4, Active: true, PublicKey: publicKey}
	base := signedEnvelope(t, validated, authority, privateKey)
	for _, test := range []struct {
		name   string
		mutate func(*Envelope)
		code   ErrorCode
		reason string
	}{
		{"schema", func(value *Envelope) { value.SchemaVersion = "coh.signed-action/v2" }, Denied, "unsupported_signature_contract"},
		{"algorithm", func(value *Envelope) { value.SignatureAlgorithm = "none" }, Denied, "unsupported_signature_contract"},
		{"manifest-digest", func(value *Envelope) { value.ManifestDigest = digest("0") }, Denied, "manifest_digest_mismatch"},
		{"signer", func(value *Envelope) { value.SignerActorID = uuid("9") }, Denied, "signature_authority"},
		{"key-id", func(value *Envelope) { value.KeyID = "requestor.other" }, Denied, "signature_authority"},
		{"key-revision", func(value *Envelope) { value.SignerKeyRevision++ }, Denied, "signature_authority"},
		{"signature", func(value *Envelope) { value.Signature = strings.Repeat("A", 86) }, Denied, "signature_invalid"},
		{"requestor", func(value *Envelope) {
			value.Manifest.RequestorActorID = uuid("9")
			manifestBytes, marshalErr := json.Marshal(value.Manifest)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			changed, decodeErr := Decode(context.Background(), manifestBytes)
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			value.ManifestDigest = changed.Digest
		}, Denied, "signature_authority"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var envelope Envelope
			if err := json.Unmarshal(base, &envelope); err != nil {
				t.Fatal(err)
			}
			test.mutate(&envelope)
			encoded, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Verify(context.Background(), encoded, authority)
			if Code(err) != test.code || Reason(err) != test.reason {
				t.Fatalf("code = %s, reason = %s, err = %v", Code(err), Reason(err), err)
			}
		})
	}

	unknown := bytes.Replace(base, []byte(`{"contract_version"`), []byte(`{"admin":true,"contract_version"`), 1)
	if _, err := Verify(context.Background(), unknown, authority); Code(err) != InvalidInput || Reason(err) != "envelope_decoding" {
		t.Fatalf("unknown-field err = %v", err)
	}
	duplicate := bytes.Replace(base, []byte(`{"contract_version"`), []byte(`{"contract_version":"1.0.0","contract_version"`), 1)
	if _, err := Verify(context.Background(), duplicate, authority); Code(err) != InvalidInput || Reason(err) != "manifest_decoding" {
		t.Fatalf("duplicate-field err = %v", err)
	}
}

func TestCancellationTimeoutAndRecovery(t *testing.T) {
	input := manifestFixture(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Decode(canceled, input); Code(err) != Canceled || Reason(err) != "request_canceled" {
		t.Fatalf("canceled err = %v", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := Decode(expired, input); Code(err) != Timeout || Reason(err) != "request_timeout" {
		t.Fatalf("timeout err = %v", err)
	}
	if _, err := Decode(context.Background(), input); err != nil {
		t.Fatalf("fresh-context recovery: %v", err)
	}
}

func signedEnvelope(t *testing.T, validated ValidatedManifest, authority SignerAuthority, privateKey ed25519.PrivateKey) []byte {
	t.Helper()
	message := append([]byte(SignatureDomain), validated.CanonicalBytes()...)
	envelope := Envelope{SchemaVersion: EnvelopeSchemaVersion, ContractVersion: ContractVersion,
		Manifest: cloneManifest(validated.Value()), ManifestDigest: validated.Digest, SignerActorID: authority.ActorID,
		SignerKeyRevision: authority.KeyRevision, KeyID: authority.KeyID, SignatureAlgorithm: "ed25519",
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func deterministicKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := sha256.Sum256([]byte("COH-CYB-52-INERT-TEST-KEY"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func mutateManifest(t *testing.T, input []byte, mutation denialCase) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.TrimPrefix(mutation.Path, "/"), "/")
	current := value
	for _, part := range parts[:len(parts)-1] {
		next, ok := current[part].(map[string]any)
		if !ok {
			t.Fatalf("path %q is not an object", mutation.Path)
		}
		current = next
	}
	key := parts[len(parts)-1]
	switch mutation.Operation {
	case "remove":
		delete(current, key)
	case "set":
		var decoded any
		if err := json.Unmarshal(mutation.Value, &decoded); err != nil {
			t.Fatal(err)
		}
		current[key] = decoded
	default:
		t.Fatalf("operation %q", mutation.Operation)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func manifestFixture(t *testing.T) []byte {
	t.Helper()
	input, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "action", "v1", "fixtures", "valid", "detection-publish.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(input)
}

func signedFixture(t *testing.T) []byte {
	t.Helper()
	input, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "action", "v1", "fixtures", "valid", "detection-publish.signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(input)
}

func decodeFixture(t *testing.T, name string, destination any) {
	t.Helper()
	input, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "action", "v1", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(input, destination); err != nil {
		t.Fatal(err)
	}
}

func digest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }

func uuid(fill string) string {
	return "0198d6c4-" + strings.Repeat(fill, 4) + "-7" + strings.Repeat(fill, 3) + "-8" + strings.Repeat(fill, 3) + "-" + strings.Repeat(fill, 12)
}
