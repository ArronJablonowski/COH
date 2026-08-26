package toolregistry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testManifestID  = "0198d6c4-1111-7111-8111-111111111111"
	testPublisherID = "0198d6c4-2222-7222-8222-222222222222"
	testReviewID    = "0198d6c4-3333-7333-8333-333333333333"
	testReviewerID  = "0198d6c4-4444-7444-8444-444444444444"
)

var registryTime = time.Date(2026, 8, 26, 2, 30, 0, 0, time.UTC)

func TestCanonicalSignedManifestAndOwnedCopies(t *testing.T) {
	manifest := testManifest()
	for _, field := range manifest.Operations[0].InputFields {
		if err := validateInputField(field); err != nil {
			t.Fatalf("fixture field %s: %+v: %v", field.Name, field, err)
		}
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	validated, err := Decode(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(validated.CanonicalBytes()) >= len(encoded) || !bytes.HasPrefix(validated.CanonicalBytes(), []byte(`{"artifact_digest"`)) {
		t.Fatalf("canonical bytes = %s", validated.CanonicalBytes())
	}
	signed, authority := signedManifest(t, manifest)
	verified, err := Verify(context.Background(), signed, authority)
	if err != nil || verified.ManifestDigest != validated.Digest {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	copyOfManifest := verified.Manifest()
	copyOfManifest.Operations[0].InputFields[0].Name = "changed"
	if verified.Manifest().Operations[0].InputFields[0].Name == "changed" {
		t.Fatal("caller mutated verified manifest")
	}
	copyOfBytes := verified.CanonicalEnvelopeBytes()
	copyOfBytes[0] = '['
	if verified.CanonicalEnvelopeBytes()[0] != '{' {
		t.Fatal("caller mutated verified envelope")
	}
}

func TestFrozenCanonicalFixtures(t *testing.T) {
	manifestBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "tool", "v1", "fixtures", "valid", "query-tool.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	validated, err := Decode(context.Background(), manifestBytes)
	if err != nil || !bytes.Equal(validated.CanonicalBytes(), bytes.TrimSpace(manifestBytes)) {
		t.Fatalf("manifest fixture is not canonical: %v", err)
	}
	signedBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "tool", "v1", "fixtures", "valid", "query-tool.signed.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, authority := signedManifest(t, testManifest())
	verified, err := Verify(context.Background(), signedBytes, authority)
	if err != nil || !bytes.Equal(verified.CanonicalEnvelopeBytes(), bytes.TrimSpace(signedBytes)) ||
		verified.ManifestDigest != validated.Digest {
		t.Fatalf("signed fixture drift: digest=%s err=%v", verified.ManifestDigest, err)
	}
	for _, name := range []string{"tool-manifest.schema.json", "signed-tool-manifest.schema.json"} {
		data, readErr := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "tool", "v1", name))
		var schema map[string]any
		if readErr != nil || json.Unmarshal(data, &schema) != nil || schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
			t.Fatalf("schema %s invalid: %v", name, readErr)
		}
	}
}

func TestFrozenDenialCorpus(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "tool", "v1", "fixtures", "denial-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaVersion   string `json:"schema_version"`
		ContractVersion string `json:"contract_version"`
		Cases           []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &corpus); err != nil || corpus.SchemaVersion != "coh.tool-registry-denials/v1" ||
		corpus.ContractVersion != ContractVersion || len(corpus.Cases) != 12 {
		t.Fatalf("corpus invalid: %+v err=%v", corpus, err)
	}
	seen := make(map[string]bool)
	for _, test := range corpus.Cases {
		if seen[test.Name] || !tokenPattern.MatchString(test.Reason) {
			t.Fatalf("invalid corpus case: %+v", test)
		}
		seen[test.Name] = true
	}
	for _, required := range []string{"unreviewed", "operation-above-tool-ceiling", "native-t3", "public-internet",
		"unknown-field-type", "expired-ordering", "publisher-revoked", "policy-ceiling-elevation"} {
		if !seen[required] {
			t.Fatalf("missing denial %s", required)
		}
	}
}

func TestStrictShapeSignatureAndPublisherAuthority(t *testing.T) {
	manifest := testManifest()
	signed, authority := signedManifest(t, manifest)
	missingBoolean := bytes.Replace(signed, []byte(`"metadata_allowed":false,`), nil, 1)
	if bytes.Equal(missingBoolean, signed) {
		t.Fatalf("metadata field missing from signed fixture: %s", signed)
	}
	if _, err := Verify(context.Background(), missingBoolean, authority); Code(err) != InvalidInput {
		t.Fatalf("missing boolean err=%v", err)
	}
	unknown := bytes.Replace(signed, []byte(`{"schema_version"`), []byte(`{"admin":true,"schema_version"`), 1)
	if _, err := Verify(context.Background(), unknown, authority); Reason(err) != "envelope_decoding" {
		t.Fatalf("unknown err=%v", err)
	}
	var envelope Envelope
	if err := json.Unmarshal(signed, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Manifest.Operations[0].ResourceLimits.MemoryBytes++
	tampered, _ := json.Marshal(envelope)
	if _, err := Verify(context.Background(), tampered, authority); Reason(err) != "manifest_digest_mismatch" {
		t.Fatalf("tamper err=%v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*PublisherAuthority)
	}{
		{"unapproved", func(value *PublisherAuthority) { value.Approved = false }},
		{"inactive", func(value *PublisherAuthority) { value.Active = false }},
		{"publisher", func(value *PublisherAuthority) { value.PublisherID = testReviewerID }},
		{"key", func(value *PublisherAuthority) { value.KeyID = "publisher.rotated" }},
		{"revision", func(value *PublisherAuthority) { value.KeyRevision++ }},
		{"public key", func(value *PublisherAuthority) { value.PublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := authority
			test.mutate(&changed)
			if _, err := Verify(context.Background(), signed, changed); Code(err) != Denied {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestManifestControlDenials(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Manifest)
		reason string
	}{
		{"unreviewed", func(value *Manifest) { value.ReviewDecision = "pending" }, "manifest_review"},
		{"unsorted reviewers", func(value *Manifest) { value.ReviewerActorIDs = []string{testReviewerID, testReviewID} }, "manifest_reviewers"},
		{"operation above tool ceiling", func(value *Manifest) { value.MaximumActionTier = "T1" }, "operation_tier"},
		{"baseline above operation ceiling", func(value *Manifest) { value.Operations[0].BaselineActionTier = "T3" }, "operation_tier"},
		{"native T3", func(value *Manifest) {
			value.MaximumActionTier, value.Operations[0].MaximumActionTier = "T3", "T3"
		}, "operation_controls"},
		{"consequential cancellation unsupported", func(value *Manifest) { value.Operations[0].CancellationMode = "unsupported" }, "operation_controls"},
		{"public internet", func(value *Manifest) { value.Operations[0].NetworkPolicy.PublicInternetAllowed = true }, "operation_sandbox"},
		{"metadata", func(value *Manifest) { value.Operations[0].NetworkPolicy.MetadataAllowed = true }, "operation_sandbox"},
		{"unbounded memory", func(value *Manifest) { value.Operations[0].ResourceLimits.MemoryBytes = 0 }, "operation_sandbox"},
		{"unknown field type", func(value *Manifest) { value.Operations[0].InputFields[0].Type = "json" }, "operation_inputs"},
		{"duplicate field", func(value *Manifest) {
			value.Operations[0].InputFields = append(value.Operations[0].InputFields, value.Operations[0].InputFields[0])
		}, "operation_inputs"},
		{"expired ordering", func(value *Manifest) { value.ValidUntil = value.ValidFrom }, "manifest_validity"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := testManifest()
			test.mutate(&manifest)
			if err := Validate(manifest); Reason(err) != test.reason {
				t.Fatalf("err=%v want=%s", err, test.reason)
			}
		})
	}
}

func TestT4ManifestRequiresDedicatedNonRetryingCooperativeControl(t *testing.T) {
	manifest := testManifest()
	manifest.MaximumActionTier = "T4"
	operation := &manifest.Operations[0]
	operation.BaselineActionTier, operation.MaximumActionTier = "T4", "T4"
	operation.IsolationClass, operation.CancellationMode, operation.RetryMode = "t4_dedicated", "cooperative", "never"
	if err := Validate(manifest); err != nil {
		t.Fatalf("valid T4 controls: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Operation)
		reason string
	}{
		{"ordinary remote", func(value *Operation) { value.IsolationClass = "remote_isolated" }, "operation_controls"},
		{"automatic retry", func(value *Operation) { value.RetryMode = "safe" }, "operation_controls"},
		{"broker-only cancellation", func(value *Operation) { value.CancellationMode = "broker_only" }, "operation_controls"},
		{"no target network", func(value *Operation) {
			value.NetworkPolicy = NetworkPolicy{Mode: "none", Protocols: []string{}, DNSMode: "none"}
		}, "operation_sandbox"},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneManifest(manifest)
			test.mutate(&changed.Operations[0])
			if err := Validate(changed); Reason(err) != test.reason {
				t.Fatalf("err=%v want=%s", err, test.reason)
			}
		})
	}
}

func testManifest() Manifest {
	minimum, maximum := int64(1), int64(3600)
	return Manifest{SchemaVersion: ManifestSchemaVersion, ContractVersion: ContractVersion,
		ManifestID: testManifestID, ToolName: "query.execute", ToolVersion: "1.2.3", ArtifactDigest: testDigest("a"),
		MaximumActionTier: "T2", PublisherID: testPublisherID, ReviewID: testReviewID, ReviewRevision: 2,
		ReviewDecision: "approved", ReviewerActorIDs: []string{testReviewerID}, ThreatModelDigest: testDigest("b"),
		ReviewedAt: registryTime.Add(-time.Hour).Format(timestampLayout), ValidFrom: registryTime.Add(-time.Minute).Format(timestampLayout),
		ValidUntil: registryTime.Add(time.Hour).Format(timestampLayout), Operations: []Operation{{Name: "execute",
			InputSchemaVersion: "coh.tool-input/v1", InputFields: []InputField{
				{Name: "query_digest", Type: "digest", Required: true, MaximumBytes: 71, Enum: []string{}},
				{Name: "timeout_seconds", Type: "integer", Required: false, Minimum: &minimum, Maximum: &maximum, Enum: []string{}},
			}, BaselineActionTier: "T1", MaximumActionTier: "T2", IsolationClass: "native_restricted",
			CredentialClasses: []string{"query_reader"}, ResourceLimits: ResourceLimits{WallTimeMilliseconds: 60_000,
				CPUMilliseconds: 30_000, MemoryBytes: 256 << 20, OutputBytes: 16 << 20,
				EphemeralStorageBytes: 64 << 20, ProcessCount: 4, OpenFileCount: 128},
			NetworkPolicy: NetworkPolicy{Mode: "target_only", Protocols: []string{"tcp"}, DNSMode: "broker_resolved",
				MaximumConnections: 8}, CancellationMode: "cooperative", RetryMode: "reconcile"}}}
}

func signedManifest(t *testing.T, manifest Manifest) ([]byte, PublisherAuthority) {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	validated, err := Decode(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed([]byte(strings.Repeat("t", ed25519.SeedSize)))
	authority := PublisherAuthority{PublisherID: manifest.PublisherID, KeyID: "publisher.primary", KeyRevision: 3,
		ApprovalRevision: 5, Active: true, Approved: true, PublicKey: private.Public().(ed25519.PublicKey)}
	message := append([]byte(SignatureDomain), validated.CanonicalBytes()...)
	envelope := Envelope{SchemaVersion: EnvelopeSchemaVersion, ContractVersion: ContractVersion,
		Manifest: validated.Value(), ManifestDigest: validated.Digest, PublisherID: manifest.PublisherID,
		PublisherKeyID: authority.KeyID, PublisherKeyRevision: authority.KeyRevision,
		SignatureAlgorithm: SignatureAlgorithm, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))}
	signed, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return signed, authority
}

func testDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

type testClock struct{ now time.Time }

func (clock *testClock) Now() time.Time { return clock.now }
