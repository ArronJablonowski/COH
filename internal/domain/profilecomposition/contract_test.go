package profilecomposition

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var fixtureTime = time.Date(2026, 8, 28, 0, 1, 0, 0, time.UTC)

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }

func TestValidSignedLayerIsCanonicalImmutableAndVerified(t *testing.T) {
	input := readFixture(t, "layer.signed.valid.json")
	validated, err := Decode(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if validated.LayerDigest() != "sha256:33dcf281e69b68327019404a0b3fcd6bf4be7c4729ce4040db50faa66c2bd0b1" {
		t.Fatalf("digest=%s", validated.LayerDigest())
	}
	a := validated.CanonicalEnvelopeBytes()
	b := validated.CanonicalEnvelopeBytes()
	a[0] ^= 0xff
	if bytes.Equal(a, b) {
		t.Fatal("canonical envelope aliases internal storage")
	}
	value := validated.Value()
	value.Layer.Target.Surfaces[0] = "changed"
	if validated.Value().Layer.Target.Surfaces[0] != "api" {
		t.Fatal("value aliases internal storage")
	}
	verified, err := Verify(context.Background(), input, fixtureTrust(), fixedClock{fixtureTime})
	if err != nil {
		t.Fatal(err)
	}
	if verified.LayerDigest() != validated.LayerDigest() || verified.TrustRevision() != 7 ||
		verified.RevocationRevision() != 9 || verified.Layer().Name != "baseline.native-workstation" {
		t.Fatalf("unexpected verified layer: %+v", verified)
	}
	replayed, err := Decode(context.Background(), validated.CanonicalEnvelopeBytes())
	if err != nil || replayed.LayerDigest() != validated.LayerDigest() ||
		!bytes.Equal(replayed.CanonicalLayerBytes(), validated.CanonicalLayerBytes()) {
		t.Fatalf("canonical replay failed: %v", err)
	}
}

func TestTrustSnapshotCannotBeSerialized(t *testing.T) {
	snapshot := fixtureTrust()
	if _, err := json.Marshal(snapshot); err == nil {
		t.Fatal("trust snapshot serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &snapshot); err == nil {
		t.Fatal("trust snapshot accepted JSON")
	}
	revision := RevisionAuthority{}
	if _, err := json.Marshal(revision); err == nil {
		t.Fatal("revision authority serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &revision); err == nil {
		t.Fatal("revision authority accepted JSON")
	}
}

func TestTrustSnapshotEnvironmentMustCoverLayerDeployment(t *testing.T) {
	input := readFixture(t, "layer.signed.valid.json")
	snapshot := fixtureTrust()
	snapshot.Environment = "native_server"
	if _, err := Verify(context.Background(), input, snapshot, fixedClock{fixtureTime}); Code(err) != Denied || Reason(err) != "trust_environment_scope" {
		t.Fatalf("err=%v", err)
	}
}

func TestSignedLayerDenialCorpus(t *testing.T) {
	type denialCase struct {
		Name         string `json:"name"`
		Mutation     string `json:"mutation"`
		ExpectedCode string `json:"expected_code"`
		Reason       string `json:"reason"`
	}
	var corpus struct {
		SchemaVersion   string       `json:"schema_version"`
		ContractVersion string       `json:"contract_version"`
		Cases           []denialCase `json:"cases"`
	}
	if err := json.Unmarshal(readFixture(t, "denial-corpus.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.SchemaVersion != "coh.profile-composition-denial-corpus/v1" ||
		corpus.ContractVersion != ContractVersion || len(corpus.Cases) != 15 {
		t.Fatalf("bad corpus: %+v", corpus)
	}
	for _, test := range corpus.Cases {
		t.Run(test.Name, func(t *testing.T) {
			input, trust, ctx := mutatedCase(t, test.Mutation)
			_, err := Verify(ctx, input, trust, fixedClock{fixtureTime})
			if string(Code(err)) != test.ExpectedCode || Reason(err) != test.Reason {
				t.Fatalf("code=%s reason=%s err=%v", Code(err), Reason(err), err)
			}
		})
	}
}

func TestDecodeHonorsDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := Decode(ctx, readFixture(t, "layer.signed.valid.json")); Code(err) != Timeout {
		t.Fatalf("err=%v", err)
	}
}

func mutatedCase(t *testing.T, mutation string) ([]byte, TrustSnapshot, context.Context) {
	t.Helper()
	input := readFixture(t, "layer.signed.valid.json")
	trust := fixtureTrust()
	ctx := context.Background()
	if mutation == "duplicate-root-schema-version" {
		return bytes.Replace(input, []byte(`"schema_version": "coh.signed-profile-layer/v1"`),
			[]byte(`"schema_version": "coh.signed-profile-layer/v1", "schema_version": "coh.signed-profile-layer/v1"`), 1), trust, ctx
	}
	var value map[string]any
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	layer := value["layer"].(map[string]any)
	signatures := value["signatures"].([]any)
	switch mutation {
	case "add-root-member":
		value["unknown"] = true
	case "remove-layer-name":
		delete(layer, "name")
	case "change-contract-version":
		value["contract_version"] = "2.0.0"
	case "change-layer-name":
		layer["name"] = "baseline.changed"
	case "change-signature-byte":
		signatures[0].(map[string]any)["signature"] = "AI8f_yMFsvkRHNL9ZZMczrHCrnMeFpezvKSgto4NBHqNMWGC4sTnThDO267gMTkSsG69uIItLms_DSMvB-aDBA"
	case "remove-signatures":
		delete(value, "signatures")
	case "remove-reviewer":
		value["signatures"] = signatures[:1]
	case "remove-trust-record":
		trust.Records = trust.Records[:1]
	case "revoke-reviewer":
		trust.Records[1].Active = false
		trust.Records[1].Revoked = true
		trust.Records[1].RevocationRevision = 10
	case "expire-trust-snapshot":
		trust.CreatedAt = fixtureTime.Add(-10 * time.Minute)
		trust.ExpiresAt = fixtureTime.Add(-time.Minute)
	case "reverse-surfaces":
		layer["target"].(map[string]any)["surfaces"] = []any{"web", "test", "headless", "cli", "api"}
	case "duplicate-capability-ref":
		contribution := layer["contribution"].(map[string]any)
		refs := contribution["capability_bundles"].([]any)
		contribution["capability_bundles"] = append(refs, refs[0])
	case "add-secret-value":
		value["secret_value"] = "must-not-enter-contract"
	case "cancel-before-decode":
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		ctx = canceled
	default:
		t.Fatalf("unknown mutation %q", mutation)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, trust, ctx
}

func fixtureTrust() TrustSnapshot {
	return TrustSnapshot{
		ScopeOrganizationID: "018f0000-0000-7000-8000-000000000010",
		Environment:         "native_workstation", CreatedAt: fixtureTime.Add(-time.Minute),
		ExpiresAt: fixtureTime.Add(4 * time.Minute), TrustRevision: 7,
		Records: []SigningAuthority{
			fixtureAuthority("publisher", "018f0000-0000-7000-8000-000000000001", "profile.publisher", "CYB-183 publisher"),
			fixtureAuthority("reviewer", "018f0000-0000-7000-8000-000000000002", "profile.reviewer", "CYB-183 reviewer"),
		},
	}
}

func fixtureAuthority(role, signerID, keyID, seedLabel string) SigningAuthority {
	seed := sha256.Sum256([]byte(seedLabel))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return SigningAuthority{Role: role, SignerID: signerID, KeyID: keyID, KeyRevision: 1,
		TrustRevision: 7, RevocationRevision: 9, ValidFrom: fixtureTime.Add(-24 * time.Hour), ValidUntil: fixtureTime.Add(24 * time.Hour),
		Active: true, PublicKey: privateKey.Public().(ed25519.PublicKey)}
}

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve fixture path")
	}
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "contracts", "profile-composition", "v1", "fixtures", name)
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return input
}
