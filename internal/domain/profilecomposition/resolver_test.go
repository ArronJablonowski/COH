package profilecomposition

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func TestPrepareDeterministicallyOrdersAndNarrowsLayers(t *testing.T) {
	baseline := verifiedTestLayer(t, baseLayer())
	overlayValue := overlayLayer(baseline)
	overlay := verifiedTestLayer(t, overlayValue)
	request := testRequest()
	left, err := Prepare(context.Background(), request, []VerifiedLayer{overlay, baseline})
	if err != nil {
		t.Fatal(err)
	}
	right, err := Prepare(context.Background(), request, []VerifiedLayer{baseline, overlay})
	if err != nil {
		t.Fatal(err)
	}
	if left.ProfileBindingDigest() != right.ProfileBindingDigest() || left.ProfileBindingDigest() == "" {
		t.Fatalf("binding left=%s right=%s", left.ProfileBindingDigest(), right.ProfileBindingDigest())
	}
	if got := left.state.bindings; len(got) != 2 || got[0].Kind != "baseline" || got[1].Kind != "overlay" {
		t.Fatalf("order=%+v", got)
	}
	if left.state.limits.MaxConcurrency != 2 || left.state.features.ToolDispatch ||
		!slices.Equal(left.state.permissions, []string{"evidence.read", "model.infer"}) {
		t.Fatalf("narrowed state=%+v", left.state)
	}
	copyRefs := left.CapabilityReferences()
	copyRefs[0].ID = "changed"
	if left.CapabilityReferences()[0].ID != "capabilities.core" {
		t.Fatal("candidate aliases references")
	}
}

func TestPrepareRejectsLayerCycleAndWidening(t *testing.T) {
	baseline := verifiedTestLayer(t, baseLayer())
	firstValue := overlayLayer(baseline)
	firstValue.LayerID = "018f0000-0000-7000-8000-000000000201"
	firstValue.Name = "overlay.first"
	secondValue := overlayLayer(baseline)
	secondValue.LayerID = "018f0000-0000-7000-8000-000000000202"
	secondValue.Name = "overlay.second"
	firstDigest := "sha256:" + repeatHex("a")
	secondDigest := "sha256:" + repeatHex("b")
	firstValue.Parents = append(firstValue.Parents, Parent{LayerID: secondValue.LayerID, Revision: 1, LayerDigest: secondDigest})
	secondValue.Parents = append(secondValue.Parents, Parent{LayerID: firstValue.LayerID, Revision: 1, LayerDigest: firstDigest})
	first := internalVerifiedLayer(t, firstValue, firstDigest)
	second := internalVerifiedLayer(t, secondValue, secondDigest)
	if _, err := Prepare(context.Background(), testRequest(), []VerifiedLayer{baseline, first, second}); Code(err) != Denied || Reason(err) != "layer_cycle" {
		t.Fatalf("cycle err=%v", err)
	}
	widened := overlayLayer(baseline)
	widened.Contribution.Permissions = append(widened.Contribution.Permissions, "tool.intent.submit", "unknown.permission")
	slices.Sort(widened.Contribution.Permissions)
	if _, err := Prepare(context.Background(), testRequest(), []VerifiedLayer{baseline, verifiedTestLayer(t, widened)}); Code(err) != Denied || Reason(err) != "permission_widening" {
		t.Fatalf("widen err=%v", err)
	}
}

func testRequest() Request {
	return Request{ProfileID: "018f0000-0000-7000-8000-000000000900", Revision: 1,
		Target: ExactTarget{DeploymentKind: "native_workstation", ConnectivityMode: "connected", Platform: "darwin_arm64", Surface: "web"}}
}

func baseLayer() Layer {
	return Layer{SchemaVersion: LayerSchemaVersion, ContractVersion: ContractVersion,
		LayerID: "018f0000-0000-7000-8000-000000000100", Name: "baseline.native-workstation", Kind: "baseline",
		Revision: 1, Precedence: 0, Target: Target{DeploymentKinds: []string{"native_workstation"},
			ConnectivityModes: []string{"connected"}, Platforms: []string{"darwin_arm64"}, Surfaces: []string{"web"}},
		Parents: []Parent{}, Contribution: Contribution{
			DeploymentProfile:  ArtifactRef{ID: "deployment.native-workstation-connected", Revision: 1, Digest: "sha256:" + repeatHex("1")},
			CapabilityBundles:  []ArtifactRef{{ID: "capabilities.core", Revision: 1, Digest: "sha256:" + repeatHex("2")}},
			PolicyBundles:      []ArtifactRef{{ID: "policy.core", Revision: 1, Digest: "sha256:" + repeatHex("3")}},
			EndpointReferences: []string{"provider.primary"}, Permissions: []string{"evidence.read", "model.infer", "tool.intent.submit"},
			Limits: Limits{MaxConcurrency: 8, MaxContextBytes: 1048576, MaxDurationMS: 300000,
				MaxEvidenceBytes: 16777216, MaxModelTokens: 131072, MaxToolCalls: 64},
			Features: Features{ExternalConnectivity: true, ModelInference: true, Retrieval: true, ToolDispatch: true}},
		IssuedAt: "2026-08-28T00:00:00Z", NotBefore: "2026-08-28T00:00:00Z", ExpiresAt: "2027-08-28T00:00:00Z"}
}

func overlayLayer(baseline VerifiedLayer) Layer {
	value := baseLayer()
	value.LayerID = "018f0000-0000-7000-8000-000000000200"
	value.Name = "overlay.restricted"
	value.Kind = "overlay"
	value.Precedence = 100
	value.Parents = []Parent{{LayerID: baseline.Layer().LayerID, Revision: baseline.Layer().Revision, LayerDigest: baseline.LayerDigest()}}
	value.Contribution.Permissions = []string{"evidence.read", "model.infer"}
	value.Contribution.Limits.MaxConcurrency = 2
	value.Contribution.Features.ToolDispatch = false
	return value
}

func verifiedTestLayer(t *testing.T, layer Layer) VerifiedLayer {
	t.Helper()
	encoded, err := json.Marshal(layer)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		t.Fatal(err)
	}
	digest := digestBytes(layerDigestDomain, canonical)
	raw, _ := hex.DecodeString(digest[len("sha256:"):])
	message := append([]byte(signatureDomain), raw...)
	signatures := make([]Signature, 0, 2)
	for _, spec := range []struct{ role, signer, key, seed string }{
		{"publisher", "018f0000-0000-7000-8000-000000000001", "profile.publisher", "CYB-183 publisher"},
		{"reviewer", "018f0000-0000-7000-8000-000000000002", "profile.reviewer", "CYB-183 reviewer"},
	} {
		seed := sha256.Sum256([]byte(spec.seed))
		privateKey := ed25519.NewKeyFromSeed(seed[:])
		signatures = append(signatures, Signature{Role: spec.role, SignerID: spec.signer, KeyID: spec.key, KeyRevision: 1,
			Algorithm: SignatureAlgorithm, SignedAt: "2026-08-28T00:00:00Z",
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))})
	}
	envelope, _ := json.Marshal(Envelope{SchemaVersion: EnvelopeSchemaVersion, ContractVersion: ContractVersion,
		Layer: layer, LayerDigest: digest, Signatures: signatures})
	verified, err := Verify(context.Background(), envelope, fixtureTrust(), fixedClock{fixtureTime})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

// internalVerifiedLayer constructs the otherwise unforgeable post-verification
// value needed to exercise the graph cycle branch. A real content-addressed
// mutual parent cycle is denied even earlier by digest verification.
func internalVerifiedLayer(t *testing.T, layer Layer, digest string) VerifiedLayer {
	t.Helper()
	envelope := Envelope{SchemaVersion: EnvelopeSchemaVersion, ContractVersion: ContractVersion, Layer: layer,
		LayerDigest: digest, Signatures: []Signature{{Role: "publisher"}, {Role: "reviewer"}}}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return VerifiedLayer{validated: ValidatedEnvelope{envelopeBytes: encoded, layerDigest: digest},
		trustRevision: 7, revocationRevision: 9}
}

func repeatHex(value string) string { return strings.Repeat(value, 64) }
