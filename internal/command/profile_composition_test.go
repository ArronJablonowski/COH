package command

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/capabilityseam"
	"github.com/ArronJablonowski/COH/internal/domain/profilecomposition"
)

var compositionTestTime = time.Date(2026, 8, 28, 0, 1, 0, 0, time.UTC)

type compositionClock struct{ now time.Time }

func (clock compositionClock) Now() time.Time { return clock.now }

func TestProfileCompositionClosesCapabilityGraphDeterministically(t *testing.T) {
	request := profilecomposition.Request{ProfileID: "018f0000-0000-7000-8000-000000000900", Revision: 1,
		Target: profilecomposition.ExactTarget{DeploymentKind: "native_workstation", ConnectivityMode: "connected",
			Platform: "darwin_arm64", Surface: "web"}}
	layer := commandTestLayer("sha256:" + strings.Repeat("a", 64))
	draft, err := profilecomposition.Prepare(context.Background(), request,
		[]profilecomposition.VerifiedLayer{verifyCommandTestLayer(t, layer)})
	if err != nil {
		t.Fatal(err)
	}
	bundle := commandCapabilityBundle(t, draft.ProfileBindingDigest())
	layer.Contribution.CapabilityBundles[0].Digest = bundle.Digest()
	candidate, err := profilecomposition.Prepare(context.Background(), request,
		[]profilecomposition.VerifiedLayer{verifyCommandTestLayer(t, layer)})
	if err != nil {
		t.Fatal(err)
	}
	if candidate.ProfileBindingDigest() != draft.ProfileBindingDigest() {
		t.Fatal("capability artifact created a profile-binding digest cycle")
	}
	prepared, err := PrepareProfileCapabilities(context.Background(), candidate, []ProfileCapabilityArtifact{{
		Reference: layer.Contribution.CapabilityBundles[0], Bundle: bundle,
	}})
	if err != nil {
		t.Fatal(err)
	}
	authority := commandQualificationAuthority(prepared, bundle.Value())
	resolved, graph, err := prepared.Resolve(context.Background(), compositionClock{compositionTestTime}, authority)
	if err != nil {
		t.Fatal(err)
	}
	value := resolved.Value()
	if value.ProfileBindingDigest != candidate.ProfileBindingDigest() || value.CapabilityGraphDigest != graph.Digest() ||
		value.CompositionDigest != resolved.Digest() || value.CompositionDigest == value.ProfileBindingDigest {
		t.Fatalf("resolved=%+v graph=%s", value, graph.Digest())
	}
	replay, replayGraph, err := prepared.Resolve(context.Background(), compositionClock{compositionTestTime}, authority)
	if err != nil || replay.Digest() != resolved.Digest() || replayGraph.Digest() != graph.Digest() ||
		!slices.Equal(replay.CanonicalBytes(), resolved.CanonicalBytes()) {
		t.Fatalf("replay=%s graph=%s err=%v", replay.Digest(), replayGraph.Digest(), err)
	}
}

func TestProfileCompositionRejectsMissingCapabilityArtifact(t *testing.T) {
	request := profilecomposition.Request{ProfileID: "018f0000-0000-7000-8000-000000000900", Revision: 1,
		Target: profilecomposition.ExactTarget{DeploymentKind: "native_workstation", ConnectivityMode: "connected",
			Platform: "darwin_arm64", Surface: "web"}}
	candidate, err := profilecomposition.Prepare(context.Background(), request,
		[]profilecomposition.VerifiedLayer{verifyCommandTestLayer(t, commandTestLayer("sha256:"+strings.Repeat("a", 64)))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareProfileCapabilities(context.Background(), candidate, nil); profilecomposition.Code(err) != profilecomposition.Denied || profilecomposition.Reason(err) != "capability_artifacts_incomplete" {
		t.Fatalf("err=%v", err)
	}
}

func commandTestLayer(capabilityDigest string) profilecomposition.Layer {
	return profilecomposition.Layer{SchemaVersion: profilecomposition.LayerSchemaVersion,
		ContractVersion: profilecomposition.ContractVersion, LayerID: "018f0000-0000-7000-8000-000000000100",
		Name: "baseline.native-workstation", Kind: "baseline", Revision: 1,
		Target: profilecomposition.Target{DeploymentKinds: []string{"native_workstation"}, ConnectivityModes: []string{"connected"},
			Platforms: []string{"darwin_arm64"}, Surfaces: []string{"web"}}, Parents: []profilecomposition.Parent{},
		Contribution: profilecomposition.Contribution{
			DeploymentProfile:  profilecomposition.ArtifactRef{ID: "deployment.native-workstation-connected", Revision: 1, Digest: "sha256:" + strings.Repeat("1", 64)},
			CapabilityBundles:  []profilecomposition.ArtifactRef{{ID: "capabilities.core", Revision: 1, Digest: capabilityDigest}},
			PolicyBundles:      []profilecomposition.ArtifactRef{{ID: "policy.core", Revision: 1, Digest: "sha256:" + strings.Repeat("3", 64)}},
			EndpointReferences: []string{"provider.primary"}, Permissions: []string{"evidence.read", "model.infer", "tool.intent.submit"},
			Limits: profilecomposition.Limits{MaxConcurrency: 8, MaxContextBytes: 1048576, MaxDurationMS: 300000,
				MaxEvidenceBytes: 16777216, MaxModelTokens: 131072, MaxToolCalls: 64},
			Features: profilecomposition.Features{ExternalConnectivity: true, ModelInference: true, Retrieval: true, ToolDispatch: true}},
		IssuedAt: "2026-08-28T00:00:00Z", NotBefore: "2026-08-28T00:00:00Z", ExpiresAt: "2027-08-28T00:00:00Z"}
}

func verifyCommandTestLayer(t *testing.T, layer profilecomposition.Layer) profilecomposition.VerifiedLayer {
	t.Helper()
	_, digest, err := profilecomposition.CanonicalLayer(context.Background(), layer)
	if err != nil {
		t.Fatal(err)
	}
	message, err := profilecomposition.SignatureMessage(digest)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make([]profilecomposition.Signature, 0, 2)
	for _, spec := range []struct{ role, signer, key, seed string }{
		{"publisher", "018f0000-0000-7000-8000-000000000001", "profile.publisher", "CYB-183 publisher"},
		{"reviewer", "018f0000-0000-7000-8000-000000000002", "profile.reviewer", "CYB-183 reviewer"},
	} {
		seed := sha256.Sum256([]byte(spec.seed))
		privateKey := ed25519.NewKeyFromSeed(seed[:])
		signatures = append(signatures, profilecomposition.Signature{Role: spec.role, SignerID: spec.signer,
			KeyID: spec.key, KeyRevision: 1, Algorithm: profilecomposition.SignatureAlgorithm,
			SignedAt: "2026-08-28T00:00:00Z", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))})
	}
	encoded, _ := json.Marshal(profilecomposition.Envelope{SchemaVersion: profilecomposition.EnvelopeSchemaVersion,
		ContractVersion: profilecomposition.ContractVersion, Layer: layer, LayerDigest: digest, Signatures: signatures})
	verified, err := profilecomposition.Verify(context.Background(), encoded, commandTrustSnapshot(), compositionClock{compositionTestTime})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func commandTrustSnapshot() profilecomposition.TrustSnapshot {
	return profilecomposition.TrustSnapshot{ScopeOrganizationID: "018f0000-0000-7000-8000-000000000010",
		Environment: "native_workstation", CreatedAt: compositionTestTime.Add(-time.Minute),
		ExpiresAt: compositionTestTime.Add(4 * time.Minute), TrustRevision: 7,
		Records: []profilecomposition.SigningAuthority{
			commandSigningAuthority("publisher", "018f0000-0000-7000-8000-000000000001", "profile.publisher", "CYB-183 publisher"),
			commandSigningAuthority("reviewer", "018f0000-0000-7000-8000-000000000002", "profile.reviewer", "CYB-183 reviewer"),
		}}
}

func commandSigningAuthority(role, signer, key, seedText string) profilecomposition.SigningAuthority {
	seed := sha256.Sum256([]byte(seedText))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return profilecomposition.SigningAuthority{Role: role, SignerID: signer, KeyID: key, KeyRevision: 1,
		TrustRevision: 7, RevocationRevision: 9, ValidFrom: compositionTestTime.Add(-24 * time.Hour),
		ValidUntil: compositionTestTime.Add(24 * time.Hour), Active: true, PublicKey: privateKey.Public().(ed25519.PublicKey)}
}

func commandCapabilityBundle(t *testing.T, profileDigest string) capabilityseam.ValidatedBundle {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve fixture")
	}
	input, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "contracts", "capability-seam", "v1", "fixtures", "bundle.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle capabilityseam.Bundle
	if err := json.Unmarshal(input, &bundle); err != nil {
		t.Fatal(err)
	}
	bundle.BundleID = "capabilities.core"
	bundle.ProfileDigest = profileDigest
	for index := range bundle.Providers {
		bundle.Providers[index].Qualification.ProfileDigest = profileDigest
	}
	encoded, _ := json.Marshal(bundle)
	validated, err := capabilityseam.DecodeBundle(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func commandQualificationAuthority(prepared PreparedProfileCapabilities,
	bundle capabilityseam.Bundle) capabilityseam.QualificationAuthoritySnapshot {
	records := make([]capabilityseam.QualificationAuthorityRecord, len(bundle.Providers))
	for index, provider := range bundle.Providers {
		q := provider.Qualification
		records[index] = capabilityseam.QualificationAuthorityRecord{RecordID: q.RecordID, RecordDigest: q.RecordDigest,
			ProviderID: provider.ProviderID, ProviderVersion: provider.ProviderVersion,
			ProviderArtifactDigest: provider.ArtifactDigest, Capability: provider.Capability,
			ProfileDigest: bundle.ProfileDigest, IssuedAt: q.IssuedAt, ExpiresAt: q.ExpiresAt,
			RegistryRevision: 11, AuthorityRevision: q.AuthorityRevision, Active: true}
	}
	return capabilityseam.QualificationAuthoritySnapshot{BundleDigest: prepared.BundleDigest(), CompositionRevision: 1,
		ProfileDigest: bundle.ProfileDigest, Revision: 11, ObservedAt: compositionTestTime.Add(-time.Minute),
		ValidUntil: compositionTestTime.Add(4 * time.Minute), Records: records}
}
