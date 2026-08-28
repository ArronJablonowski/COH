package command

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/capabilityseam"
	"github.com/ArronJablonowski/COH/internal/domain/profilecomposition"
)

func TestProfileCompositionDeploymentAndSurfaceParityMatrix(t *testing.T) {
	targets := []profilecomposition.ExactTarget{
		{DeploymentKind: "native_workstation", ConnectivityMode: "connected", Platform: "darwin_arm64", Surface: "web"},
		{DeploymentKind: "native_server", ConnectivityMode: "restricted_connected", Platform: "linux_amd64", Surface: "cli"},
		{DeploymentKind: "compose", ConnectivityMode: "air_gapped", Platform: "linux_arm64", Surface: "api"},
		{DeploymentKind: "native_workstation", ConnectivityMode: "air_gapped", Platform: "windows_amd64", Surface: "headless"},
		{DeploymentKind: "compose", ConnectivityMode: "connected", Platform: "linux_amd64", Surface: "test"},
	}
	var inspectionShape []string
	for _, target := range targets {
		name := target.DeploymentKind + "/" + target.ConnectivityMode + "/" + target.Platform + "/" + target.Surface
		t.Run(name, func(t *testing.T) {
			resolved, graph, inspection := resolveParityProfile(t, target)
			if resolved.Value().Target != target || inspection.Value().Target != target ||
				resolved.Value().CapabilityGraphDigest != graph.Digest() ||
				inspection.Value().CompositionDigest != resolved.Digest() {
				t.Fatalf("resolved=%+v inspection=%+v", resolved.Value(), inspection.Value())
			}
			var shape map[string]json.RawMessage
			if err := json.Unmarshal(inspection.CanonicalBytes(), &shape); err != nil {
				t.Fatal(err)
			}
			keys := make([]string, 0, len(shape))
			for key := range shape {
				keys = append(keys, key)
			}
			slices.Sort(keys)
			if inspectionShape == nil {
				inspectionShape = keys
			} else if !slices.Equal(inspectionShape, keys) {
				t.Fatalf("surface shape drift: want=%v got=%v", inspectionShape, keys)
			}
		})
	}
}

func resolveParityProfile(t *testing.T, target profilecomposition.ExactTarget) (
	profilecomposition.ValidatedResolvedProfile, capabilityseam.ValidatedGraph, profilecomposition.ValidatedInspection) {
	t.Helper()
	request := profilecomposition.Request{ProfileID: "018f0000-0000-7000-8000-000000000900", Revision: 1, Target: target}
	layer := commandTestLayer("sha256:" + strings.Repeat("a", 64))
	layer.Target = profilecomposition.Target{DeploymentKinds: []string{target.DeploymentKind},
		ConnectivityModes: []string{target.ConnectivityMode}, Platforms: []string{target.Platform},
		Surfaces: []string{target.Surface}}
	layer.Name = "baseline." + target.DeploymentKind + "." + target.Surface
	layer.Contribution.DeploymentProfile.ID = "deployment." + target.DeploymentKind + "." + target.ConnectivityMode
	if target.ConnectivityMode == "air_gapped" {
		layer.Contribution.OfflineBundleDigest = "sha256:" + strings.Repeat("8", 64)
		layer.Contribution.Features.ExternalConnectivity = false
	}
	draft, err := profilecomposition.Prepare(context.Background(), request, commandRevisionAuthority(request),
		[]profilecomposition.VerifiedLayer{verifyCommandTestLayer(t, layer)})
	if err != nil {
		t.Fatal(err)
	}
	bundleValue := commandCapabilityBundle(t, draft.ProfileBindingDigest()).Value()
	for index := range bundleValue.Providers {
		bundleValue.Providers[index].Scope.Environment = target.DeploymentKind
	}
	for index := range bundleValue.Consumers {
		bundleValue.Consumers[index].Scope.Environment = target.DeploymentKind
	}
	encoded, err := json.Marshal(bundleValue)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := capabilityseam.DecodeBundle(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	layer.Contribution.CapabilityBundles[0].Digest = bundle.Digest()
	candidate, err := profilecomposition.Prepare(context.Background(), request, commandRevisionAuthority(request),
		[]profilecomposition.VerifiedLayer{verifyCommandTestLayer(t, layer)})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareProfileCapabilities(context.Background(), candidate, []ProfileCapabilityArtifact{{
		Reference: layer.Contribution.CapabilityBundles[0], Bundle: bundle,
	}})
	if err != nil {
		t.Fatal(err)
	}
	resolved, graph, err := prepared.Resolve(context.Background(), compositionClock{compositionTestTime},
		commandQualificationAuthority(prepared, bundle.Value()))
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := prepared.Inspect(context.Background(), resolved, graph)
	if err != nil {
		t.Fatal(err)
	}
	replay, replayGraph, replayInspection := resolvePreparedParityReplay(t, prepared,
		commandQualificationAuthority(prepared, bundle.Value()))
	if !slices.Equal(resolved.CanonicalBytes(), replay.CanonicalBytes()) ||
		!slices.Equal(graph.CanonicalBytes(), replayGraph.CanonicalBytes()) ||
		!slices.Equal(inspection.CanonicalBytes(), replayInspection.CanonicalBytes()) {
		t.Fatal("canonical replay drift")
	}
	return resolved, graph, inspection
}

func resolvePreparedParityReplay(t *testing.T, prepared PreparedProfileCapabilities,
	authority capabilityseam.QualificationAuthoritySnapshot) (profilecomposition.ValidatedResolvedProfile,
	capabilityseam.ValidatedGraph, profilecomposition.ValidatedInspection) {
	t.Helper()
	resolved, graph, err := prepared.Resolve(context.Background(), compositionClock{compositionTestTime}, authority)
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := prepared.Inspect(context.Background(), resolved, graph)
	if err != nil {
		t.Fatal(err)
	}
	return resolved, graph, inspection
}
