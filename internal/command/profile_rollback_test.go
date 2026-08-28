package command

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/profileactivation"
	"github.com/ArronJablonowski/COH/internal/domain/profilecomposition"
	"github.com/ArronJablonowski/COH/internal/persistence/sqlite"
)

func TestAuthorizedRollbackReverifiesAndActivatesAsNewComposition(t *testing.T) {
	target := profilecomposition.ExactTarget{DeploymentKind: "native_workstation", ConnectivityMode: "connected",
		Platform: "darwin_arm64", Surface: "web"}
	baseRequest := profilecomposition.Request{ProfileID: "018f0000-0000-7000-8000-000000000900", Revision: 1, Target: target}
	initialAuthority := commandRevisionAuthority(baseRequest)
	first := resolveActivationProfile(t, baseRequest, initialAuthority, commandTestLayer("sha256:"+strings.Repeat("a", 64)))

	root := t.TempDir()
	backup := filepath.Join(root, "backups")
	if err := os.Mkdir(backup, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.Open(context.Background(), sqlite.Config{Path: filepath.Join(root, "coh.sqlite3"),
		BackupDirectory: backup, Clock: func() time.Time { return compositionTestTime }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	controller, err := profileactivation.NewController(store,
		commandMaintenanceGate{digest: "sha256:" + strings.Repeat("d", 64)}, compositionClock{compositionTestTime})
	if err != nil {
		t.Fatal(err)
	}
	active, err := ActivateResolvedProfile(context.Background(), controller,
		"018f0000-0000-7000-8000-000000000960", profileactivation.Startup, 30000,
		first.resolved, first.inspection, 0, "")
	if err != nil {
		t.Fatal(err)
	}

	secondRequest := baseRequest
	secondRequest.Revision = 2
	secondRequest.PreviousCompositionDigest = active.Profile.CompositionDigest
	secondAuthority := profilecomposition.RevisionAuthority{ProfileID: baseRequest.ProfileID, Target: target,
		CurrentRevision: 1, CurrentCompositionDigest: active.Profile.CompositionDigest, Active: true}
	second := resolveActivationProfile(t, secondRequest, secondAuthority,
		commandTestLayer("sha256:"+strings.Repeat("a", 64)))
	active, err = ActivateResolvedProfile(context.Background(), controller,
		"018f0000-0000-7000-8000-000000000961", profileactivation.Maintenance, 30000,
		second.resolved, second.inspection, active.Profile.ProfileRevision, active.Profile.CompositionDigest)
	if err != nil {
		t.Fatal(err)
	}

	thirdRequest := baseRequest
	thirdRequest.Revision = 3
	thirdRequest.PreviousCompositionDigest = active.Profile.CompositionDigest
	thirdAuthority := profilecomposition.RevisionAuthority{ProfileID: baseRequest.ProfileID, Target: target,
		CurrentRevision: 2, CurrentCompositionDigest: active.Profile.CompositionDigest, Active: true}
	third := resolveActivationProfile(t, thirdRequest, thirdAuthority,
		commandTestLayer("sha256:"+strings.Repeat("a", 64)))
	active, err = ActivateResolvedProfile(context.Background(), controller,
		"018f0000-0000-7000-8000-000000000962", profileactivation.Maintenance, 30000,
		third.resolved, third.inspection, active.Profile.ProfileRevision, active.Profile.CompositionDigest)
	if err != nil {
		t.Fatal(err)
	}

	rollbackAuthorization := "sha256:" + strings.Repeat("b", 64)
	rollbackRequest := baseRequest
	rollbackRequest.PreviousCompositionDigest = active.Profile.CompositionDigest
	rollbackRequest.RollbackAuthorizationDigest = rollbackAuthorization
	rollbackAuthority := profilecomposition.RevisionAuthority{ProfileID: baseRequest.ProfileID, Target: target,
		CurrentRevision: 3, CurrentCompositionDigest: active.Profile.CompositionDigest,
		RollbackAuthorizationDigest: rollbackAuthorization, Active: true}
	rollbackLayer := commandTestLayer("sha256:" + strings.Repeat("a", 64))
	rollbackLayer.RollbackAuthorizationDigest = rollbackAuthorization
	rollback := resolveActivationProfile(t, rollbackRequest, rollbackAuthority, rollbackLayer)
	rolledBack, err := ActivateResolvedProfile(context.Background(), controller,
		"018f0000-0000-7000-8000-000000000963", profileactivation.Maintenance, 30000,
		rollback.resolved, rollback.inspection, active.Profile.ProfileRevision, active.Profile.CompositionDigest)
	if err != nil || rolledBack.Profile.ProfileRevision != 1 ||
		rolledBack.Profile.CompositionDigest == first.resolved.Digest() ||
		rolledBack.Profile.TransitionID == active.Profile.TransitionID {
		t.Fatalf("rollback=%+v err=%v", rolledBack, err)
	}
}

type activationProfile struct {
	resolved   profilecomposition.ValidatedResolvedProfile
	inspection profilecomposition.ValidatedInspection
}

func resolveActivationProfile(t *testing.T, request profilecomposition.Request,
	authority profilecomposition.RevisionAuthority, layer profilecomposition.Layer) activationProfile {
	t.Helper()
	draft, err := profilecomposition.Prepare(context.Background(), request, authority,
		[]profilecomposition.VerifiedLayer{verifyCommandTestLayer(t, layer)})
	if err != nil {
		t.Fatal(err)
	}
	bundle := commandCapabilityBundle(t, draft.ProfileBindingDigest())
	layer.Contribution.CapabilityBundles[0].Digest = bundle.Digest()
	candidate, err := profilecomposition.Prepare(context.Background(), request, authority,
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
	return activationProfile{resolved: resolved, inspection: inspection}
}
