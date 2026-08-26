package toolregistry

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRegistryAdmissionReplayResolutionAndTierNarrowing(t *testing.T) {
	clock := &testClock{now: registryTime}
	registry, err := NewRegistry(clock)
	if err != nil {
		t.Fatal(err)
	}
	signed, authority := signedManifest(t, testManifest())
	admitted, err := registry.Admit(context.Background(), signed, authority)
	if err != nil || admitted.Replayed || admitted.Tool.ArtifactDigest != testDigest("a") ||
		admitted.PublisherID != testPublisherID || admitted.PublisherApprovalRevision != authority.ApprovalRevision ||
		admitted.ReviewID != testReviewID || admitted.ReviewRevision != 2 {
		t.Fatalf("admission=%+v err=%v", admitted, err)
	}
	replayed, err := registry.Admit(context.Background(), signed, authority)
	if err != nil || !replayed.Replayed || replayed.ManifestDigest != admitted.ManifestDigest {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}
	resolved, err := registry.Resolve(context.Background(), admitted.Tool, authority)
	if err != nil || resolved.ManifestDigest != admitted.ManifestDigest {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	capability, err := registry.ResolveOperation(context.Background(), admitted.Tool, "execute", "T1", "T2", authority)
	if err != nil || capability.EffectiveCeiling != "T2" || capability.Operation.Name != "execute" {
		t.Fatalf("capability=%+v err=%v", capability, err)
	}
	capability.Operation.InputFields[0].Name = "changed"
	again, err := registry.ResolveOperation(context.Background(), admitted.Tool, "execute", "T1", "T2", authority)
	if err != nil || again.Operation.InputFields[0].Name != "query_digest" {
		t.Fatalf("caller mutated registry operation: %+v err=%v", again, err)
	}
	for _, test := range []struct {
		operation string
		required  string
		ceiling   string
		reason    string
	}{
		{"missing", "T1", "T2", "operation_not_registered"},
		{"execute", "T0", "T2", "tier_below_baseline"},
		{"execute", "T1", "T0", "tier_exceeds_effective_ceiling"},
		{"execute", "T1", "T3", "policy_ceiling_elevation"},
	} {
		if _, err := registry.ResolveOperation(context.Background(), admitted.Tool, test.operation,
			test.required, test.ceiling, authority); Reason(err) != test.reason {
			t.Fatalf("request=%+v err=%v", test, err)
		}
	}
}

func TestRegistryRevocationExpiryCollisionAndRecovery(t *testing.T) {
	clock := &testClock{now: registryTime}
	registry, _ := NewRegistry(clock)
	manifest := testManifest()
	signed, authority := signedManifest(t, manifest)
	admission, err := registry.Admit(context.Background(), signed, authority)
	if err != nil {
		t.Fatal(err)
	}

	revoked := authority
	revoked.Active = false
	if _, err := registry.Resolve(context.Background(), admission.Tool, revoked); Reason(err) != "publisher_authority" {
		t.Fatalf("revocation err=%v", err)
	}
	newer := authority
	newer.ApprovalRevision++
	if replay, err := registry.Admit(context.Background(), signed, newer); err != nil || !replay.Replayed {
		t.Fatalf("new approval replay=%+v err=%v", replay, err)
	}
	stale := authority
	if _, err := registry.Admit(context.Background(), signed, stale); Reason(err) != "publisher_authority_stale" {
		t.Fatalf("stale replay err=%v", err)
	}
	if _, err := registry.Resolve(context.Background(), admission.Tool, stale); Reason(err) != "publisher_authority_stale" {
		t.Fatalf("stale approval err=%v", err)
	}
	rotated := newer
	rotated.KeyRevision++
	if _, err := registry.Resolve(context.Background(), admission.Tool, rotated); Reason(err) != "publisher_authority" {
		t.Fatalf("rotation err=%v", err)
	}

	changed := manifest
	changed.Operations[0].ResourceLimits.OutputBytes++
	changedSigned, _ := signedManifest(t, changed)
	if _, err := registry.Admit(context.Background(), changedSigned, newer); Reason(err) != "tool_identity_collision" {
		t.Fatalf("collision err=%v", err)
	}
	if _, err := registry.Resolve(context.Background(), admission.Tool, newer); err != nil {
		t.Fatalf("last valid snapshot lost: %v", err)
	}

	clock.now = registryTime.Add(2 * time.Hour)
	if _, err := registry.Resolve(context.Background(), admission.Tool, newer); Reason(err) != "manifest_not_current" {
		t.Fatalf("expiry err=%v", err)
	}
	clock.now = registryTime
	if _, err := registry.Resolve(context.Background(), admission.Tool, newer); err != nil {
		t.Fatalf("fresh-time recovery: %v", err)
	}
}

func TestRegistryCancellationTimeoutAndConcurrentReplay(t *testing.T) {
	registry, _ := NewRegistry(&testClock{now: registryTime})
	signed, authority := signedManifest(t, testManifest())
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := registry.Admit(canceled, signed, authority); Code(err) != Canceled {
		t.Fatalf("cancel err=%v", err)
	}
	expired, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := registry.Admit(expired, signed, authority); Code(err) != Timeout {
		t.Fatalf("timeout err=%v", err)
	}

	const workers = 16
	start := make(chan struct{})
	results := make(chan Admission, workers)
	errors := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := registry.Admit(context.Background(), signed, authority)
			results <- result
			errors <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent admission err=%v", err)
		}
	}
	fresh, replayed := 0, 0
	for result := range results {
		if result.Replayed {
			replayed++
		} else {
			fresh++
		}
	}
	if fresh != 1 || replayed != workers-1 {
		t.Fatalf("fresh=%d replayed=%d", fresh, replayed)
	}
}
