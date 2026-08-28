package capabilityseam

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"
)

func TestRepeatedAndConcurrentResolutionIsDeterministic(t *testing.T) {
	bundle := bundleWithTokenizerDependency(t)
	authority := authorityFor(bundle)
	resolver, err := NewResolver(fixedClock{now: qualificationTestTime})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := resolver.Resolve(context.Background(), bundle, authority)
	if err != nil {
		t.Fatal(err)
	}
	for trial := 0; trial < 100; trial++ {
		resolved, resolveErr := resolver.Resolve(context.Background(), bundle, authority)
		if resolveErr != nil || resolved.Digest() != baseline.Digest() ||
			!bytes.Equal(resolved.CanonicalBytes(), baseline.CanonicalBytes()) {
			t.Fatalf("trial %d diverged: digest=%s err=%v", trial, resolved.Digest(), resolveErr)
		}
	}
	const workers = 64
	results := make(chan ValidatedGraph, workers)
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			resolved, resolveErr := resolver.Resolve(context.Background(), bundle, authority)
			results <- resolved
			errors <- resolveErr
		}()
	}
	group.Wait()
	close(results)
	close(errors)
	for resolveErr := range errors {
		if resolveErr != nil {
			t.Fatalf("concurrent resolution: %v", resolveErr)
		}
	}
	for resolved := range results {
		if resolved.Digest() != baseline.Digest() || !bytes.Equal(resolved.CanonicalBytes(), baseline.CanonicalBytes()) {
			t.Fatal("concurrent resolution diverged")
		}
	}
}

func TestRevocationAfterSuccessAndRecovery(t *testing.T) {
	bundle := decodeFixtureBundle(t)
	resolver, _ := NewResolver(fixedClock{now: qualificationTestTime})
	authority := authorityFor(bundle)
	baseline, err := resolver.Resolve(context.Background(), bundle, authority)
	if err != nil {
		t.Fatal(err)
	}
	revoked := authority
	revoked.Records = append([]QualificationAuthorityRecord(nil), authority.Records...)
	revoked.Records[0].Active = false
	revoked.Records[0].RevocationRevision = 2
	if graph, err := resolver.Resolve(context.Background(), bundle, revoked); graph.Digest() != "" ||
		Code(err) != Denied || Reason(err) != "qualification_revoked" {
		t.Fatalf("revoked graph=%s err=%v", graph.Digest(), err)
	}
	recovered, err := resolver.Resolve(context.Background(), bundle, authority)
	if err != nil || recovered.Digest() != baseline.Digest() {
		t.Fatalf("recovery digest=%s err=%v", recovered.Digest(), err)
	}
}

func TestCompositionMigrationAndAuthorizedRollback(t *testing.T) {
	resolver, _ := NewResolver(fixedClock{now: qualificationTestTime})
	oldBundle := decodeFixtureBundle(t)
	oldAuthority := authorityFor(oldBundle)
	oldGraph, err := resolver.Resolve(context.Background(), oldBundle, oldAuthority)
	if err != nil {
		t.Fatal(err)
	}
	newBundle := migratedBundle(t)
	newAuthority := authorityFor(newBundle)
	newGraph, err := resolver.Resolve(context.Background(), newBundle, newAuthority)
	if err != nil || newGraph.Digest() == oldGraph.Digest() {
		t.Fatalf("migration digest=%s old=%s err=%v", newGraph.Digest(), oldGraph.Digest(), err)
	}
	if graph, err := resolver.Resolve(context.Background(), oldBundle, newAuthority); graph.Digest() != "" ||
		Code(err) != Denied || Reason(err) != "composition_authority_stale" {
		t.Fatalf("unauthorized rollback graph=%s err=%v", graph.Digest(), err)
	}
	rolledBack, err := resolver.Resolve(context.Background(), oldBundle, oldAuthority)
	if err != nil || rolledBack.Digest() != oldGraph.Digest() {
		t.Fatalf("authorized rollback digest=%s err=%v", rolledBack.Digest(), err)
	}
}

func TestCancellationDuringQualificationPublishesNoGraph(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	resolver, _ := NewResolver(cancelingClock{now: qualificationTestTime, cancel: cancel})
	bundle := bundleWithTokenizerDependency(t)
	graph, err := resolver.Resolve(ctx, bundle, authorityFor(bundle))
	if graph.Digest() != "" || Code(err) != Canceled || Reason(err) != "context_canceled" {
		t.Fatalf("graph=%s code=%s reason=%s err=%v", graph.Digest(), Code(err), Reason(err), err)
	}
}

func FuzzCapabilitySeamDecodersRecoverAcceptedDocuments(f *testing.F) {
	f.Add(readFixture(f, "bundle.valid.json"))
	f.Add(readFixture(f, "graph.valid.json"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if bundle, err := DecodeBundle(context.Background(), input); err == nil {
			again, replayErr := DecodeBundle(context.Background(), bundle.CanonicalBytes())
			if replayErr != nil || again.Digest() != bundle.Digest() {
				t.Fatalf("accepted bundle did not replay: %v", replayErr)
			}
		}
		if graph, err := DecodeGraph(context.Background(), input); err == nil {
			again, replayErr := DecodeGraph(context.Background(), graph.CanonicalBytes())
			if replayErr != nil || again.Digest() != graph.Digest() {
				t.Fatalf("accepted graph did not replay: %v", replayErr)
			}
		}
	})
}

type cancelingClock struct {
	now    time.Time
	cancel context.CancelFunc
}

func (clock cancelingClock) Now() time.Time {
	clock.cancel()
	return clock.now
}

func migratedBundle(t *testing.T) ValidatedBundle {
	return mutateValidBundle(t, func(value *Bundle) {
		value.Revision = 2
		capability := CapabilityRef{Name: "model.inference", Version: "1.1.0"}
		value.Definitions[0].Capability = capability
		value.Providers[0].Capability = capability
		value.Providers[0].ProviderVersion = "1.1.0"
		value.Providers[0].ArtifactDigest = digestOf("9")
		value.Providers[0].Owner.ArtifactDigest = digestOf("9")
		value.Providers[0].Qualification.RecordID = "018f0000-0000-7000-8000-000000000009"
		value.Providers[0].Qualification.RecordDigest = digestOf("9")
		value.Providers[0].Qualification.ProviderArtifactDigest = digestOf("9")
		value.Consumers[0].Capability = capability
	})
}
