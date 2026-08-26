package skilldiscovery

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestSearchReturnsOnlyCompactMetadataWithStablePaginationAndReplay(t *testing.T) {
	fixture := newTestFixture(t)
	request := fixture.search()
	first, err := fixture.control.Search(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Skills) != 2 || first.Skills[0].SkillName != "alpha_skill" ||
		first.Skills[1].SkillName != "beta_skill" || first.NextCursor == "" || first.Replayed {
		t.Fatalf("unexpected first page: %#v", first)
	}
	if len(fixture.authority.requests) != 3 || fixture.authority.requests[0].SkillName != "" ||
		fixture.authority.requests[1].SkillName != "alpha_skill" {
		t.Fatalf("search was not separately authorized before candidates: %#v", fixture.authority.requests)
	}
	request.RequestID = testRequest2
	request.IdempotencyKey = "search-two"
	request.Cursor = first.NextCursor
	request.ExpectedSnapshotDigest = first.SnapshotDigest
	second, err := fixture.control.Search(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Skills) != 1 || second.Skills[0].SkillName != "gamma_skill" || second.NextCursor != "" {
		t.Fatalf("unexpected second page: %#v", second)
	}
	replayRequest := fixture.search()
	replayed, err := fixture.control.Search(context.Background(), replayRequest)
	if err != nil || !replayed.Replayed || fixture.store.commits != 2 {
		t.Fatalf("exact replay not recovered: %#v %v commits=%d", replayed, err, fixture.store.commits)
	}
	replayed.Skills[0].SkillName = "mutated"
	again, err := fixture.control.Search(context.Background(), replayRequest)
	if err != nil || again.Skills[0].SkillName != "alpha_skill" {
		t.Fatal("replay returned aliased result memory")
	}
}

func TestDetailAndResourceRequireExactSignedBindings(t *testing.T) {
	fixture := newTestFixture(t)
	detail, err := fixture.control.Detail(context.Background(), fixture.detail("alpha_skill"))
	if err != nil {
		t.Fatal(err)
	}
	if detail.ContentDigest == "" || len(detail.Resources) != 1 || len(detail.Permissions) != 1 ||
		detail.ManifestDigest != fixture.registry.results["alpha_skill"].ManifestDigest {
		t.Fatalf("unexpected detail: %#v", detail)
	}
	resourceRequest := fixture.resource("alpha_skill")
	resource := fixture.registry.results["alpha_skill"].Resources[0]
	fixture.retriever.result.Digest = resource.Digest
	fixture.retriever.result.MediaType = resource.MediaType
	fixture.retriever.result.Classification = resource.Classification
	fixture.retriever.result.Length = resource.Length
	result, err := fixture.control.Resource(context.Background(), resourceRequest)
	if err != nil {
		t.Fatal(err)
	}
	if result.Artifact.Digest != resource.Digest ||
		fixture.retriever.request.DecisionDigest == "" ||
		fixture.retriever.request.ProvenanceDigest != detail.ProvenanceDigest {
		t.Fatalf("retrieval lost exact bindings: %#v %#v", result, fixture.retriever.request)
	}
}

func TestChangedReplayStaleStateTamperAndArtifactDriftFailClosed(t *testing.T) {
	fixture := newTestFixture(t)
	request := fixture.search()
	first, err := fixture.control.Search(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	changed := request
	changed.Query = "alpha"
	if _, err := fixture.control.Search(context.Background(), changed); CodeOf(err) != Denied || Reason(err) != "changed_replay" {
		t.Fatalf("changed replay accepted: %v", err)
	}
	stale := request
	stale.RequestID = testRequest2
	stale.IdempotencyKey = "stale"
	stale.Cursor = first.NextCursor
	stale.ExpectedSnapshotDigest = testDigest("old-snapshot")
	if _, err := fixture.control.Search(context.Background(), stale); CodeOf(err) != Denied || Reason(err) != "stale_catalog_snapshot" {
		t.Fatalf("stale snapshot accepted: %v", err)
	}
	fixture.authority.tamper = true
	if _, err := fixture.control.Detail(context.Background(), fixture.detail("alpha_skill")); CodeOf(err) != Denied {
		t.Fatalf("tampered decision accepted: %v", err)
	}
	fixture.authority.tamper = false
	resourceRequest := fixture.resource("alpha_skill")
	fixture.retriever.result = fixtureResourceRef(fixture, "alpha_skill")
	fixture.retriever.result.Length++
	if _, err := fixture.control.Resource(context.Background(), resourceRequest); CodeOf(err) != Denied ||
		Reason(err) != "retrieved_artifact_mismatch" {
		t.Fatalf("artifact drift accepted: %v", err)
	}
}

func TestProgressiveParentsCannotBeSkippedOrSubstituted(t *testing.T) {
	fixture := newTestFixture(t)
	detail := fixture.detail("alpha_skill")
	detail.SearchIdempotencyKey = "missing-search-parent"
	if _, err := fixture.control.Detail(context.Background(), detail); CodeOf(err) != Denied ||
		Reason(err) != "parent_result_missing" {
		t.Fatalf("detail skipped compact parent: %v", err)
	}
	detail = fixture.detail("alpha_skill")
	detail.ExpectedSearchResultDigest = testDigest("different-search-result")
	if _, err := fixture.control.Detail(context.Background(), detail); CodeOf(err) != Denied ||
		Reason(err) != "compact_parent_mismatch" {
		t.Fatalf("detail substituted compact result: %v", err)
	}
	detail = fixture.detail("alpha_skill")
	detail.ActorID = testRequest2
	if _, err := fixture.control.Detail(context.Background(), detail); CodeOf(err) != Denied ||
		Reason(err) != "parent_result_invalid" {
		t.Fatalf("detail reused another actor's compact result: %v", err)
	}
	resource := fixture.resource("alpha_skill")
	resource.ExpectedDetailResultDigest = testDigest("different-detail-result")
	if _, err := fixture.control.Resource(context.Background(), resource); CodeOf(err) != Denied ||
		Reason(err) != "detail_parent_mismatch" {
		t.Fatalf("resource substituted detail result: %v", err)
	}
}

func TestCancellationTimeoutAndDependencyFailureAreTyped(t *testing.T) {
	fixture := newTestFixture(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.control.Search(canceled, fixture.search()); CodeOf(err) != Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
	fixture.registry.err = context.DeadlineExceeded
	if _, err := fixture.control.Detail(context.Background(), fixture.detail("alpha_skill")); CodeOf(err) != Timeout {
		t.Fatalf("registry timeout lost: %v", err)
	}
	fixture.registry.err = nil
	fixture.authority.err = errors.New("policy offline")
	request := fixture.detail("beta_skill")
	request.IdempotencyKey = "authority-offline"
	if _, err := fixture.control.Detail(context.Background(), request); CodeOf(err) != Unavailable || !Retryable(err) {
		t.Fatalf("authority outage lost: %v", err)
	}
	fixture = newTestFixture(t)
	resourceRequest := fixture.resource("alpha_skill")
	resourceRequest.Deadline = fixture.now.Add(time.Millisecond)
	fixture.retriever.block = true
	if _, err := fixture.control.Resource(context.Background(), resourceRequest); CodeOf(err) != Timeout {
		t.Fatalf("operation deadline did not cancel retriever: %v", err)
	}
}

func TestExactReplayRechecksCurrentRegistryAndCatalog(t *testing.T) {
	fixture := newTestFixture(t)
	detailRequest := fixture.detail("alpha_skill")
	if _, err := fixture.control.Detail(context.Background(), detailRequest); err != nil {
		t.Fatal(err)
	}
	fixture.registry.err = context.DeadlineExceeded
	if _, err := fixture.control.Detail(context.Background(), detailRequest); CodeOf(err) != Timeout {
		t.Fatalf("detail replay bypassed current registry state: %v", err)
	}
	fixture = newTestFixture(t)
	searchRequest := fixture.search()
	if _, err := fixture.control.Search(context.Background(), searchRequest); err != nil {
		t.Fatal(err)
	}
	fixture.catalog.snapshot.SnapshotDigest = testDigest("replacement-snapshot")
	if _, err := fixture.control.Search(context.Background(), searchRequest); CodeOf(err) != Denied ||
		Reason(err) != "stale_replay_result" {
		t.Fatalf("search replay served stale catalog: %v", err)
	}
}

func TestLostCommitResponseRecoversWithoutChangingResult(t *testing.T) {
	fixture := newTestFixture(t)
	fixture.store.lostResponse = true
	request := fixture.search()
	if _, err := fixture.control.Search(context.Background(), request); CodeOf(err) != Unavailable {
		t.Fatalf("ambiguous commit did not surface as unavailable: %v", err)
	}
	recovered, err := fixture.control.Search(context.Background(), request)
	if err != nil || !recovered.Replayed || len(recovered.Skills) != 2 || fixture.store.commits != 1 {
		t.Fatalf("lost response did not recover exactly: %#v %v commits=%d", recovered, err, fixture.store.commits)
	}
}

func TestDiscoverySurfaceExposesNoContentOrExecutionCapability(t *testing.T) {
	controller := reflect.TypeOf(Controller{})
	if controller.NumField() != 6 {
		t.Fatalf("controller capability surface changed: %v", controller)
	}
	for _, value := range []any{CompactSkill{}, SearchResult{}, ResourceResult{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			name := typeOf.Field(index).Name
			forbidden := map[string]bool{"Content": true, "Bytes": true, "Path": true, "URL": true,
				"URI": true, "Secret": true, "Connector": true, "Executor": true, "Filesystem": true}
			if forbidden[name] || typeOf.Field(index).Type.Kind() == reflect.Func ||
				typeOf.Field(index).Type.Kind() == reflect.Interface {
				t.Fatalf("%s exposes forbidden field %s", typeOf.Name(), name)
			}
		}
	}
}

func fixtureResourceRef(fixture fixture, name string) domain.ArtifactRef {
	resource := fixture.registry.results[name].Resources[0]
	return domain.ArtifactRef{Digest: resource.Digest, MediaType: resource.MediaType,
		Classification: resource.Classification, Length: resource.Length}
}
