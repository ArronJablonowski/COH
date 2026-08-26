package agentloop

import (
	"context"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/retrievalguard"
	"github.com/ArronJablonowski/COH/internal/workflow/skilldiscovery"
)

type discoveryStub struct {
	searchRequest   skilldiscovery.SearchRequest
	detailRequest   skilldiscovery.DetailRequest
	resourceRequest skilldiscovery.ResourceRequest
	searchResult    skilldiscovery.SearchResult
	detailResult    skilldiscovery.DetailResult
	resourceResult  skilldiscovery.ResourceResult
	err             error
}

func (stub *discoveryStub) Search(_ context.Context, request skilldiscovery.SearchRequest) (skilldiscovery.SearchResult, error) {
	stub.searchRequest = request
	return stub.searchResult, stub.err
}
func (stub *discoveryStub) Detail(_ context.Context, request skilldiscovery.DetailRequest) (skilldiscovery.DetailResult, error) {
	stub.detailRequest = request
	return stub.detailResult, stub.err
}
func (stub *discoveryStub) Resource(_ context.Context, request skilldiscovery.ResourceRequest) (skilldiscovery.ResourceResult, error) {
	stub.resourceRequest = request
	return stub.resourceResult, stub.err
}

func TestSkillDiscoveryActivityExposesOnlyProgressivePhases(t *testing.T) {
	stub := &discoveryStub{searchResult: skilldiscovery.SearchResult{
		Skills: []skilldiscovery.CompactSkill{{SkillName: "timeline_builder", SkillVersion: "1.0.0",
			ManifestDigest: testDigestOne, ProvenanceDigest: testDigestTwo}},
		SnapshotDigest: testDigestThree, ResultDigest: testDigestOne}}
	activity, err := NewSkillDiscoveryActivity(stub, &retrievalGuardStub{})
	if err != nil {
		t.Fatal(err)
	}
	request := skilldiscovery.SearchRequest{RequestID: testRun}
	result, err := activity.Search(context.Background(), request)
	if err != nil || stub.searchRequest.RequestID != request.RequestID || len(result.Skills) != 1 {
		t.Fatalf("progressive search was not passed exactly: %#v %v", result, err)
	}
	typeOf := reflect.TypeOf(SkillDiscoveryActivity{})
	if typeOf.NumField() != 2 || typeOf.Field(0).Name != "discovery" || typeOf.Field(1).Name != "guard" {
		t.Fatalf("activity gained another capability: %v", typeOf)
	}
	interfaceType := reflect.TypeOf((*ProgressiveSkillDiscovery)(nil)).Elem()
	if interfaceType.NumMethod() != 3 {
		t.Fatalf("discovery interface widened: %v", interfaceType)
	}
	for _, forbidden := range []string{"Change", "Promote", "Execute", "Invoke", "Submit", "HTTP", "Shell"} {
		if _, found := interfaceType.MethodByName(forbidden); found {
			t.Fatalf("discovery exposes forbidden method %s", forbidden)
		}
	}
}

func TestSkillDiscoveryActivityMapsDenialAndTimeout(t *testing.T) {
	stub := &discoveryStub{err: context.DeadlineExceeded}
	activity, _ := NewSkillDiscoveryActivity(stub, &retrievalGuardStub{})
	if _, err := activity.Detail(context.Background(), skilldiscovery.DetailRequest{}); Code(err) != Timeout {
		t.Fatalf("timeout not preserved: %v", err)
	}
}

func TestSkillResourceIsInspectedBeforeModelFacingRelease(t *testing.T) {
	resource := skilldiscovery.ResourceResult{SkillName: "timeline_builder", ManifestDigest: testDigestOne,
		ResourceName: "references/timeline.md", Artifact: domain.ArtifactRef{Digest: testDigestOne,
			MediaType: "text/plain", Classification: "restricted", Length: 256},
		ProvenanceDigest: testDigestTwo}
	discovery := &discoveryStub{resourceResult: resource}
	guard := &retrievalGuardStub{result: guardedResult()}
	activity, err := NewSkillDiscoveryActivity(discovery, guard)
	if err != nil {
		t.Fatal(err)
	}
	request := skilldiscovery.ResourceRequest{RequestID: testRun, IdempotencyKey: "resource-1",
		Case: testScope(), TaskID: testPlanStep, ActorID: testActor, PolicyDigest: testDigestOne,
		Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z")}
	result, err := activity.Resource(context.Background(), SkillResourceRequest{Discovery: request,
		ActorRevision: 4, InspectionIdempotencyKey: "inspect-resource-1",
		InspectionProfile: retrievalguard.InspectionProfile{Name: "strict_data"}})
	if err != nil {
		t.Fatal(err)
	}
	if guard.request.Source.Kind != retrievalguard.DocumentSource || guard.request.Source.Trust != retrievalguard.UntrustedContent ||
		guard.request.Source.Artifact != resource.Artifact || guard.request.Source.ProvenanceDigest != resource.ProvenanceDigest ||
		guard.request.ActorRevision != 4 || result.Inspection.Sanitized.Digest != testDigestThree || result.SourceDigest != testDigestOne {
		t.Fatalf("guard request=%+v result=%+v", guard.request, result)
	}
	resultType := reflect.TypeOf(result)
	if _, exposed := resultType.FieldByName("Artifact"); exposed {
		t.Fatal("raw skill resource artifact is model-facing")
	}
}
