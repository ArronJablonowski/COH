package agentloop

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/ArronJablonowski/COH/internal/workflow/skillregistry"
)

type skillRegistryStub struct {
	request   skillregistry.ResolveRequest
	decision  skillregistry.AccessDecision
	authority skillregistry.ResolutionAuthority
	result    skillregistry.ResolvedSkill
	err       error
}

func (stub *skillRegistryStub) Change(context.Context,
	skillregistry.ChangeRequest) (skillregistry.State, error) {
	return skillregistry.State{}, errors.New("change is not exposed by lookup activity")
}

func (stub *skillRegistryStub) Resolve(_ context.Context, request skillregistry.ResolveRequest,
	decision skillregistry.AccessDecision, authority skillregistry.ResolutionAuthority) (skillregistry.ResolvedSkill, error) {
	stub.request, stub.decision, stub.authority = request, decision, authority
	return stub.result, stub.err
}

type skillAuthorityStub struct {
	request   SkillLookupRequest
	decision  skillregistry.AccessDecision
	authority skillregistry.ResolutionAuthority
	err       error
}

func (stub *skillAuthorityStub) AuthorizeSkill(_ context.Context,
	request SkillLookupRequest) (skillregistry.AccessDecision, skillregistry.ResolutionAuthority, error) {
	stub.request = request
	return stub.decision, stub.authority, stub.err
}

func TestSkillLookupActivityPassesOnlyExactImmutableBindings(t *testing.T) {
	deadline := mustTime(t, "2026-08-26T17:10:00.000000000Z")
	request := SkillLookupRequest{
		RequestID: testRun, Case: testScope(), TaskID: testPlanStep, ActorID: testActor,
		SkillName: "timeline_builder", ExpectedManifestDigest: testDigestOne,
		RequiredPermission: "evidence.read", PolicyDigest: testDigestTwo, Deadline: deadline,
	}
	decision := skillregistry.AccessDecision{DecisionID: testActionStep, DecisionDigest: testDigestThree}
	authority := skillregistry.ResolutionAuthority{}
	registry := &skillRegistryStub{result: skillregistry.ResolvedSkill{
		SkillName: "timeline_builder", SkillVersion: "1.0.0", ManifestDigest: testDigestOne,
		ContentDigest: testDigestTwo, Resources: []skillregistry.Resource{{
			Name: "instructions", Digest: testDigestThree, MediaType: "text/markdown",
			Classification: "internal", Length: 32,
		}}, Permissions: []string{"evidence.read"}, OwnerActorID: testActor,
		ReviewID: testActionStep, ReviewRevision: 2, ProvenanceDigest: testDigestThree,
	}}
	resolver := &skillAuthorityStub{decision: decision, authority: authority}
	activity, err := NewSkillLookupActivity(registry, resolver)
	if err != nil {
		t.Fatal(err)
	}
	result, err := activity.Lookup(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if resolver.request != request || registry.request.RequestID != request.RequestID ||
		registry.request.OrganizationID != request.Case.OrganizationID ||
		registry.request.TenantID != request.Case.TenantID || registry.request.CaseID != request.Case.CaseID ||
		registry.request.TaskID != request.TaskID || registry.request.ActorID != request.ActorID ||
		registry.request.SkillName != request.SkillName ||
		registry.request.ExpectedManifestDigest != request.ExpectedManifestDigest ||
		registry.request.RequiredPermission != request.RequiredPermission ||
		registry.request.PolicyDigest != request.PolicyDigest || registry.request.Deadline != request.Deadline ||
		registry.decision.DecisionDigest != decision.DecisionDigest {
		t.Fatalf("lookup widened or dropped bindings: %#v", registry.request)
	}
	if result.ContentDigest != testDigestTwo || len(result.Resources) != 1 ||
		result.Resources[0].Digest != testDigestThree || result.Permissions[0] != "evidence.read" {
		t.Fatalf("unexpected result: %#v", result)
	}
	result.Resources[0].Name = "mutated"
	result.Permissions[0] = "mutated"
	if registry.result.Resources[0].Name != "instructions" ||
		registry.result.Permissions[0] != "evidence.read" {
		t.Fatal("lookup returned mutable registry slices")
	}
}

func TestSkillLookupActivityDeniesMalformedAndMapsRegistryFailure(t *testing.T) {
	registry := &skillRegistryStub{}
	authority := &skillAuthorityStub{}
	activity, _ := NewSkillLookupActivity(registry, authority)
	request := SkillLookupRequest{
		RequestID: testRun, Case: testScope(), TaskID: testPlanStep, ActorID: testActor,
		SkillName: "timeline_builder", ExpectedManifestDigest: testDigestOne,
		RequiredPermission: "evidence.read", PolicyDigest: testDigestTwo,
		Deadline: mustTime(t, "2026-08-26T17:10:00.000000000Z"),
	}
	malformed := request
	malformed.Case.TenantID = "wrong"
	if _, err := activity.Lookup(context.Background(), malformed); Code(err) != InvalidInput {
		t.Fatalf("malformed scope accepted: %v", err)
	}
	registry.err = context.DeadlineExceeded
	if _, err := activity.Lookup(context.Background(), request); Code(err) != Timeout {
		t.Fatalf("registry timeout not preserved: %v", err)
	}
	authority.err = errors.New("policy unavailable")
	registry.err = nil
	if _, err := activity.Lookup(context.Background(), request); err == nil {
		t.Fatal("authority failure was ignored")
	}
}

func TestSkillLookupSurfaceHasNoExecutionCapability(t *testing.T) {
	typeOf := reflect.TypeOf(SkillLookupActivity{})
	if typeOf.NumField() != 2 || typeOf.Field(0).Name != "registry" ||
		typeOf.Field(1).Name != "authority" {
		t.Fatalf("lookup activity capability surface changed: %v", typeOf)
	}
	resultType := reflect.TypeOf(SkillLookupResult{})
	forbidden := map[string]bool{
		"Content": true, "Bytes": true, "Path": true, "URI": true, "URL": true,
		"Connector": true, "Executor": true, "Filesystem": true, "Model": true,
	}
	for index := 0; index < resultType.NumField(); index++ {
		if forbidden[resultType.Field(index).Name] {
			t.Fatalf("result exposes %s", resultType.Field(index).Name)
		}
	}
}
