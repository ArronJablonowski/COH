package skilldiscovery

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/skillregistry"
)

const (
	testOrg      = "0198d6c4-2001-7001-8001-000000000001"
	testTenant   = "0198d6c4-2002-7002-8002-000000000002"
	testCase     = "0198d6c4-2003-7003-8003-000000000003"
	testTask     = "0198d6c4-2004-7004-8004-000000000004"
	testActor    = "0198d6c4-2005-7005-8005-000000000005"
	testOwner    = "0198d6c4-2006-7006-8006-000000000006"
	testReview   = "0198d6c4-2007-7007-8007-000000000007"
	testRequest  = "0198d6c4-2008-7008-8008-000000000008"
	testRequest2 = "0198d6c4-2009-7009-8009-000000000009"
)

func testDigest(label string) string {
	value, _ := digest("TEST\x00", label)
	return value
}

func testScope() domain.CaseRef {
	return domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase}
}

type testClock struct{ now time.Time }

func (clock testClock) Now() time.Time { return clock.now }

type catalogStub struct {
	snapshot skillregistry.CatalogSnapshot
	err      error
}

func (stub *catalogStub) LoadCatalog(context.Context, string, string) (skillregistry.CatalogSnapshot, error) {
	return stub.snapshot, stub.err
}

type registryStub struct {
	mu       sync.Mutex
	results  map[string]skillregistry.ResolvedSkill
	requests []skillregistry.ResolveRequest
	err      error
}

func (stub *registryStub) Resolve(_ context.Context, request skillregistry.ResolveRequest,
	_ skillregistry.AccessDecision, _ skillregistry.ResolutionAuthority) (skillregistry.ResolvedSkill, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.requests = append(stub.requests, request)
	if stub.err != nil {
		return skillregistry.ResolvedSkill{}, stub.err
	}
	return cloneResolved(stub.results[request.SkillName]), nil
}

type authorityStub struct {
	now      time.Time
	requests []AuthorizationRequest
	tamper   bool
	err      error
}

func (stub *authorityStub) AuthorizeDiscovery(_ context.Context, request AuthorizationRequest) (
	Decision, skillregistry.AccessDecision, skillregistry.ResolutionAuthority, error) {
	stub.requests = append(stub.requests, request)
	if stub.err != nil {
		return Decision{}, skillregistry.AccessDecision{}, skillregistry.ResolutionAuthority{}, stub.err
	}
	decision := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID: operationRequestID(request.RequestID, request.Phase, request.SkillName, len(stub.requests)),
		RequestID:  request.RequestID, PolicyDigest: request.PolicyDigest, Case: request.Case, TaskID: request.TaskID,
		ActorID: request.ActorID, Phase: request.Phase, SkillName: request.SkillName,
		ManifestDigest: request.ManifestDigest, RequiredPermission: request.RequiredPermission,
		ResourceName: request.ResourceName, ResourceDigest: request.ResourceDigest,
		QueryDigest: request.QueryDigest, SnapshotDigest: request.SnapshotDigest, Cursor: request.Cursor,
		PageLimit: request.PageLimit, ParentResultDigest: request.ParentResultDigest,
		Deadline: request.Deadline, Outcome: "allow", Revision: 1,
		IssuedAt: stub.now.Add(-time.Minute), ExpiresAt: stub.now.Add(time.Hour)}
	decision.DecisionDigest, _ = decisionDigest(decision)
	if stub.tamper {
		decision.TaskID = testRequest2
	}
	return decision, skillregistry.AccessDecision{}, skillregistry.ResolutionAuthority{}, nil
}

type retrieverStub struct {
	request RetrievalRequest
	result  domain.ArtifactRef
	err     error
	block   bool
}

func (stub *retrieverStub) ResolveResource(ctx context.Context, request RetrievalRequest) (domain.ArtifactRef, error) {
	stub.request = request
	if stub.block {
		<-ctx.Done()
		return domain.ArtifactRef{}, ctx.Err()
	}
	return stub.result, stub.err
}

type memoryStore struct {
	mu           sync.Mutex
	records      map[string]Record
	commits      int
	err          error
	lostResponse bool
}

func newMemoryStore() *memoryStore { return &memoryStore{records: map[string]Record{}} }

func memoryKey(scope domain.CaseRef, task string, operation Phase, idempotency string) string {
	return scope.OrganizationID + scope.TenantID + scope.CaseID + task + string(operation) + idempotency
}

func (store *memoryStore) Load(_ context.Context, scope domain.CaseRef, task string,
	operation Phase, idempotency string) (Record, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.err != nil {
		return Record{}, false, store.err
	}
	value, found := store.records[memoryKey(scope, task, operation, idempotency)]
	return cloneRecord(value), found, nil
}

func (store *memoryStore) Commit(_ context.Context, _ string, value Record) (Record, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.err != nil {
		return Record{}, false, store.err
	}
	key := memoryKey(value.Case, value.TaskID, value.Operation, value.IdempotencyDigest)
	if prior, found := store.records[key]; found {
		return cloneRecord(prior), true, nil
	}
	store.records[key] = cloneRecord(value)
	store.commits++
	if store.lostResponse {
		store.lostResponse = false
		return Record{}, false, errors.New("response lost after durable commit")
	}
	return cloneRecord(value), false, nil
}

type fixture struct {
	now       time.Time
	catalog   *catalogStub
	registry  *registryStub
	authority *authorityStub
	retriever *retrieverStub
	store     *memoryStore
	control   *Controller
}

func newTestFixture(t *testing.T) fixture {
	t.Helper()
	now := time.Date(2026, 8, 26, 21, 0, 0, 0, time.UTC)
	results := map[string]skillregistry.ResolvedSkill{}
	entries := make([]skillregistry.PromotedSkillRef, 0, 3)
	for index, name := range []string{"alpha_skill", "beta_skill", "gamma_skill"} {
		manifest := testDigest("manifest-" + name)
		provenance := testDigest("provenance-" + name)
		resource := skillregistry.Resource{Name: "instructions", Digest: testDigest("resource-" + name),
			MediaType: "text/markdown", Classification: "internal", Length: int64(100 + index)}
		results[name] = skillregistry.ResolvedSkill{SkillName: name, SkillVersion: "1.0.0",
			ManifestDigest: manifest, ContentDigest: testDigest("content-" + name),
			Resources: []skillregistry.Resource{resource}, Permissions: []string{"evidence.read"},
			OwnerActorID: testOwner, ReviewID: testReview, ReviewRevision: 1,
			ProvenanceDigest: provenance}
		entries = append(entries, skillregistry.PromotedSkillRef{SkillName: name,
			ManifestDigest: manifest, StateRevision: 1, ProvenanceDigest: provenance})
	}
	catalog := &catalogStub{snapshot: skillregistry.CatalogSnapshot{
		SchemaVersion: skillregistry.CatalogSchemaVersion, ContractVersion: skillregistry.ContractVersion,
		OrganizationID: testOrg, TenantID: testTenant, Entries: entries,
		SnapshotDigest: testDigest("snapshot"), UpdatedAt: now, Revision: 1}}
	registry := &registryStub{results: results}
	authority := &authorityStub{now: now}
	retriever := &retrieverStub{}
	store := newMemoryStore()
	controller, err := New(catalog, registry, authority, retriever, store, testClock{now})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{now, catalog, registry, authority, retriever, store, controller}
}

func (fixture fixture) search() SearchRequest {
	return SearchRequest{SchemaVersion: SearchSchemaVersion, ContractVersion: ContractVersion,
		RequestID: testRequest, IdempotencyKey: "search-one", Case: testScope(), TaskID: testTask,
		ActorID: testActor, PolicyDigest: testDigest("policy"), RequiredPermission: "evidence.read",
		Limit: 2, Deadline: fixture.now.Add(time.Hour)}
}

func (fixture fixture) detail(name string) DetailRequest {
	parentKey := "parent-search-" + name
	resolved := fixture.registry.results[name]
	search := SearchResult{Skills: []CompactSkill{{SkillName: name, SkillVersion: resolved.SkillVersion,
		ManifestDigest: resolved.ManifestDigest, ProvenanceDigest: resolved.ProvenanceDigest}},
		SnapshotDigest: fixture.catalog.snapshot.SnapshotDigest}
	search.ResultDigest, _ = searchResultDigest(search)
	record, _ := newRecord(testScope(), testTask, testActor, testDigest("policy"), "evidence.read",
		CompactSearch, idempotencyDigest(parentKey),
		testDigest("parent-search-intent-"+name), []string{testDigest("parent-search-decision-" + name)},
		&search, nil, nil, fixture.now)
	fixture.store.records[memoryKey(testScope(), testTask, CompactSearch, record.IdempotencyDigest)] = record
	return DetailRequest{SchemaVersion: DetailSchemaVersion, ContractVersion: ContractVersion,
		RequestID: testRequest, IdempotencyKey: "detail-one", Case: testScope(), TaskID: testTask,
		ActorID: testActor, PolicyDigest: testDigest("policy"), RequiredPermission: "evidence.read",
		SkillName: name, ExpectedManifestDigest: resolved.ManifestDigest,
		SearchIdempotencyKey: parentKey, ExpectedSearchResultDigest: search.ResultDigest,
		Deadline: fixture.now.Add(time.Hour)}
}

func (fixture fixture) resource(name string) ResourceRequest {
	resolved := fixture.registry.results[name]
	resource := resolved.Resources[0]
	parentKey := "parent-detail-" + name
	detail := DetailResult{SkillName: resolved.SkillName, SkillVersion: resolved.SkillVersion,
		ManifestDigest: resolved.ManifestDigest, ContentDigest: resolved.ContentDigest,
		Resources:   append([]skillregistry.Resource(nil), resolved.Resources...),
		Permissions: append([]string(nil), resolved.Permissions...), OwnerActorID: resolved.OwnerActorID,
		ReviewID: resolved.ReviewID, ReviewRevision: resolved.ReviewRevision,
		ProvenanceDigest: resolved.ProvenanceDigest}
	detail.ResultDigest, _ = detailResultDigest(detail)
	record, _ := newRecord(testScope(), testTask, testActor, testDigest("policy"), "evidence.read",
		DetailExpand, idempotencyDigest(parentKey),
		testDigest("parent-detail-intent-"+name), []string{testDigest("parent-detail-decision-" + name)},
		nil, &detail, nil, fixture.now)
	fixture.store.records[memoryKey(testScope(), testTask, DetailExpand, record.IdempotencyDigest)] = record
	return ResourceRequest{SchemaVersion: ResourceSchemaVersion, ContractVersion: ContractVersion,
		RequestID: testRequest, IdempotencyKey: "resource-one", Case: testScope(), TaskID: testTask,
		ActorID: testActor, PolicyDigest: testDigest("policy"), RequiredPermission: "evidence.read",
		SkillName: name, ExpectedManifestDigest: resolved.ManifestDigest,
		ResourceName: resource.Name, ResourceDigest: resource.Digest,
		DetailIdempotencyKey: parentKey, ExpectedDetailResultDigest: detail.ResultDigest,
		Deadline: fixture.now.Add(time.Hour)}
}
