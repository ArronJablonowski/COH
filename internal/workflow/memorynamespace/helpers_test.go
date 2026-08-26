package memorynamespace

import (
	"context"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const (
	testOrg      = "0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e"
	testTenant   = "0198d6c4-22dc-7b3c-af2c-75c1b8eb4f16"
	testCase     = "0198d6c4-7618-7d31-8e0a-9da53cae8ca2"
	testSession  = "0198d6c4-1111-7111-8111-111111111111"
	testActor    = "0198d6c4-2222-7222-8222-222222222222"
	testReviewer = "0198d6c4-3333-7333-8333-333333333333"
	testRequest  = "0198d6c4-4444-7444-8444-444444444444"
)

var testNow = time.Now().UTC().Add(time.Hour).Truncate(time.Second)

type testClock struct{ now time.Time }

func (clock *testClock) Now() time.Time { return clock.now }

type testAuthority struct {
	mu     sync.Mutex
	now    *testClock
	allow  bool
	tamper bool
	err    error
	calls  int
}

func (authority *testAuthority) AuthorizeMemory(_ context.Context, request AccessRequest) (Decision, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.calls++
	if authority.err != nil {
		return Decision{}, authority.err
	}
	bound, _ := AccessDigest(request)
	decision := Decision{SchemaVersion: AccessSchemaVersion, ContractVersion: ContractVersion,
		Allowed: authority.allow, ReasonCode: "memory_allowed", AccessRequestDigest: bound,
		DecidedAt: authority.now.now, ExpiresAt: authority.now.now.Add(time.Minute)}
	if !authority.allow {
		decision.ReasonCode = "memory_denied"
	}
	decision.DecisionDigest, _ = DecisionBindingDigest(decision)
	if authority.tamper {
		decision.AccessRequestDigest = digest("tampered", nil)
	}
	return decision, nil
}

type testReviewAuthority struct {
	now   *testClock
	allow bool
	err   error
	calls int
}

func (authority *testReviewAuthority) AuthorizeReview(_ context.Context, request ReviewRequest) (ReviewDecision, error) {
	authority.calls++
	if authority.err != nil {
		return ReviewDecision{}, authority.err
	}
	bound, _ := ReviewDigest(request)
	expires := authority.now.now.Add(time.Minute)
	if expires.After(request.Review.ValidUntil) {
		expires = request.Review.ValidUntil
	}
	decision := ReviewDecision{SchemaVersion: ReviewSchemaVersion, ContractVersion: ContractVersion,
		Allowed: authority.allow, ReasonCode: "review_allowed", ReviewRequestDigest: bound,
		DecidedAt: authority.now.now, ExpiresAt: expires}
	if !authority.allow {
		decision.ReasonCode = "review_revoked"
	}
	decision.DecisionDigest, _ = ReviewDecisionBindingDigest(decision)
	return decision, nil
}

type memoryStore struct {
	mu        sync.Mutex
	namespace Namespace
	current   map[string]Record
	receipts  map[string]Record
	tamper    bool
}

func newMemoryStore(namespace Namespace) *memoryStore {
	return &memoryStore{namespace: namespace, current: map[string]Record{}, receipts: map[string]Record{}}
}
func (store *memoryStore) Namespace() Namespace { return store.namespace }
func (store *memoryStore) Load(ctx context.Context, scope Scope, key string) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.current[scopeIdentity(store.namespace, scope)+"\x00"+key]
	if ok && store.tamper {
		value.ProvenanceDigest = digest("tampered", nil)
	}
	return cloneRecord(value), ok, nil
}
func (store *memoryStore) Recover(ctx context.Context, scope Scope, key, idempotency string) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.receipts[scopeIdentity(store.namespace, scope)+"\x00"+key+"\x00"+idempotency]
	return cloneRecord(value), ok, nil
}
func (store *memoryStore) Commit(ctx context.Context, _ string, intent string, expected uint64, value Record) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	base := scopeIdentity(store.namespace, value.Scope) + "\x00" + value.Key
	receipt := base + "\x00" + value.IdempotencyDigest
	if prior, ok := store.receipts[receipt]; ok {
		if prior.IntentDigest != intent {
			return Record{}, false, newError(Denied, "changed_replay", false, nil)
		}
		return cloneRecord(prior), true, nil
	}
	current, found := store.current[base]
	if (!found && expected != 0) || (found && current.Revision != expected) {
		return Record{}, false, newError(Conflict, "stale_revision", false, nil)
	}
	store.current[base], store.receipts[receipt] = cloneRecord(value), cloneRecord(value)
	return cloneRecord(value), false, nil
}

func scopeFor(namespace Namespace) Scope {
	switch namespace {
	case SessionMemory:
		return Scope{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase, SessionID: testSession, SubjectActorID: testActor}
	case CaseMemory:
		return Scope{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase}
	case AnalystPreferenceMemory:
		return Scope{OrganizationID: testOrg, TenantID: testTenant, SubjectActorID: testActor}
	default:
		return Scope{OrganizationID: testOrg, TenantID: testTenant}
	}
}

func retentionFor(namespace Namespace, now time.Time) RetentionPolicy {
	class, _ := retentionBoundary(namespace)
	return RetentionPolicy{Class: class, PolicyDigest: digest("retention", []byte(namespace)), ExpiresAt: now.Add(2 * time.Hour)}
}

func validPut(namespace Namespace, now time.Time) PutRequest {
	request := PutRequest{SchemaVersion: PutSchemaVersion, ContractVersion: ContractVersion,
		RequestID: testRequest, IdempotencyKey: "write-1", ActorID: testActor, Namespace: namespace,
		Scope: scopeFor(namespace), Key: "investigation.summary", Value: domain.ArtifactRef{Digest: digest("artifact", []byte(namespace)), MediaType: "application/json", Classification: "restricted", Length: 128},
		ValueType: map[Namespace]string{SessionMemory: "session_state_reference", CaseMemory: "case_memory_reference",
			AnalystPreferenceMemory: "analyst_preference_reference", ReviewedOrganizationMemory: "reviewed_organization_reference"}[namespace],
		Retention: retentionFor(namespace, now), PolicyDigest: digest("policy", nil), Deadline: now.Add(time.Hour)}
	if namespace == ReviewedOrganizationMemory {
		request.Review = Review{ReviewID: testSession, ReviewerActorID: testReviewer, Revision: 1,
			AuthorityDigest: digest("review-authority", nil), ReviewedAt: now.Add(-time.Hour), ValidUntil: now.Add(30 * time.Minute)}
	}
	return request
}

func validGet(put PutRequest, now time.Time) GetRequest {
	return GetRequest{SchemaVersion: GetSchemaVersion, ContractVersion: ContractVersion,
		RequestID: testRequest, ActorID: put.ActorID, Namespace: put.Namespace, Scope: put.Scope, Key: put.Key, PolicyDigest: put.PolicyDigest, Deadline: now.Add(time.Hour)}
}

func newControllerForTest(clock *testClock) (*Controller, *testAuthority, *testReviewAuthority, map[Namespace]*memoryStore) {
	stores := map[Namespace]*memoryStore{SessionMemory: newMemoryStore(SessionMemory), CaseMemory: newMemoryStore(CaseMemory), AnalystPreferenceMemory: newMemoryStore(AnalystPreferenceMemory), ReviewedOrganizationMemory: newMemoryStore(ReviewedOrganizationMemory)}
	authority := &testAuthority{now: clock, allow: true}
	reviews := &testReviewAuthority{now: clock, allow: true}
	controller, _ := New(stores[SessionMemory], stores[CaseMemory], stores[AnalystPreferenceMemory], stores[ReviewedOrganizationMemory], authority, reviews, clock)
	return controller, authority, reviews, stores
}
