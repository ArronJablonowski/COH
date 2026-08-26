package retrievalguard

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

const (
	testOrg      = "0198d6c4-1001-7001-8001-000000000001"
	testTenant   = "0198d6c4-1002-7002-8002-000000000002"
	testCase     = "0198d6c4-1003-7003-8003-000000000003"
	testTask     = "0198d6c4-1004-7004-8004-000000000004"
	testActor    = "0198d6c4-1005-7005-8005-000000000005"
	testRequest  = "0198d6c4-1006-7006-8006-000000000006"
	testDecision = "0198d6c4-1007-7007-8007-000000000007"
)

var testNow = time.Now().UTC().Add(time.Hour).Truncate(time.Second)

type testClock struct{ now time.Time }

func (clock *testClock) Now() time.Time { return clock.now }

type authorityStub struct {
	mu     sync.Mutex
	clock  *testClock
	allow  bool
	tamper bool
	err    error
	calls  int
	last   AuthorizationRequest
}

func (authority *authorityStub) AuthorizeRetrieval(_ context.Context, request AuthorizationRequest) (Decision, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.calls++
	authority.last = request
	if authority.err != nil {
		return Decision{}, authority.err
	}
	outcome, reason := "deny", "policy_denied"
	if authority.allow {
		outcome, reason = "allow", "inspection_allowed"
	}
	decision := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion, DecisionID: testDecision, RequestDigest: request.RequestDigest, Case: request.Case, TaskID: request.TaskID, ActorID: request.ActorID, ActorRevision: request.ActorRevision, PolicyDigest: request.PolicyDigest, RevocationDigest: digest("revocation", nil), Outcome: outcome, ReasonCode: reason, Revision: 1, IssuedAt: authority.clock.now.Add(-time.Minute), ExpiresAt: authority.clock.now.Add(time.Minute)}
	decision.DecisionDigest, _ = DecisionBindingDigest(decision)
	if authority.tamper {
		decision.RequestDigest = digest("tampered", nil)
	}
	return decision, nil
}

type inspectorStub struct {
	result  InspectionResult
	err     error
	calls   int
	request InspectionRequest
}

func (inspector *inspectorStub) Inspect(_ context.Context, request InspectionRequest) (InspectionResult, error) {
	inspector.calls++
	inspector.request = request
	return cloneInspection(inspector.result), inspector.err
}

type verifierStub struct {
	err   error
	calls int
}

func (verifier *verifierStub) VerifyArtifact(context.Context, domain.ArtifactRef) error {
	verifier.calls++
	return verifier.err
}

type auditorStub struct {
	mu     sync.Mutex
	err    error
	events map[string]tamperaudit.Event
	calls  int
}

func (auditor *auditorStub) AppendAuditEvent(_ context.Context, event tamperaudit.Event) error {
	auditor.mu.Lock()
	defer auditor.mu.Unlock()
	auditor.calls++
	if auditor.err != nil {
		return auditor.err
	}
	if prior, ok := auditor.events[event.EventID]; ok && !reflect.DeepEqual(prior, event) {
		return errors.New("changed audit replay")
	}
	auditor.events[event.EventID] = event
	return nil
}

type memoryStore struct {
	mu      sync.Mutex
	records map[string]Record
	lost    bool
	calls   int
}

func (store *memoryStore) Load(ctx context.Context, scope domain.CaseRef, task, idempotency string) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.records[scope.CaseID+"\x00"+task+"\x00"+idempotency]
	return cloneRecord(value), ok, nil
}
func (store *memoryStore) Commit(ctx context.Context, _ string, value Record) (Record, bool, error) {
	if err := contextError(ctx); err != nil {
		return Record{}, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls++
	key := value.Request.Case.CaseID + "\x00" + value.Request.TaskID + "\x00" + value.IdempotencyDigest
	if prior, ok := store.records[key]; ok {
		if prior.IntentDigest != value.IntentDigest {
			return Record{}, false, newError(Denied, "changed_replay", false, nil)
		}
		return cloneRecord(prior), true, nil
	}
	store.records[key] = cloneRecord(value)
	if store.lost {
		store.lost = false
		return Record{}, false, newError(Unavailable, "lost_response", true, nil)
	}
	return cloneRecord(value), false, nil
}

func validProfile() InspectionProfile {
	value := InspectionProfile{Name: "strict_data", Revision: 1, MaximumBytes: 1 << 20, AllowedMediaTypes: []string{"application/json", "text/plain"}, DenyActiveFormats: true, RedactSecrets: true, NeutralizeDirectives: true}
	value.ProfileDigest, _ = ProfileBindingDigest(value)
	return value
}
func validRequest(now time.Time) Request {
	return Request{SchemaVersion: RequestSchemaVersion, ContractVersion: ContractVersion, RequestID: testRequest, IdempotencyKey: "inspect-1", Case: domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase}, TaskID: testTask, ActorID: testActor, ActorRevision: 3, Source: Source{Kind: DocumentSource, Artifact: domain.ArtifactRef{Digest: digest("hostile-source", nil), MediaType: "text/plain", Classification: "restricted", Length: 512}, Trust: UntrustedContent, ProvenanceDigest: digest("source-provenance", nil)}, Profile: validProfile(), PolicyDigest: digest("policy", nil), Deadline: now.Add(time.Hour)}
}
func validInspection(request Request) InspectionResult {
	findings := []Finding{{Code: InstructionLike, Count: 2}, {Code: SecretRedacted, Count: 1}}
	bound, _ := FindingsBindingDigest(findings)
	return InspectionResult{SourceDigest: request.Source.Artifact.Digest, SourceProvenanceDigest: request.Source.ProvenanceDigest, Sanitized: domain.ArtifactRef{Digest: digest("sanitized", nil), MediaType: "application/json", Classification: request.Source.Artifact.Classification, Length: 256}, Trust: UntrustedContent, Findings: findings, FindingsDigest: bound, RedactionCount: 1, Complete: true, InspectorDigest: digest("inspector", nil)}
}
func newFixture() (*Controller, *testClock, *authorityStub, *inspectorStub, *verifierStub, *auditorStub, *memoryStore) {
	clock := &testClock{testNow}
	request := validRequest(clock.now)
	authority := &authorityStub{clock: clock, allow: true}
	inspector := &inspectorStub{result: validInspection(request)}
	verifier := &verifierStub{}
	auditor := &auditorStub{events: map[string]tamperaudit.Event{}}
	store := &memoryStore{records: map[string]Record{}}
	controller, _ := New(authority, inspector, verifier, auditor, store, clock)
	return controller, clock, authority, inspector, verifier, auditor, store
}
