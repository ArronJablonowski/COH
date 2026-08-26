package broker

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/policy"
	"github.com/ArronJablonowski/COH/internal/policy/approvalfingerprint"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

const (
	organizationID = "0198d6c4-1111-7111-8111-111111111111"
	tenantID       = "0198d6c4-3333-7333-8333-333333333333"
	caseID         = "0198d6c4-4444-7444-8444-444444444444"
	requestorID    = "0198d6c4-2222-7222-8222-222222222222"
	ownerID        = "0198d6c4-5555-7555-8555-555555555555"
	approverID     = "0198d6c4-7777-7777-8777-777777777777"
	serviceID      = "0198d6c4-8888-7888-8888-888888888888"
	approvalID     = "0198d6c4-6666-7666-8666-666666666666"
)

var testTime = time.Date(2026, 8, 26, 1, 10, 0, 0, time.UTC)

func TestLifecycleSuccessReplayAndTerminalDenial(t *testing.T) {
	fixture := newServiceFixture(t)
	requested, err := fixture.service.requestApproval(context.Background(), requestCommand("request-1"))
	if err != nil || requested.Record.State != lifecycle.Requested || requested.Record.Revision != 1 {
		t.Fatalf("request = %+v, err=%v", requested, err)
	}
	replayed, err := fixture.service.requestApproval(context.Background(), requestCommand("request-1"))
	if err != nil || !replayed.Replayed || !reflect.DeepEqual(replayed.Record, requested.Record) {
		t.Fatalf("request replay = %+v, err=%v", replayed, err)
	}
	granted, err := fixture.service.grantApproval(context.Background(), transitionCommand("grant-1", 1, approver(), "approval_granted", true))
	if err != nil || granted.Record.State != lifecycle.Granted || len(granted.Record.Grants) != 1 {
		t.Fatalf("grant = %+v, err=%v", granted, err)
	}
	grantReplay, err := fixture.service.grantApproval(context.Background(), transitionCommand("grant-1", 1, approver(), "approval_granted", true))
	if err != nil || !grantReplay.Replayed || grantReplay.Record.Revision != 2 {
		t.Fatalf("grant replay = %+v, err=%v", grantReplay, err)
	}
	consumed, err := fixture.service.consumeApproval(context.Background(), transitionCommand("consume-1", 2, owner(), "approval_consumed", true))
	if err != nil || consumed.Record.State != lifecycle.Consumed || consumed.Record.UseCount != 1 {
		t.Fatalf("consume = %+v, err=%v", consumed, err)
	}
	_, err = fixture.service.consumeApproval(context.Background(), transitionCommand("consume-2", 3, owner(), "approval_consumed", true))
	if lifecycle.Code(err) != lifecycle.Denied {
		t.Fatalf("terminal consume err=%v", err)
	}
	if len(fixture.store.outbox) != 3 || len(fixture.audit.events) != 1 {
		t.Fatalf("outbox=%d denied_audit=%d", len(fixture.store.outbox), len(fixture.audit.events))
	}
}

func TestLifecycleDispositionTransitions(t *testing.T) {
	for _, test := range []struct {
		name       string
		operation  func(*approvalService, context.Context, approvalTransitionCommand) (approvalResult, error)
		actor      policy.ActorAuthority
		state      lifecycle.State
		afterGrant bool
		expired    bool
	}{
		{name: "reject", operation: (*approvalService).rejectApproval, actor: approver(), state: lifecycle.Rejected},
		{name: "revoke requested", operation: (*approvalService).revokeApproval, actor: approver(), state: lifecycle.Revoked},
		{name: "revoke granted", operation: (*approvalService).revokeApproval, actor: approver(), state: lifecycle.Revoked, afterGrant: true},
		{name: "expire", operation: (*approvalService).expireApproval, actor: serviceActor(), state: lifecycle.Expired, expired: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			if _, err := fixture.service.requestApproval(context.Background(), requestCommand("request-"+test.name)); err != nil {
				t.Fatal(err)
			}
			revision := uint64(1)
			if test.afterGrant {
				if _, err := fixture.service.grantApproval(context.Background(), transitionCommand("grant-"+test.name, 1, approver(), "approval_granted", true)); err != nil {
					t.Fatal(err)
				}
				revision = 2
			}
			if test.expired {
				fixture.clock.now = testTime.Add(time.Hour)
			}
			command := transitionCommand(test.name+"-1", revision, test.actor, "approval_"+string(test.state), false)
			result, err := test.operation(fixture.service, context.Background(), command)
			if err != nil || result.Record.State != test.state {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestConcurrentConsumeAllowsExactlyOneUse(t *testing.T) {
	fixture := newServiceFixture(t)
	_, _ = fixture.service.requestApproval(context.Background(), requestCommand("request-race"))
	_, _ = fixture.service.grantApproval(context.Background(), transitionCommand("grant-race", 1, approver(), "approval_granted", true))
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func(key string) {
			defer wait.Done()
			<-start
			_, err := fixture.service.consumeApproval(context.Background(), transitionCommand(key, 2, owner(), "approval_consumed", true))
			results <- err
		}("consume-race-" + string(rune('a'+index)))
	}
	close(start)
	wait.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if lifecycle.Code(err) == lifecycle.Conflict {
			conflicts++
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestDenialsCancellationAndAuditFailure(t *testing.T) {
	fixture := newServiceFixture(t)
	selfActor := requestor()
	selfActor.Permissions = []string{"action.request", "approval.decide"}
	self := transitionCommand("self", 1, selfActor, "approval_granted", true)
	_, _ = fixture.service.requestApproval(context.Background(), requestCommand("request-denials"))
	if _, err := fixture.service.grantApproval(context.Background(), self); lifecycle.Reason(err) != "self_approval" {
		t.Fatalf("self approval err=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.service.rejectApproval(canceled, transitionCommand("cancel", 1, approver(), "approval_rejected", false)); lifecycle.Code(err) != lifecycle.Canceled {
		t.Fatalf("cancellation err=%v", err)
	}
	fixture.audit.fail = true
	if _, err := fixture.service.rejectApproval(context.Background(), transitionCommand("stale", 9, approver(), "approval_rejected", false)); lifecycle.Reason(err) != "audit_unavailable" {
		t.Fatalf("audit failure err=%v", err)
	}
}

func TestFingerprintDenialScopeBindingAndAuditRedaction(t *testing.T) {
	fixture := newServiceFixture(t)
	badScope := requestCommand("scope-mismatch")
	badScope.Requestor.TenantID = "0198d6c4-9999-7999-8999-999999999999"
	if _, err := fixture.service.requestApproval(context.Background(), badScope); lifecycle.Reason(err) != "actor_scope_mismatch" {
		t.Fatalf("scope mismatch err=%v", err)
	}
	invalid := requestCommand("invalid")
	invalid.ApprovalID = "raw-secret-approval"
	invalid.Requestor.ActorID = "raw-secret-actor"
	invalid.approvalProof.Fingerprint.OrganizationID = "raw-secret-organization"
	if _, err := fixture.service.requestApproval(context.Background(), invalid); lifecycle.Code(err) != lifecycle.InvalidInput {
		t.Fatalf("invalid request err=%v", err)
	}
	last := fixture.audit.events[len(fixture.audit.events)-1]
	if last.ApprovalID != "" || last.ActorID != "" || last.OrganizationID != "" {
		t.Fatalf("unsafe audit identifiers: %+v", last)
	}
	store, audit, clock := &memoryStore{records: make(map[string]workflow.MetadataRecord)}, &memoryAudit{}, &fakeClock{now: testTime}
	denied, err := newApprovalServiceWithDependencies(store, denyingVerifier{}, audit, clock, &sequenceReader{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := denied.requestApproval(context.Background(), requestCommand("fingerprint-denied")); lifecycle.Reason(err) != "fingerprint_authority" {
		t.Fatalf("fingerprint denial err=%v", err)
	}
}

type serviceFixture struct {
	service *approvalService
	store   *memoryStore
	audit   *memoryAudit
	clock   *fakeClock
}

func newServiceFixture(t *testing.T) serviceFixture {
	t.Helper()
	store, audit, clock := &memoryStore{records: make(map[string]workflow.MetadataRecord)}, &memoryAudit{}, &fakeClock{now: testTime}
	service, err := newApprovalServiceWithDependencies(store, fakeVerifier{}, audit, clock, &sequenceReader{})
	if err != nil {
		t.Fatal(err)
	}
	return serviceFixture{service: service, store: store, audit: audit, clock: clock}
}

func requestCommand(key string) approvalRequestCommand {
	return approvalRequestCommand{ApprovalID: approvalID, IdempotencyKey: key, Requestor: requestor(), approvalProof: proof()}
}

func transitionCommand(key string, revision uint64, actor policy.ActorAuthority, reason string, withProof bool) approvalTransitionCommand {
	command := approvalTransitionCommand{ApprovalID: approvalID, IdempotencyKey: key, ExpectedRevision: revision,
		Case: domain.CaseRef{OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID}, Actor: actor, ReasonCode: reason}
	if withProof {
		value := proof()
		command.approvalProof = &value
	}
	return command
}

func proof() approvalProof {
	return approvalProof{Fingerprint: approvalfingerprint.Fingerprint{SchemaVersion: approvalfingerprint.SchemaVersion,
		ContractVersion:      approvalfingerprint.ContractVersion,
		FingerprintDigest:    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ManifestDigest:       "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		PolicyDecisionDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		OrganizationID:       organizationID, TenantID: tenantID, CaseID: caseID, RequestorActorID: requestorID,
		ActionOwnerActorID: ownerID, ValidFrom: "2026-08-26T01:00:00.000000000Z",
		ValidUntil: "2026-08-26T02:00:00.000000000Z", MaximumUseCount: 1}}
}

func actor(id, permission string) policy.ActorAuthority {
	return policy.ActorAuthority{ActorID: id, OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID,
		Revision: 4, Active: true, Roles: []string{"analyst"}, Permissions: []string{permission}}
}

func requestor() policy.ActorAuthority    { return actor(requestorID, "action.request") }
func owner() policy.ActorAuthority        { return actor(ownerID, "action.request") }
func approver() policy.ActorAuthority     { return actor(approverID, "approval.decide") }
func serviceActor() policy.ActorAuthority { return actor(serviceID, "service.invoke") }

type fakeVerifier struct{}

func (fakeVerifier) Verify(_ context.Context, candidate approvalfingerprint.Fingerprint, _ actionmanifest.VerifiedEnvelope,
	_ actionmanifest.SignerAuthority, _ policy.Decision) (approvalfingerprint.Fingerprint, error) {
	return candidate, nil
}

type denyingVerifier struct{}

func (denyingVerifier) Verify(context.Context, approvalfingerprint.Fingerprint, actionmanifest.VerifiedEnvelope,
	actionmanifest.SignerAuthority, policy.Decision) (approvalfingerprint.Fingerprint, error) {
	return approvalfingerprint.Fingerprint{}, errors.New("signer revoked")
}

type fakeClock struct{ now time.Time }

func (clock *fakeClock) Now() time.Time { return clock.now }

type sequenceReader struct {
	mu   sync.Mutex
	next byte
}

func (reader *sequenceReader) Read(value []byte) (int, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.next++
	for index := range value {
		value[index] = reader.next
	}
	return len(value), nil
}

type memoryAudit struct {
	mu     sync.Mutex
	events []lifecycle.Event
	fail   bool
}

func (audit *memoryAudit) AppendApprovalLifecycleEvent(_ context.Context, event lifecycle.Event) error {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	if audit.fail {
		return errors.New("audit down")
	}
	audit.events = append(audit.events, event)
	return nil
}

type memoryStore struct {
	mu      sync.Mutex
	records map[string]workflow.MetadataRecord
	outbox  []workflow.OutboxMessage
}

func (store *memoryStore) Get(ctx context.Context, key workflow.RecordKey) (workflow.MetadataRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return workflow.MetadataRecord{}, err
	}
	record, exists := store.records[key.ID]
	if !exists {
		return workflow.MetadataRecord{}, workflow.NewStorageError(workflow.StorageNotFound, "get", "key", "not found", nil)
	}
	return record, nil
}

func (store *memoryStore) Transact(ctx context.Context, transaction workflow.Transaction) (workflow.CommitResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return workflow.CommitResult{}, err
	}
	mutation := transaction.Mutations[0]
	current, exists := store.records[mutation.Key.ID]
	if (!exists && mutation.ExpectedRevision != 0) || (exists && current.Revision != mutation.ExpectedRevision) {
		return workflow.CommitResult{}, workflow.NewStorageError(workflow.StorageConflict, "transact", "revision", "conflict", nil)
	}
	store.records[mutation.Key.ID] = *mutation.Record
	store.outbox = append(store.outbox, transaction.Outbox...)
	return workflow.CommitResult{IdempotencyKey: transaction.IdempotencyKey,
		RecordVersions: map[string]uint64{mutation.Key.ID: mutation.Record.Revision}, OutboxIDs: []string{transaction.Outbox[0].ID}}, nil
}
