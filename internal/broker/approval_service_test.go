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
	organizationID       = "0198d6c4-1111-7111-8111-111111111111"
	tenantID             = "0198d6c4-3333-7333-8333-333333333333"
	caseID               = "0198d6c4-4444-7444-8444-444444444444"
	requestorID          = "0198d6c4-2222-7222-8222-222222222222"
	ownerID              = "0198d6c4-5555-7555-8555-555555555555"
	approverID           = "0198d6c4-7777-7777-8777-777777777777"
	secondApproverID     = "0198d6c4-9999-7999-8999-999999999999"
	requestorPrincipalID = "0198d6c4-aaaa-7aaa-8aaa-aaaaaaaaaaaa"
	approverPrincipalID  = "0198d6c4-bbbb-7bbb-8bbb-bbbbbbbbbbbb"
	secondPrincipalID    = "0198d6c4-cccc-7ccc-8ccc-cccccccccccc"
	serviceID            = "0198d6c4-8888-7888-8888-888888888888"
	approvalID           = "0198d6c4-6666-7666-8666-666666666666"
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

func TestT4RequiresTwoDistinctEnrolledHumanPrincipals(t *testing.T) {
	fixture := newServiceFixtureTier(t, "T4")
	requested, err := fixture.service.requestApproval(context.Background(), requestCommand("t4-request"))
	if err != nil || requested.Record.RequiredGrantCount != 2 || requested.Record.ActionTier != "T4" {
		t.Fatalf("T4 request=%+v err=%v", requested, err)
	}
	first, err := fixture.service.grantApproval(context.Background(), transitionCommand("t4-first", 1, approver(), "approval_granted", true))
	if err != nil || first.Record.State != lifecycle.Requested || len(first.Record.Grants) != 1 {
		t.Fatalf("first grant=%+v err=%v", first, err)
	}
	premature := transitionCommand("t4-premature", 2, owner(), "approval_consumed", true)
	if _, err := fixture.service.consumeApproval(context.Background(), premature); lifecycle.Reason(err) != "approval_not_current" {
		t.Fatalf("premature consume err=%v", err)
	}
	secondActor := secondApprover()
	second, err := fixture.service.grantApproval(context.Background(), transitionCommand("t4-second", 2, secondActor, "approval_granted", true))
	if err != nil || second.Record.State != lifecycle.Granted || len(second.Record.Grants) != 2 {
		t.Fatalf("second grant=%+v err=%v", second, err)
	}
	secondReplay, err := fixture.service.grantApproval(context.Background(), transitionCommand("t4-second", 2, secondActor, "approval_granted", true))
	if err != nil || !secondReplay.Replayed || secondReplay.Record.Revision != 3 {
		t.Fatalf("second replay=%+v err=%v", secondReplay, err)
	}
	consume := transitionCommand("t4-consume", 3, owner(), "approval_consumed", true)
	consume.GrantAuthorities = []approvalGrantAuthority{
		grantAuthority(approver(), approverPrincipalID), grantAuthority(secondActor, secondPrincipalID),
	}
	consumed, err := fixture.service.consumeApproval(context.Background(), consume)
	if err != nil || consumed.Record.State != lifecycle.Consumed {
		t.Fatalf("T4 consume=%+v err=%v", consumed, err)
	}
}

func TestT4ConcurrentFirstGrantsSerialize(t *testing.T) {
	fixture := newServiceFixtureTier(t, "T4")
	_, _ = fixture.service.requestApproval(context.Background(), requestCommand("t4-race-request"))
	commands := []approvalTransitionCommand{
		transitionCommand("t4-race-first", 1, approver(), "approval_granted", true),
		transitionCommand("t4-race-second", 1, secondApprover(), "approval_granted", true),
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, command := range commands {
		wait.Add(1)
		go func(value approvalTransitionCommand) {
			defer wait.Done()
			<-start
			_, err := fixture.service.grantApproval(context.Background(), value)
			results <- err
		}(command)
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
	stored, err := fixture.store.Get(context.Background(), recordKey(organizationID, tenantID, caseID, approvalID))
	if err != nil || stored.Revision != 2 {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	record, err := decodeMetadata(stored)
	if err != nil || record.State != lifecycle.Requested || len(record.Grants) != 1 {
		t.Fatalf("record=%+v err=%v", record, err)
	}
}

func TestT4DeniesAliasServiceAndUnenrolledApprovers(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*approvalTransitionCommand)
		reason string
	}{
		{name: "same human alias", reason: "invalid_grants", mutate: func(command *approvalTransitionCommand) {
			command.Principal.PrincipalID = approverPrincipalID
		}},
		{name: "requestor alias", reason: "self_approval", mutate: func(command *approvalTransitionCommand) {
			command.Principal.PrincipalID = requestorPrincipalID
		}},
		{name: "service identity", reason: "approver_ineligible", mutate: func(command *approvalTransitionCommand) {
			command.Principal.IdentityKind = "service"
		}},
		{name: "unenrolled", reason: "approver_ineligible", mutate: func(command *approvalTransitionCommand) {
			command.Principal.Enrolled = false
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixtureTier(t, "T4")
			_, _ = fixture.service.requestApproval(context.Background(), requestCommand("t4-request-"+test.name))
			_, _ = fixture.service.grantApproval(context.Background(), transitionCommand("t4-first-"+test.name, 1, approver(), "approval_granted", true))
			command := transitionCommand("t4-second-"+test.name, 2, secondApprover(), "approval_granted", true)
			test.mutate(&command)
			if _, err := fixture.service.grantApproval(context.Background(), command); lifecycle.Reason(err) != test.reason {
				t.Fatalf("err=%v want=%s", err, test.reason)
			}
		})
	}
}

func TestT4ConsumptionRevalidatesBothEnrollments(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*approvalTransitionCommand)
		reason string
	}{
		{name: "missing second", reason: "approver_enrollment_incomplete", mutate: func(command *approvalTransitionCommand) {
			command.GrantAuthorities = command.GrantAuthorities[:1]
		}},
		{name: "unenrolled", reason: "approver_ineligible", mutate: func(command *approvalTransitionCommand) {
			command.GrantAuthorities[1].Principal.Enrolled = false
		}},
		{name: "revoked", reason: "actor_revoked", mutate: func(command *approvalTransitionCommand) {
			command.GrantAuthorities[1].Actor.Active = false
		}},
		{name: "stale enrollment", reason: "approver_authority_changed", mutate: func(command *approvalTransitionCommand) {
			command.GrantAuthorities[1].Principal.EnrollmentRevision = 1
		}},
		{name: "principal changed", reason: "approver_authority_changed", mutate: func(command *approvalTransitionCommand) {
			command.GrantAuthorities[1].Principal.PrincipalID = "0198d6c4-dddd-7ddd-8ddd-dddddddddddd"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixtureTier(t, "T4")
			_, _ = fixture.service.requestApproval(context.Background(), requestCommand("t4-revalidate-request-"+test.name))
			_, _ = fixture.service.grantApproval(context.Background(), transitionCommand("t4-revalidate-first-"+test.name, 1, approver(), "approval_granted", true))
			_, _ = fixture.service.grantApproval(context.Background(), transitionCommand("t4-revalidate-second-"+test.name, 2, secondApprover(), "approval_granted", true))
			consume := transitionCommand("t4-revalidate-consume-"+test.name, 3, owner(), "approval_consumed", true)
			consume.GrantAuthorities = []approvalGrantAuthority{
				grantAuthority(approver(), approverPrincipalID), grantAuthority(secondApprover(), secondPrincipalID),
			}
			test.mutate(&consume)
			if _, err := fixture.service.consumeApproval(context.Background(), consume); lifecycle.Reason(err) != test.reason {
				t.Fatalf("consume err=%v want=%s", err, test.reason)
			}
		})
	}
}

type serviceFixture struct {
	service *approvalService
	store   *memoryStore
	audit   *memoryAudit
	clock   *fakeClock
}

func newServiceFixture(t *testing.T) serviceFixture {
	return newServiceFixtureTier(t, "T2")
}

func newServiceFixtureTier(t *testing.T, tier string) serviceFixture {
	t.Helper()
	store, audit, clock := &memoryStore{records: make(map[string]workflow.MetadataRecord)}, &memoryAudit{}, &fakeClock{now: testTime}
	service, err := newApprovalServiceWithDependencies(store, fakeVerifier{tier: tier}, audit, clock, &sequenceReader{})
	if err != nil {
		t.Fatal(err)
	}
	return serviceFixture{service: service, store: store, audit: audit, clock: clock}
}

func requestCommand(key string) approvalRequestCommand {
	actor := requestor()
	return approvalRequestCommand{ApprovalID: approvalID, IdempotencyKey: key, Requestor: actor,
		Principal: principal(actor, requestorPrincipalID), approvalProof: proof()}
}

func transitionCommand(key string, revision uint64, actor policy.ActorAuthority, reason string, withProof bool) approvalTransitionCommand {
	command := approvalTransitionCommand{ApprovalID: approvalID, IdempotencyKey: key, ExpectedRevision: revision,
		Case: domain.CaseRef{OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID}, Actor: actor, ReasonCode: reason}
	if contains(actor.Permissions, "approval.decide") {
		value := principal(actor, principalIDForActor(actor.ActorID))
		command.Principal = &value
	}
	if contains(actor.Permissions, "action.request") && actor.ActorID == ownerID {
		command.GrantAuthorities = []approvalGrantAuthority{grantAuthority(approver(), approverPrincipalID)}
	}
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
	role := "analyst"
	if permission == "approval.decide" {
		role = "approver"
	} else if permission == "service.invoke" {
		role = "service"
	}
	return policy.ActorAuthority{ActorID: id, OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID,
		Revision: 4, Active: true, Roles: []string{role}, Permissions: []string{permission}}
}

func principal(actor policy.ActorAuthority, principalID string) approvalPrincipalAuthority {
	return approvalPrincipalAuthority{ActorID: actor.ActorID, ActorRevision: actor.Revision, PrincipalID: principalID,
		IdentityKind: "human", EnrollmentRevision: 2, Enrolled: true}
}

func grantAuthority(actor policy.ActorAuthority, principalID string) approvalGrantAuthority {
	return approvalGrantAuthority{Actor: actor, Principal: principal(actor, principalID)}
}

func requestor() policy.ActorAuthority      { return actor(requestorID, "action.request") }
func owner() policy.ActorAuthority          { return actor(ownerID, "action.request") }
func approver() policy.ActorAuthority       { return actor(approverID, "approval.decide") }
func secondApprover() policy.ActorAuthority { return actor(secondApproverID, "approval.decide") }
func serviceActor() policy.ActorAuthority   { return actor(serviceID, "service.invoke") }

func principalIDForActor(actorID string) string {
	if actorID == secondApproverID {
		return secondPrincipalID
	}
	return approverPrincipalID
}

type fakeVerifier struct{ tier string }

func (verifier fakeVerifier) verifyApproval(_ context.Context, candidate approvalfingerprint.Fingerprint, _ actionmanifest.VerifiedEnvelope,
	_ actionmanifest.SignerAuthority, _ policy.Decision) (approvalVerifiedProof, error) {
	tier := verifier.tier
	if tier == "" {
		tier = "T2"
	}
	return approvalVerifiedProof{Fingerprint: candidate, ActionTier: tier}, nil
}

type denyingVerifier struct{}

func (denyingVerifier) verifyApproval(context.Context, approvalfingerprint.Fingerprint, actionmanifest.VerifiedEnvelope,
	actionmanifest.SignerAuthority, policy.Decision) (approvalVerifiedProof, error) {
	return approvalVerifiedProof{}, errors.New("signer revoked")
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
