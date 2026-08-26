package caselifecycle

import (
	"context"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

const (
	testOrg       = "0199a213-3001-7001-8001-000000000001"
	testTenant    = "0199a213-3002-7002-8002-000000000002"
	testCase      = "0199a213-3003-7003-8003-000000000003"
	testActor     = "0199a213-3004-7004-8004-000000000004"
	testAssignee  = "0199a213-3005-7005-8005-000000000005"
	testRetention = "0199a213-3006-7006-8006-000000000006"
	testRequest   = "0199a213-3007-7007-8007-000000000007"
	testDecision  = "0199a213-3008-7008-8008-000000000008"
)

var testNow = time.Now().UTC().Add(time.Hour).Truncate(time.Second)

func validCreateCommand() Command {
	classification, assignee, retention := Internal, testAssignee, testRetention
	retainUntil := testNow.Add(24 * time.Hour)
	return Command{SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion,
		RequestID: testRequest, IdempotencyKey: "case-create-1", Operation: Create,
		Case:    domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase},
		ActorID: testActor, ActorRevision: 2, TargetClassification: &classification,
		AssigneeActorID: &assignee, RetentionPolicyID: &retention, RetainUntil: &retainUntil,
		PolicyDigest: testDigest("policy"), Deadline: testNow.Add(time.Hour)}
}

func validAuthorization(command Command) AuthorizationRequest {
	intent, _ := CommandBindingDigest(command)
	value := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: intent, Command: cloneCommand(command)}
	value.AuthorizationDigest, _ = AuthorizationBindingDigest(value)
	return value
}

func validDecision(command Command, authorization AuthorizationRequest) Decision {
	value := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID: testDecision, AuthorizationDigest: authorization.AuthorizationDigest,
		IntentDigest: authorization.IntentDigest, Operation: command.Operation, Case: command.Case,
		ActorID: command.ActorID, ActorRevision: command.ActorRevision, ExpectedRevision: command.ExpectedRevision,
		PolicyDigest: command.PolicyDigest, RevocationDigest: testDigest("revocation"), Outcome: "allow",
		ReasonCode: "case_allowed", IssuedAt: testNow, ExpiresAt: testNow.Add(time.Minute), Revision: 1}
	value.DecisionDigest, _ = DecisionBindingDigest(value)
	return value
}

func validRecord(command Command, decision Decision) Record {
	value := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion, Case: command.Case,
		CreatorActorID: command.ActorID, OwnerActorID: command.ActorID, AssigneeActorID: *command.AssigneeActorID,
		Classification: *command.TargetClassification, State: Open, RetentionPolicyID: *command.RetentionPolicyID,
		RetainUntil: *command.RetainUntil, PolicyDigest: command.PolicyDigest, IntentDigest: decision.IntentDigest,
		IdempotencyDigest: IdempotencyBindingDigest(command.IdempotencyKey), DecisionDigest: decision.DecisionDigest,
		RevocationDigest: decision.RevocationDigest, AuditEventDigest: testDigest("audit"),
		CreatedAt: testNow, UpdatedAt: testNow, Revision: 1}
	value.ProvenanceDigest, _ = RecordProvenanceDigest(value)
	return value
}

func validReceipt(command Command, decision Decision, record Record) Receipt {
	value := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: command.RequestID, Operation: command.Operation, Case: command.Case,
		IntentDigest: record.IntentDigest, IdempotencyDigest: record.IdempotencyDigest,
		DecisionDigest: decision.DecisionDigest, RevocationDigest: decision.RevocationDigest,
		AuditEventDigest: record.AuditEventDigest, Command: cloneCommand(command), Record: cloneRecord(record), CreatedAt: record.UpdatedAt}
	value.ReceiptDigest, _ = ReceiptBindingDigest(value)
	return value
}

func testDigest(value string) string { return digest("COH-CASE-TEST-V1\x00", []byte(value)) }

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *testClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *testClock) set(value time.Time) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = value
}

type testAuthority struct {
	mu      sync.Mutex
	now     time.Time
	outcome string
	reason  string
	calls   []AuthorizationRequest
}

type authorityFunc func(context.Context, AuthorizationRequest) (Decision, error)

func (function authorityFunc) AuthorizeCase(ctx context.Context, request AuthorizationRequest) (Decision, error) {
	return function(ctx, request)
}

func (authority *testAuthority) AuthorizeCase(_ context.Context, request AuthorizationRequest) (Decision, error) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.calls = append(authority.calls, cloneAuthorization(request))
	outcome, reason := authority.outcome, authority.reason
	if outcome == "" {
		outcome, reason = "allow", "case_allowed"
	}
	value := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID: testDecision, AuthorizationDigest: request.AuthorizationDigest,
		IntentDigest: request.IntentDigest, Operation: request.Command.Operation, Case: request.Command.Case,
		ActorID: request.Command.ActorID, ActorRevision: request.Command.ActorRevision,
		ExpectedRevision: request.Command.ExpectedRevision, PolicyDigest: request.Command.PolicyDigest,
		RevocationDigest: testDigest("revocation"), Outcome: outcome, ReasonCode: reason,
		IssuedAt: authority.now, ExpiresAt: authority.now.Add(time.Minute), Revision: 1}
	value.DecisionDigest, _ = DecisionBindingDigest(value)
	return value, nil
}

type testAuditor struct {
	mu     sync.Mutex
	events []tamperaudit.Event
	err    error
}

func (auditor *testAuditor) AppendAuditEvent(_ context.Context, event tamperaudit.Event) error {
	auditor.mu.Lock()
	defer auditor.mu.Unlock()
	if auditor.err != nil {
		return auditor.err
	}
	auditor.events = append(auditor.events, event)
	return nil
}

type testStore struct {
	mu        sync.Mutex
	current   map[domain.CaseRef]Record
	receipts  map[string]Receipt
	commitErr error
}

func newTestStore() *testStore {
	return &testStore{current: make(map[domain.CaseRef]Record), receipts: make(map[string]Receipt)}
}

func (store *testStore) Load(_ context.Context, scope domain.CaseRef) (Record, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.current[scope]
	return cloneRecord(value), found, nil
}

func (store *testStore) Recover(_ context.Context, scope domain.CaseRef, idempotency string) (Receipt, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, found := store.receipts[receiptTestKey(scope, idempotency)]
	return cloneReceipt(value), found, nil
}

func (store *testStore) Commit(_ context.Context, _ string, intent string, expected uint64,
	record Record, receipt Receipt) (Receipt, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.commitErr != nil {
		return Receipt{}, false, store.commitErr
	}
	key := receiptTestKey(record.Case, record.IdempotencyDigest)
	if recovered, found := store.receipts[key]; found {
		return cloneReceipt(recovered), true, nil
	}
	current, found := store.current[record.Case]
	if (!found && expected != 0) || (found && current.Revision != expected) || record.Revision != expected+1 ||
		record.IntentDigest != intent || validateRecord(record) != nil || validateReceipt(receipt) != nil {
		return Receipt{}, false, newError(Conflict, "store_conflict", false, nil)
	}
	store.current[record.Case] = cloneRecord(record)
	store.receipts[key] = cloneReceipt(receipt)
	return cloneReceipt(receipt), false, nil
}

func receiptTestKey(scope domain.CaseRef, idempotency string) string {
	return scope.OrganizationID + "\x00" + scope.TenantID + "\x00" + scope.CaseID + "\x00" + idempotency
}

func nextCommand(operation Operation, record Record, suffix string) Command {
	value := Command{SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion,
		RequestID:      "0199a213-3010-7010-8010-0000000000" + suffix,
		IdempotencyKey: "case-" + string(operation) + "-" + suffix, Operation: operation,
		Case: record.Case, ActorID: testActor, ActorRevision: 2, PolicyDigest: testDigest("policy"),
		ExpectedRevision: record.Revision, Deadline: record.UpdatedAt.Add(time.Hour)}
	return value
}
