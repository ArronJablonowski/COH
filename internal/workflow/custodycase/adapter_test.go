package custodycase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/caselifecycle"
)

const (
	testOrg       = "0199a213-3001-7001-8001-000000000001"
	testTenant    = "0199a213-3002-7002-8002-000000000002"
	testCase      = "0199a213-3003-7003-8003-000000000003"
	testActor     = "0199a213-3004-7004-8004-000000000004"
	testAssignee  = "0199a213-3005-7005-8005-000000000005"
	testRetention = "0199a213-3006-7006-8006-000000000006"
	testRequest   = "0199a213-3007-7007-8007-000000000007"
)

type repositoryStub struct {
	record  caselifecycle.Record
	receipt caselifecycle.Receipt
}

func (stub repositoryStub) Load(_ context.Context, _ domain.CaseRef) (caselifecycle.Record, bool, error) {
	return stub.record, true, nil
}

func (stub repositoryStub) ResolveReceipt(_ context.Context, _ domain.CaseRef,
	_ string) (caselifecycle.Receipt, bool, error) {
	return stub.receipt, true, nil
}

func TestAdapterProjectsCanonicalCaseAndDeletionReceipt(t *testing.T) {
	now := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	scope := domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase}
	record := deletedRecord(scope, now)
	receipt := deletionReceipt(record, now.Add(25*time.Hour))
	adapter, err := New(repositoryStub{record: record, receipt: receipt})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, found, err := adapter.LoadCase(t.Context(), scope)
	wantRetention, _ := caselifecycle.RetentionPolicyBindingDigest(testRetention)
	if err != nil || !found || snapshot.Case != scope || snapshot.State != "deleted" ||
		snapshot.Revision != 2 || snapshot.RetentionPolicyDigest != wantRetention ||
		snapshot.ProvenanceDigest != record.ProvenanceDigest {
		t.Fatalf("snapshot=%+v found=%v err=%v", snapshot, found, err)
	}
	proof, found, err := adapter.ResolveLifecycleReceipt(t.Context(), scope, receipt.ReceiptDigest)
	if err != nil || !found || proof.Case != scope || proof.Operation != "delete" || proof.Revision != 2 ||
		proof.ReceiptDigest != receipt.ReceiptDigest ||
		proof.ProvenanceDigest != receipt.Record.ProvenanceDigest || proof.LegalHold {
		t.Fatalf("proof=%+v found=%v err=%v", proof, found, err)
	}
}

func TestAdapterRejectsCrossScopeAndMalformedReceiptDigest(t *testing.T) {
	now := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	scope := domain.CaseRef{OrganizationID: testOrg, TenantID: testTenant, CaseID: testCase}
	record := deletedRecord(scope, now)
	receipt := deletionReceipt(record, now.Add(25*time.Hour))
	adapter, _ := New(repositoryStub{record: record, receipt: receipt})
	other := scope
	other.CaseID = "0199a213-3999-7999-8999-000000000099"
	if _, found, err := adapter.LoadCase(t.Context(), other); err == nil || found {
		t.Fatalf("cross-scope load found=%v err=%v", found, err)
	}
	if _, found, err := adapter.ResolveLifecycleReceipt(t.Context(), scope, "invalid"); err == nil || found {
		t.Fatalf("malformed resolve found=%v err=%v", found, err)
	}
}

func deletedRecord(scope domain.CaseRef, created time.Time) caselifecycle.Record {
	reason := testDigest("reason")
	value := caselifecycle.Record{SchemaVersion: caselifecycle.RecordSchemaVersion,
		ContractVersion: caselifecycle.ContractVersion, Case: scope, CreatorActorID: testActor,
		OwnerActorID: testActor, AssigneeActorID: testAssignee, Classification: caselifecycle.Restricted,
		State: caselifecycle.Deleted, RetentionPolicyID: testRetention, RetainUntil: created.Add(24 * time.Hour),
		DeletionReasonDigest: &reason, DeletedByActorID: stringPointer(testActor),
		PolicyDigest: testDigest("policy"), IntentDigest: testDigest("intent"),
		IdempotencyDigest: testDigest("idempotency"), DecisionDigest: testDigest("decision"),
		RevocationDigest: testDigest("revocation"), AuditEventDigest: testDigest("audit"),
		PreviousProvenanceDigest: stringPointer(testDigest("previous")), CreatedAt: created,
		UpdatedAt: created.Add(25 * time.Hour), Revision: 2}
	value.ProvenanceDigest, _ = caselifecycle.RecordProvenanceDigest(value)
	return value
}

func deletionReceipt(record caselifecycle.Record, deadline time.Time) caselifecycle.Receipt {
	reason := *record.DeletionReasonDigest
	command := caselifecycle.Command{SchemaVersion: caselifecycle.CommandSchemaVersion,
		ContractVersion: caselifecycle.ContractVersion, RequestID: testRequest,
		IdempotencyKey: "custody-case-delete", Operation: caselifecycle.Delete, Case: record.Case,
		ActorID: testActor, ActorRevision: 1, ReasonDigest: &reason, PolicyDigest: record.PolicyDigest,
		ExpectedRevision: 1, Deadline: deadline}
	commandIntent, _ := caselifecycle.CommandBindingDigest(command)
	record.IntentDigest = commandIntent
	record.IdempotencyDigest = caselifecycle.IdempotencyBindingDigest(command.IdempotencyKey)
	record.ProvenanceDigest, _ = caselifecycle.RecordProvenanceDigest(record)
	receipt := caselifecycle.Receipt{SchemaVersion: caselifecycle.ReceiptSchemaVersion,
		ContractVersion: caselifecycle.ContractVersion, RequestID: command.RequestID,
		Operation: command.Operation, Case: command.Case, IntentDigest: record.IntentDigest,
		IdempotencyDigest: record.IdempotencyDigest, DecisionDigest: record.DecisionDigest,
		RevocationDigest: record.RevocationDigest, AuditEventDigest: record.AuditEventDigest,
		Command: command, Record: record, CreatedAt: record.UpdatedAt}
	receipt.ReceiptDigest, _ = caselifecycle.ReceiptBindingDigest(receipt)
	return receipt
}

func testDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func stringPointer(value string) *string { return &value }
