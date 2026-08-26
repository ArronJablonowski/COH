package caselifecycle

import (
	"errors"
	"testing"
	"time"
)

func TestControllerExecutesCompleteCaseLifecycleAndReplay(t *testing.T) {
	now := testNow
	clock := &testClock{now: now}
	authority := &testAuthority{now: now}
	auditor := &testAuditor{}
	store := newTestStore()
	controller, err := New(authority, auditor, store, clock)
	if err != nil {
		t.Fatal(err)
	}
	create := validCreateCommand()
	result, err := controller.Execute(t.Context(), create)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	assertResult(t, result, Open, Internal, 1, false)
	replay, err := controller.Execute(t.Context(), create)
	if err != nil || !replay.Replayed || replay.Receipt.ReceiptDigest != result.Receipt.ReceiptDigest {
		t.Fatalf("exact replay failed: result=%+v err=%v", replay, err)
	}

	classification := Confidential
	command := nextCommand(Classify, result.Record, "11")
	command.TargetClassification = &classification
	result = executeCaseCommand(t, controller, authority, clock, command)
	assertResult(t, result, Open, Confidential, 2, false)

	assignee := "0199a213-3012-7012-8012-000000000012"
	command = nextCommand(Assign, result.Record, "12")
	command.AssigneeActorID = &assignee
	result = executeCaseCommand(t, controller, authority, clock, command)
	if result.Record.AssigneeActorID != assignee {
		t.Fatal("assignment was not applied")
	}

	reason := testDigest("hold")
	command = nextCommand(PlaceHold, result.Record, "13")
	command.ReasonDigest = &reason
	result = executeCaseCommand(t, controller, authority, clock, command)
	if !result.Record.LegalHold || result.Record.HoldReasonDigest == nil {
		t.Fatal("legal hold was not applied")
	}

	releaseReason := testDigest("release")
	command = nextCommand(ReleaseHold, result.Record, "14")
	command.ReasonDigest = &releaseReason
	result = executeCaseCommand(t, controller, authority, clock, command)
	if result.Record.LegalHold || result.Record.HoldReasonDigest != nil {
		t.Fatal("legal hold was not released")
	}

	command = nextCommand(Close, result.Record, "15")
	result = executeCaseCommand(t, controller, authority, clock, command)
	assertResult(t, result, Closed, Confidential, 6, false)

	command = nextCommand(Reopen, result.Record, "16")
	result = executeCaseCommand(t, controller, authority, clock, command)
	assertResult(t, result, Open, Confidential, 7, false)

	manifest := testDigest("manifest")
	command = nextCommand(Export, result.Record, "17")
	command.ExportManifestDigest = &manifest
	result = executeCaseCommand(t, controller, authority, clock, command)
	if result.Record.ExportCount != 1 || result.Record.LastExportManifestDigest == nil ||
		*result.Record.LastExportManifestDigest != manifest {
		t.Fatal("export attribution was not applied")
	}

	deleteAt := result.Record.RetainUntil.Add(time.Second)
	clock.set(deleteAt)
	authority.now = deleteAt
	deleteReason := testDigest("delete")
	command = nextCommand(Delete, result.Record, "18")
	command.ReasonDigest = &deleteReason
	command.Deadline = deleteAt.Add(time.Hour)
	result = executeCaseCommand(t, controller, authority, clock, command)
	assertResult(t, result, Deleted, Confidential, 9, false)
	if result.Record.DeletionReasonDigest == nil || result.Record.DeletedByActorID == nil ||
		*result.Record.DeletedByActorID != testActor {
		t.Fatal("deletion attribution was not retained")
	}
	if len(auditor.events) != 11 { // Nine operations plus original and replay events for the replay.
		t.Fatalf("unexpected audit event count: %d", len(auditor.events))
	}
}

func TestControllerFailsClosedForStatePolicyAndChangedReplay(t *testing.T) {
	now := testNow
	clock := &testClock{now: now}
	authority := &testAuthority{now: now}
	auditor := &testAuditor{}
	store := newTestStore()
	controller, _ := New(authority, auditor, store, clock)
	create := validCreateCommand()
	created, err := controller.Execute(t.Context(), create)
	if err != nil {
		t.Fatal(err)
	}

	changed := cloneCommand(create)
	changed.PolicyDigest = testDigest("different-policy")
	if _, err = controller.Execute(t.Context(), changed); CodeOf(err) != Denied || Reason(err) != "stored_receipt_invalid" {
		t.Fatalf("changed replay was not denied: %v", err)
	}

	lower := Public
	command := nextCommand(Classify, created.Record, "21")
	command.TargetClassification = &lower
	if _, err = controller.Execute(t.Context(), command); CodeOf(err) != Denied || Reason(err) != "classification_reduction_denied" {
		t.Fatalf("classification reduction was not denied: %v", err)
	}

	reason := testDigest("early-delete")
	command = nextCommand(Delete, created.Record, "22")
	command.ReasonDigest = &reason
	if _, err = controller.Execute(t.Context(), command); CodeOf(err) != Denied || Reason(err) != "retention_active" {
		t.Fatalf("early deletion was not denied: %v", err)
	}

	authority.outcome, authority.reason = "deny", "policy_denied"
	command = nextCommand(Close, created.Record, "23")
	if _, err = controller.Execute(t.Context(), command); CodeOf(err) != Denied || Reason(err) != "policy_denied" {
		t.Fatalf("policy denial was not enforced: %v", err)
	}
	if len(auditor.events) != 5 { // Create and four audited denials.
		t.Fatalf("denials were not fully audited: %d", len(auditor.events))
	}
}

func TestControllerDoesNotReleaseSuccessWhenAuditFails(t *testing.T) {
	now := testNow
	clock := &testClock{now: now}
	authority := &testAuthority{now: now}
	auditor := &testAuditor{err: errors.New("offline")}
	store := newTestStore()
	controller, _ := New(authority, auditor, store, clock)
	if _, err := controller.Execute(t.Context(), validCreateCommand()); CodeOf(err) != Unavailable || Reason(err) != "audit_unavailable" {
		t.Fatalf("audit failure released success: %v", err)
	}
	if _, found, _ := store.Load(t.Context(), validCreateCommand().Case); !found {
		t.Fatal("durable commit was lost after audit failure")
	}
	auditor.err = nil
	result, err := controller.Execute(t.Context(), validCreateCommand())
	if err != nil || !result.Replayed {
		t.Fatalf("exact replay did not repair audit: result=%+v err=%v", result, err)
	}
}

func executeCaseCommand(t *testing.T, controller *Controller, authority *testAuthority,
	clock *testClock, command Command) Result {
	t.Helper()
	authority.now = clock.Now()
	result, err := controller.Execute(t.Context(), command)
	if err != nil {
		t.Fatalf("%s failed: %v", command.Operation, err)
	}
	return result
}

func assertResult(t *testing.T, result Result, state State, classification Classification,
	revision uint64, replayed bool) {
	t.Helper()
	if result.Record.State != state || result.Record.Classification != classification ||
		result.Record.Revision != revision || result.Replayed != replayed || validateRecord(result.Record) != nil ||
		validateReceipt(result.Receipt) != nil {
		t.Fatalf("unexpected lifecycle result: %+v", result)
	}
}
