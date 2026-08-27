package custody

import (
	"context"
	"testing"
)

func TestControllerAppendsAcquisitionAndExactReplayRepairsWithoutDuplicate(t *testing.T) {
	controller, command, authority, _, evidence, ledger, auditor := custodyControllerFixture(t)
	result, err := controller.Execute(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if result.Replayed || result.Receipt.Sequence != 1 || len(ledger.records) != 1 ||
		ledger.records[0].Command.Subject.IngestionReceiptDigest != command.Subject.IngestionReceiptDigest ||
		ledger.records[0].Command.SourceIdentityDigest == nil ||
		*ledger.records[0].Command.SourceIdentityDigest != *command.SourceIdentityDigest {
		t.Fatalf("invalid acquisition result: %+v", result)
	}
	if len(authority.requests) != 1 || evidence.resolve != 1 || len(auditor.events) != 1 ||
		auditor.events[0].Operation != "evidence.custody.acquire" {
		t.Fatal("acquisition did not traverse evidence, authority, and audit boundaries once")
	}

	replayed, err := controller.Execute(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.Receipt != result.Receipt || len(ledger.records) != 1 ||
		len(authority.requests) != 2 || evidence.resolve != 2 || len(auditor.events) != 2 ||
		auditor.events[1].Operation != "evidence.custody.replay" {
		t.Fatal("exact replay did not reauthorize, verify, audit, and recover one record")
	}
}

func TestControllerChangedReplayStopsBeforeEvidenceAndAuthority(t *testing.T) {
	controller, command, authority, _, evidence, ledger, _ := custodyControllerFixture(t)
	if _, err := controller.Execute(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	changed := cloneCommand(command)
	changed.PolicyDigest = fixtureDigest("changed.policy")
	if _, err := controller.Execute(context.Background(), changed); CodeOf(err) != Denied {
		t.Fatalf("changed replay error=%v", err)
	}
	if len(ledger.records) != 1 || len(authority.requests) != 1 || evidence.resolve != 1 {
		t.Fatal("changed replay crossed a protected dependency boundary")
	}
}

func TestControllerRecoversCommittedRecordAfterAuditFailure(t *testing.T) {
	controller, command, _, _, _, ledger, auditor := custodyControllerFixture(t)
	auditor.fail = true
	if _, err := controller.Execute(context.Background(), command); CodeOf(err) != Unavailable {
		t.Fatalf("audit failure error=%v", err)
	}
	if len(ledger.records) != 1 {
		t.Fatal("custody commit was not retained for exact repair")
	}
	auditor.fail = false
	result, err := controller.Execute(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Replayed || len(ledger.records) != 1 || len(auditor.events) != 2 {
		t.Fatal("audit repair duplicated custody or omitted replay evidence")
	}
}

func TestControllerRejectsStaleHeadBeforeEvidenceOrAuthority(t *testing.T) {
	controller, command, authority, _, evidence, ledger, _ := custodyControllerFixture(t)
	last := custodyFixtureTime.Add(-1)
	command.ExpectedHead = Head{Case: command.Case, Sequence: 1,
		ChainHash: fixtureDigest("other.head"), LastRecordAt: &last}
	if _, err := controller.Execute(context.Background(), command); CodeOf(err) != Conflict {
		t.Fatalf("stale head error=%v", err)
	}
	if len(authority.requests) != 0 || evidence.resolve != 0 || len(ledger.records) != 0 {
		t.Fatal("stale head crossed evidence or authority boundary")
	}
}
