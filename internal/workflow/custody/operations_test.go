package custody

import (
	"context"
	"sort"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func TestControllerRecordsEveryCustodyOperationWithExactSafeFacts(t *testing.T) {
	for _, test := range []struct {
		operation Operation
		phase     Phase
	}{
		{Access, Authorized}, {Transform, Completed}, {Redact, Completed},
		{PlaceHold, Completed}, {ReleaseHold, Completed},
	} {
		t.Run(string(test.operation), func(t *testing.T) {
			controller, command, _, cases, _, ledger, _ := custodyOperationFixture(t, test.operation, test.phase)
			configureLifecycleFixture(command, cases)
			result, err := controller.Execute(context.Background(), command)
			if err != nil {
				t.Fatal(err)
			}
			if result.Receipt.Sequence != 1 || len(ledger.records) != 1 ||
				ledger.records[0].Command.Operation != test.operation || ledger.records[0].Command.Phase != test.phase {
				t.Fatalf("unexpected operation record: %+v", result)
			}
			if test.operation == Transform || test.operation == Redact {
				if len(ledger.records[0].Command.Parents) != 1 {
					t.Fatal("derived operation lost parent lineage")
				}
			}
			if test.operation == Redact && (ledger.records[0].Command.RuleDigest == nil ||
				ledger.records[0].Command.MappingDigest == nil || ledger.records[0].Command.ApprovalDigest == nil) {
				t.Fatal("redaction lost governed rule, mapping, or approval digest")
			}
		})
	}
}

func TestTransferAndExportCompletionRequireExactAuthorizationReceipt(t *testing.T) {
	for _, operation := range []Operation{Transfer, Export} {
		t.Run(string(operation), func(t *testing.T) {
			controller, authorized, authority, cases, evidence, ledger, _ :=
				custodyOperationFixture(t, operation, Authorized)
			first, err := controller.Execute(context.Background(), authorized)
			if err != nil {
				t.Fatal(err)
			}
			completed := completionCommand(operation, authorized, first.Receipt, ledger.head)
			addEvidenceFixture(completed, evidence)
			second, err := controller.Execute(context.Background(), completed)
			if err != nil {
				t.Fatal(err)
			}
			if second.Receipt.Sequence != 2 || len(ledger.records) != 2 ||
				ledger.records[1].Command.PriorAuthorizationDigest == nil ||
				*ledger.records[1].Command.PriorAuthorizationDigest != first.Receipt.ReceiptDigest {
				t.Fatal("completion did not bind the authorization receipt")
			}

			changed := completionCommand(operation, authorized, first.Receipt, ledger.head)
			changed.RequestID = custodyUUID(9)
			changed.IdempotencyKey = "substituted-destination"
			changed.DestinationDigest = digestPointer("substituted.destination")
			addEvidenceFixture(changed, evidence)
			beforeAuthority := len(authority.requests)
			if _, err = controller.Execute(context.Background(), changed); CodeOf(err) != Denied {
				t.Fatalf("destination substitution error=%v", err)
			}
			if len(authority.requests) != beforeAuthority || len(ledger.records) != 2 {
				t.Fatal("destination substitution crossed authority or append boundary")
			}
			_ = cases
		})
	}
}

func TestDeletionAuthorizationPrecedesLifecycleDeletionCompletion(t *testing.T) {
	controller, authorized, authority, cases, evidence, ledger, _ :=
		custodyOperationFixture(t, Delete, Authorized)
	first, err := controller.Execute(context.Background(), authorized)
	if err != nil {
		t.Fatal(err)
	}
	completed := completionCommand(Delete, authorized, first.Receipt, ledger.head)
	completed.ExpectedCaseRevision = 3
	completed.LifecycleReceiptDigest = digestPointer("delete.lifecycle")
	cases.current.State, cases.current.Revision = "deleted", 3
	cases.receipts[*completed.LifecycleReceiptDigest] = LifecycleReceiptSnapshot{Case: completed.Case,
		Operation: "delete", Revision: 3, ReceiptDigest: *completed.LifecycleReceiptDigest,
		ProvenanceDigest: fixtureDigest("delete.lifecycle.provenance")}
	addEvidenceFixture(completed, evidence)
	result, err := controller.Execute(context.Background(), completed)
	if err != nil {
		t.Fatal(err)
	}
	if result.Receipt.Sequence != 2 || len(authority.requests) != 2 ||
		ledger.records[1].Command.PriorAuthorizationDigest == nil ||
		*ledger.records[1].Command.PriorAuthorizationDigest != first.Receipt.ReceiptDigest {
		t.Fatal("deletion completion did not preserve authorization ancestry")
	}
}

func TestDeletionAuthorizationFailsUnderRetentionOrHoldBeforeAuthority(t *testing.T) {
	controller, command, authority, cases, _, ledger, _ := custodyOperationFixture(t, Delete, Authorized)
	cases.current.LegalHold = true
	if _, err := controller.Execute(context.Background(), command); Reason(err) != "legal_hold_active" {
		t.Fatalf("hold denial=%v", err)
	}
	if len(authority.requests) != 0 || len(ledger.records) != 0 {
		t.Fatal("held deletion crossed authority or append boundary")
	}
	cases.current.LegalHold = false
	cases.current.RetainUntil = custodyFixtureTime.Add(1)
	if _, err := controller.Execute(context.Background(), command); Reason(err) != "retention_active" {
		t.Fatalf("retention denial=%v", err)
	}
}

func custodyOperationFixture(t *testing.T, operation Operation, phase Phase) (*Controller, Command,
	*custodyTestAuthority, *custodyTestCases, *custodyTestEvidence, *custodyTestLedger, *custodyTestAuditor) {
	t.Helper()
	controller, _, authority, cases, evidence, ledger, auditor := custodyControllerFixture(t)
	command := custodyCommandFixture(operation, phase)
	command.ExpectedHead = cloneHead(ledger.head)
	command.ExpectedCaseRevision = cases.current.Revision
	addEvidenceFixture(command, evidence)
	return controller, command, authority, cases, evidence, ledger, auditor
}

func addEvidenceFixture(command Command, evidence *custodyTestEvidence) {
	parents := make([]VerifiedEvidence, len(command.Parents))
	for index, reference := range command.Parents {
		parents[index] = VerifiedEvidence{Reference: reference, SourceIdentityDigest: fixtureDigest("parent.source"),
			VerificationDigest: fixtureDigest("parent.verified." + reference.Artifact.Digest)}
		evidence.values[evidenceKey(reference)] = parents[index]
	}
	artifacts := make([]domain.ArtifactRef, len(command.Parents))
	manifests := make([]string, len(command.Parents))
	for index, reference := range command.Parents {
		artifacts[index], manifests[index] = reference.Artifact, reference.Manifest.Digest
	}
	sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].Digest < artifacts[right].Digest })
	sort.Strings(manifests)
	source := fixtureDigest("subject.source")
	if command.SourceIdentityDigest != nil {
		source = *command.SourceIdentityDigest
	}
	evidence.values[evidenceKey(command.Subject)] = VerifiedEvidence{Reference: command.Subject,
		SourceIdentityDigest: source, ParentArtifacts: artifacts, ParentManifestDigests: manifests,
		VerificationDigest: fixtureDigest("subject.verified." + command.Subject.Artifact.Digest)}
}

func configureLifecycleFixture(command Command, cases *custodyTestCases) {
	if command.LifecycleReceiptDigest == nil {
		return
	}
	operation, hold := string(command.Operation), false
	if command.Operation == PlaceHold {
		hold, cases.current.LegalHold = true, true
	}
	if command.Operation == ReleaseHold {
		operation, cases.current.LegalHold = "release_hold", false
	}
	cases.receipts[*command.LifecycleReceiptDigest] = LifecycleReceiptSnapshot{Case: command.Case,
		Operation: operation, Revision: cases.current.Revision, ReceiptDigest: *command.LifecycleReceiptDigest,
		ProvenanceDigest: fixtureDigest("lifecycle.provenance"), LegalHold: hold}
}

func completionCommand(operation Operation, authorized Command, receipt Receipt, head Head) Command {
	value := custodyCommandFixture(operation, Completed)
	value.Case, value.ActorID, value.ActorRevision = authorized.Case, authorized.ActorID, authorized.ActorRevision
	value.Subject, value.PolicyDigest = authorized.Subject, authorized.PolicyDigest
	value.PurposeDigest, value.DestinationDigest = clonePointer(authorized.PurposeDigest), clonePointer(authorized.DestinationDigest)
	value.RecipientDigest, value.ReasonDigest = clonePointer(authorized.RecipientDigest), clonePointer(authorized.ReasonDigest)
	value.ArtifactSetDigest = clonePointer(authorized.ArtifactSetDigest)
	value.RequestID, value.IdempotencyKey = custodyUUID(8), "custody-completion"
	value.ExpectedCaseRevision, value.ExpectedHead = authorized.ExpectedCaseRevision, cloneHead(head)
	value.PriorAuthorizationDigest = clonePointer(&receipt.ReceiptDigest)
	return value
}
