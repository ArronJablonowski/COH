package custody

import (
	"context"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain"
)

type custodyVerifierLedger struct {
	Ledger
	read func(context.Context, domain.CaseRef, uint64, uint16) ([]Record, error)
}

func (ledger custodyVerifierLedger) Read(ctx context.Context, scope domain.CaseRef, after uint64,
	limit uint16) ([]Record, error) {
	return ledger.read(ctx, scope, after, limit)
}

func TestVerifierAcceptsCompleteChainFromGenesis(t *testing.T) {
	_, command, _, _, evidence, ledger, auditor := custodyControllerFixture(t)
	buildTwoRecordChain(t, command, evidence, ledger, auditor)
	verifier, err := NewVerifier(ledger, evidence, auditor, &custodyTestClock{now: custodyFixtureTime})
	if err != nil {
		t.Fatal(err)
	}
	report, err := verifier.VerifyFromGenesis(context.Background(), command.Case)
	if err != nil || report.Outcome != VerificationValid || report.ReasonCode != VerifySuccess ||
		report.FromSequence != 1 || report.ToSequence != 2 || report.HeadChainHash != ledger.head.ChainHash ||
		report.ReportDigest == "" {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	want, err := VerificationReportBindingDigest(report)
	if err != nil || want != report.ReportDigest {
		t.Fatalf("report digest want=%s got=%s err=%v", want, report.ReportDigest, err)
	}
}

func TestVerifierRejectsInsertionDeletionReorderMutationForkAndTruncation(t *testing.T) {
	_, command, _, _, evidence, ledger, auditor := custodyControllerFixture(t)
	records := buildTwoRecordChain(t, command, evidence, ledger, auditor)
	mutated := cloneRecord(records[0])
	mutated.AuditEventDigest = fixtureDigest("verifier-mutated-audit")
	forked := cloneRecord(records[1])
	forked.PreviousChainHash = fixtureDigest("verifier-fork")
	forked.Command.ExpectedHead.ChainHash = forked.PreviousChainHash
	forked.IntentDigest, _ = CommandBindingDigest(forked.Command)
	forked.ProvenanceDigest, _ = RecordProvenanceDigest(forked)
	forked.RecordDigest, _ = RecordBindingDigest(forked)
	forked.ChainHash, _ = RecordChainHash(forked)
	tests := map[string]struct {
		read   func(context.Context, domain.CaseRef, uint64, uint16) ([]Record, error)
		reason VerificationReason
	}{
		"insertion": {staticVerifierRead([]Record{records[0], records[0], records[1]}), VerifyInvalidSequence},
		"deletion":  {staticVerifierRead([]Record{records[1]}), VerifyInvalidSequence},
		"reorder":   {staticVerifierRead([]Record{records[1], records[0]}), VerifyInvalidSequence},
		"mutation":  {staticVerifierRead([]Record{mutated, records[1]}), VerifyInvalidRecord},
		"fork":      {staticVerifierRead([]Record{records[0], forked}), VerifyInvalidChain},
		"truncation": {func(_ context.Context, _ domain.CaseRef, after uint64, _ uint16) ([]Record, error) {
			if after == 0 {
				return []Record{cloneRecord(records[0])}, nil
			}
			return nil, nil
		}, VerifyTruncatedInterval},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			adversarial := custodyVerifierLedger{Ledger: ledger, read: test.read}
			verifier, err := NewVerifier(adversarial, evidence, auditor,
				&custodyTestClock{now: custodyFixtureTime})
			if err != nil {
				t.Fatal(err)
			}
			report, err := verifier.VerifyFromGenesis(context.Background(), command.Case)
			if err != nil || report.Outcome == VerificationValid || report.ReasonCode != test.reason ||
				report.ReportDigest == "" {
				t.Fatalf("report=%+v err=%v", report, err)
			}
		})
	}
}

func TestVerifierRejectsMissingAuditCoverage(t *testing.T) {
	_, command, _, _, evidence, ledger, auditor := custodyControllerFixture(t)
	records := buildTwoRecordChain(t, command, evidence, ledger, auditor)
	auditor.mu.Lock()
	delete(auditor.proofs, records[1].AuditEventDigest)
	auditor.mu.Unlock()
	verifier, err := NewVerifier(ledger, evidence, auditor, &custodyTestClock{now: custodyFixtureTime})
	if err != nil {
		t.Fatal(err)
	}
	report, err := verifier.VerifyFromGenesis(context.Background(), command.Case)
	if err != nil || report.Outcome != VerificationInvalid || report.ReasonCode != VerifyMissingAudit {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func buildTwoRecordChain(t *testing.T, command Command, evidence *custodyTestEvidence,
	ledger *custodyTestLedger, auditor *custodyTestAuditor) []Record {
	t.Helper()
	authority := &custodyTestAuthority{}
	cases := &custodyTestCases{current: CaseSnapshot{Case: command.Case, State: "open",
		Classification: "restricted", Revision: 2, RetentionPolicyDigest: fixtureDigest("retention"),
		RetainUntil: custodyFixtureTime.Add(-1), ProvenanceDigest: fixtureDigest("case.provenance")},
		receipts: make(map[string]LifecycleReceiptSnapshot)}
	controller, err := New(authority, cases, evidence, ledger, auditor,
		&custodyTestClock{now: custodyFixtureTime})
	if err != nil {
		t.Fatal(err)
	}
	first, err := controller.Execute(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	access := cloneCommand(command)
	access.RequestID = custodyUUID(8)
	access.IdempotencyKey = "custody-verifier-access"
	access.Operation, access.Phase = Access, Authorized
	access.SourceIdentityDigest = nil
	access.PurposeDigest = digestPointer("verifier-purpose")
	last := custodyFixtureTime
	access.ExpectedHead = Head{Case: command.Case, Sequence: 1,
		ChainHash: first.Receipt.ChainHash, LastRecordAt: &last}
	if _, err = controller.Execute(context.Background(), access); err != nil {
		t.Fatal(err)
	}
	return []Record{cloneRecord(ledger.records[0]), cloneRecord(ledger.records[1])}
}

func staticVerifierRead(records []Record) func(context.Context, domain.CaseRef, uint64, uint16) ([]Record, error) {
	return func(_ context.Context, _ domain.CaseRef, _ uint64, _ uint16) ([]Record, error) {
		result := make([]Record, len(records))
		for index := range records {
			result[index] = cloneRecord(records[index])
		}
		return result, nil
	}
}
