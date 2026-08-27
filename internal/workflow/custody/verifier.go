package custody

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

// Verifier independently walks the durable custody interval from genesis.
// It has no authority or mutation capability.
type Verifier struct {
	ledger   Ledger
	evidence EvidenceResolver
	auditor  Auditor
	clock    Clock
}

func NewVerifier(ledger Ledger, evidence EvidenceResolver, auditor Auditor,
	clock Clock) (*Verifier, error) {
	if ledger == nil || evidence == nil || auditor == nil || clock == nil {
		return nil, newError(InvalidInput, "verifier_dependencies_required", false, nil)
	}
	return &Verifier{ledger: ledger, evidence: evidence, auditor: auditor, clock: clock}, nil
}

func (verifier *Verifier) VerifyFromGenesis(ctx context.Context,
	scope domain.CaseRef) (VerificationReport, error) {
	if err := contextError(ctx); err != nil {
		return VerificationReport{}, err
	}
	if !validCase(scope) {
		return VerificationReport{}, newError(InvalidInput, "verification_scope_invalid", false, nil)
	}
	now := verifier.clock.Now()
	if !validTime(now) {
		return VerificationReport{}, newError(InternalFailure, "clock_invalid", false, nil)
	}
	head, err := verifier.ledger.LoadHead(ctx, scope)
	if err != nil {
		return VerificationReport{}, mapDependency(ctx, "verification_head_unavailable", err)
	}
	if !validHead(head) || head.Case != scope || head.Sequence == 0 || head.LastRecordAt == nil {
		return verifier.report(scope, head, VerifyInvalidSequence, nil, now), nil
	}
	report := verifier.report(scope, head, VerifySuccess, nil, now)
	expectedSequence, expectedHash := uint64(1), GenesisHash
	var previous *Record
	receiptRecords := make(map[string]Record, head.Sequence)
	for expectedSequence <= head.Sequence {
		records, readErr := verifier.ledger.Read(ctx, scope, expectedSequence-1, custodyReadBatch)
		if readErr != nil {
			return verifier.report(scope, head, VerifyInvalidRecord, nil, now), nil
		}
		if len(records) == 0 || len(records) > int(custodyReadBatch) {
			return verifier.report(scope, head, VerifyTruncatedInterval, nil, now), nil
		}
		for index := range records {
			record := records[index]
			if record.Case != scope || validateRecord(record) != nil {
				return verifier.report(scope, head, VerifyInvalidRecord, nil, now), nil
			}
			if record.Sequence != expectedSequence {
				return verifier.report(scope, head, VerifyInvalidSequence, nil, now), nil
			}
			if record.PreviousChainHash != expectedHash || !recordExpectedHead(record, previous) {
				return verifier.report(scope, head, VerifyInvalidChain, nil, now), nil
			}
			verified, verifyErr := resolveEvidenceSet(ctx, verifier.evidence, record.Command)
			if verifyErr != nil || verified != record.EvidenceVerifiedDigest {
				return verifier.report(scope, head, verificationEvidenceReason(record.Command), nil, now), nil
			}
			receipt, receiptErr := receiptForRecord(record)
			if receiptErr != nil || !verifier.verifyReceipt(ctx, record, receipt) {
				return verifier.report(scope, head, VerifyInvalidReceipt, nil, now), nil
			}
			if !verifyAuthorizationAncestry(record, receiptRecords) {
				return verifier.report(scope, head, VerifyInvalidOperation, nil, now), nil
			}
			event, eventErr := allowedAuditEvent(record)
			if eventErr != nil {
				return verifier.report(scope, head, VerifyInvalidAudit, nil, now), nil
			}
			eventDigest, eventErr := auditEventBindingDigest(event)
			if eventErr != nil || eventDigest != record.AuditEventDigest {
				return verifier.report(scope, head, VerifyInvalidAudit, nil, now), nil
			}
			proof, proofErr := verifier.auditor.VerifyCustodyEvent(ctx, scope,
				record.AuditEventDigest, record.RecordDigest)
			if proofErr != nil {
				return verifier.report(scope, head, VerifyMissingAudit, nil, now), nil
			}
			if !validAuditProof(proof) || proof.EventDigest != record.AuditEventDigest {
				return verifier.report(scope, head, VerifyInvalidAudit, nil, now), nil
			}
			report.AuditCheckpointID = clonePointer(proof.CheckpointID)
			report.AuditCheckpointDigest = clonePointer(proof.CheckpointDigest)
			receiptRecords[receipt.ReceiptDigest] = cloneRecord(record)
			copy := cloneRecord(record)
			previous, expectedHash = &copy, record.ChainHash
			expectedSequence++
			if expectedSequence > head.Sequence {
				if index != len(records)-1 {
					return verifier.report(scope, head, VerifyInvalidSequence, nil, now), nil
				}
				break
			}
		}
	}
	if previous == nil || previous.Sequence != head.Sequence || previous.ChainHash != head.ChainHash ||
		!previous.OccurredAt.Equal(*head.LastRecordAt) {
		return verifier.report(scope, head, VerifyTruncatedInterval, nil, now), nil
	}
	report.ReportDigest, err = VerificationReportBindingDigest(report)
	if err != nil {
		return VerificationReport{}, err
	}
	return report, nil
}

func (verifier *Verifier) verifyReceipt(ctx context.Context, record Record, want Receipt) bool {
	resolved, found, err := verifier.ledger.ResolveReceipt(ctx, record.Case, want.ReceiptDigest)
	if err != nil || !found || validateReceiptRecordDirect(resolved, record) != nil ||
		resolved.ReceiptDigest != want.ReceiptDigest {
		return false
	}
	recovered, found, err := verifier.ledger.Recover(ctx, record.Case,
		IdempotencyBindingDigest(record.Command.IdempotencyKey))
	return err == nil && found && recovered.ReceiptDigest == want.ReceiptDigest &&
		validateReceiptRecordDirect(recovered, record) == nil
}

func (verifier *Verifier) report(scope domain.CaseRef, head Head, reason VerificationReason,
	proof *AuditProof, now time.Time) VerificationReport {
	outcome := VerificationInvalid
	if reason == VerifySuccess {
		outcome = VerificationValid
	} else if reason == VerifyTruncatedInterval {
		outcome = VerificationIncomplete
	}
	toSequence, headHash := head.Sequence, head.ChainHash
	if toSequence == 0 {
		toSequence = 1
	}
	if !digestPattern.MatchString(headHash) {
		headHash = GenesisHash
	}
	report := VerificationReport{SchemaVersion: VerificationSchemaVersion, ContractVersion: ContractVersion,
		Case: scope, FromSequence: 1, ToSequence: toSequence, HeadChainHash: headHash,
		Outcome: outcome, ReasonCode: reason, VerifiedAt: now.UTC()}
	if proof != nil {
		report.AuditCheckpointID = clonePointer(proof.CheckpointID)
		report.AuditCheckpointDigest = clonePointer(proof.CheckpointDigest)
	}
	report.ReportDigest, _ = VerificationReportBindingDigest(report)
	return report
}

func recordExpectedHead(record Record, previous *Record) bool {
	if previous == nil {
		return record.Command.ExpectedHead.Sequence == 0 &&
			record.Command.ExpectedHead.ChainHash == GenesisHash &&
			record.Command.ExpectedHead.LastRecordAt == nil && record.PreviousProvenanceDigest == nil
	}
	return record.Command.ExpectedHead.Sequence == previous.Sequence &&
		record.Command.ExpectedHead.ChainHash == previous.ChainHash &&
		record.Command.ExpectedHead.LastRecordAt != nil &&
		record.Command.ExpectedHead.LastRecordAt.Equal(previous.OccurredAt) &&
		record.PreviousProvenanceDigest != nil && *record.PreviousProvenanceDigest == previous.ProvenanceDigest
}

func receiptForRecord(record Record) (Receipt, error) {
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: record.Command.RequestID, Case: record.Case,
		IdempotencyDigest: IdempotencyBindingDigest(record.Command.IdempotencyKey),
		IntentDigest:      record.IntentDigest, DecisionDigest: record.DecisionDigest, CustodyID: record.CustodyID,
		Sequence: record.Sequence, RecordDigest: record.RecordDigest, ChainHash: record.ChainHash,
		AuditEventDigest: record.AuditEventDigest, ProvenanceDigest: record.ProvenanceDigest,
		CreatedAt: record.OccurredAt}
	var err error
	receipt.ReceiptDigest, err = ReceiptBindingDigest(receipt)
	return receipt, err
}

func verifyAuthorizationAncestry(record Record, records map[string]Record) bool {
	command := record.Command
	if command.PriorAuthorizationDigest == nil {
		return true
	}
	prior, found := records[*command.PriorAuthorizationDigest]
	return found && prior.Sequence < record.Sequence && prior.Command.Phase == Authorized &&
		prior.Command.Operation == command.Operation && prior.Command.Case == command.Case &&
		prior.Command.Subject == command.Subject && prior.Command.PolicyDigest == command.PolicyDigest &&
		sameOptionalDigest(prior.Command.PurposeDigest, command.PurposeDigest) &&
		sameOptionalDigest(prior.Command.DestinationDigest, command.DestinationDigest) &&
		sameOptionalDigest(prior.Command.RecipientDigest, command.RecipientDigest) &&
		sameOptionalDigest(prior.Command.ReasonDigest, command.ReasonDigest) &&
		sameOptionalDigest(prior.Command.ArtifactSetDigest, command.ArtifactSetDigest)
}

func verificationEvidenceReason(command Command) VerificationReason {
	if command.Operation == Transform || command.Operation == Redact {
		return VerifyBrokenLineage
	}
	return VerifyInvalidArtifact
}

func VerificationReportBindingDigest(value VerificationReport) (string, error) {
	if value.SchemaVersion != VerificationSchemaVersion || value.ContractVersion != ContractVersion ||
		!validCase(value.Case) || value.FromSequence == 0 || value.ToSequence < value.FromSequence ||
		!digestPattern.MatchString(value.HeadChainHash) ||
		(value.AuditCheckpointID == nil) != (value.AuditCheckpointDigest == nil) ||
		value.AuditCheckpointID != nil && (!uuidPattern.MatchString(*value.AuditCheckpointID) ||
			!digestPattern.MatchString(*value.AuditCheckpointDigest)) || !validTime(value.VerifiedAt) ||
		!validVerificationOutcome(value.Outcome, value.ReasonCode) {
		return "", newError(InvalidInput, "verification_report_invalid", false, nil)
	}
	canonical, err := canonicalValue(verificationToWire(value))
	if err != nil {
		return "", err
	}
	return digest("COH-CUSTODY-VERIFICATION-REPORT-V1\x00", canonical), nil
}

func validVerificationOutcome(outcome VerificationOutcome, reason VerificationReason) bool {
	if outcome == VerificationValid {
		return reason == VerifySuccess
	}
	if outcome != VerificationInvalid && outcome != VerificationIncomplete {
		return false
	}
	switch reason {
	case VerifyInvalidScope, VerifyInvalidSequence, VerifyInvalidRecord, VerifyInvalidChain,
		VerifyInvalidReceipt, VerifyInvalidArtifact, VerifyInvalidManifest, VerifyBrokenLineage,
		VerifyInvalidOperation, VerifyMissingAudit, VerifyInvalidAudit, VerifyInvalidCheckpoint,
		VerifyTruncatedInterval:
		return true
	default:
		return false
	}
}
