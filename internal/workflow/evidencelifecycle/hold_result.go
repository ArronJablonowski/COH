package evidencelifecycle

import (
	"context"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func (service *HoldService) commitHold(auditContext, operationContext context.Context, state holdState,
	idempotency string, lifecycle LifecycleProof, custody CustodyProofSet, progress Progress) (Result, error) {
	progress.Phase, progress.Revision, progress.UpdatedAt = Completed, progress.Revision+1, service.clock.Now()
	progress.ProgressDigest = ""
	var err error
	progress.ProgressDigest, err = ProgressBindingDigest(progress)
	if err != nil || ValidateProgress(progress) != nil {
		return Result{}, newError(Unavailable, "hold_completed_progress_invalid", false, err)
	}
	artifactSet, lifecycleDigest, custodyDigest := state.Evidence.ArtifactSetDigest,
		lifecycle.ReceiptDigest, custody.ReceiptSetDigest
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion,
		OperationID: progress.OperationID, Case: state.Command.Case, Operation: state.Command.Operation,
		CommandDigest: progress.CommandDigest, IntentDigest: state.IntentDigest,
		DecisionDigest: state.FinalDecisionDigest, RevocationDigest: state.FinalRevocationDigest,
		Artifacts: []EvidenceReference{}, ArtifactSetDigest: &artifactSet,
		LifecycleReceiptDigest: &lifecycleDigest, CompletionCustodyReceiptDigest: &custodyDigest,
		CompletedAt: progress.UpdatedAt, PreviousProvenanceDigest: lifecycle.ProvenanceDigest}
	record.ProvenanceDigest, err = RecordProvenanceDigest(record)
	if err != nil {
		return Result{}, newError(Unavailable, "hold_record_build_failed", false, err)
	}
	event, expectedEvent, err := completedHoldEvent(record, state, custody)
	if err != nil {
		return Result{}, err
	}
	if err = service.appendAndVerifyHoldAudit(auditContext, state.Command.Case, event, expectedEvent); err != nil {
		return Result{}, err
	}
	record.AuditEventDigest = expectedEvent
	record.RecordDigest, err = RecordBindingDigest(record)
	if err != nil {
		return Result{}, newError(Unavailable, "hold_record_build_failed", false, err)
	}
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: state.Command.RequestID, OperationID: progress.OperationID, Case: state.Command.Case,
		Operation: state.Command.Operation, IdempotencyDigest: idempotency, IntentDigest: state.IntentDigest,
		DecisionDigest: state.FinalDecisionDigest, RecordDigest: record.RecordDigest, Artifacts: []EvidenceReference{},
		ArtifactSetDigest: &artifactSet, LifecycleReceiptDigest: &lifecycleDigest,
		CompletionCustodyReceiptDigest: &custodyDigest, AuditEventDigest: expectedEvent,
		ProvenanceDigest: record.ProvenanceDigest, CreatedAt: progress.UpdatedAt}
	receipt.ReceiptDigest, err = ReceiptBindingDigest(receipt)
	if err != nil || ValidateRecord(record) != nil || ValidateReceipt(receipt) != nil {
		return Result{}, newError(Unavailable, "hold_result_build_failed", false, err)
	}
	stored, replayed, err := service.store.Commit(operationContext, state.Command.IdempotencyKey,
		state.IntentDigest, progress, record, receipt)
	if err != nil {
		return Result{}, mapExportDependency(operationContext, "hold_commit_unavailable", err)
	}
	if ValidateReceipt(stored) != nil || stored.Operation != state.Command.Operation ||
		stored.IntentDigest != state.IntentDigest || stored.IdempotencyDigest != idempotency ||
		stored.LifecycleReceiptDigest == nil || *stored.LifecycleReceiptDigest != lifecycleDigest {
		return Result{}, newError(Denied, "stored_hold_receipt_invalid", false, nil)
	}
	return Result{Receipt: stored, Replayed: replayed}, nil
}

func completedHoldEvent(record Record, state holdState,
	custody CustodyProofSet) (tamperaudit.Event, string, error) {
	precommit, err := RecordPrecommitDigest(record)
	if err != nil {
		return tamperaudit.Event{}, "", err
	}
	digests := []string{precommit, record.IntentDigest, record.DecisionDigest, record.RevocationDigest,
		*record.ArtifactSetDigest, *record.LifecycleReceiptDigest, *record.CompletionCustodyReceiptDigest,
		record.ProvenanceDigest}
	for _, proof := range custody.Proofs {
		digests = append(digests, proof.ReceiptDigest, proof.RecordDigest, proof.AuditDigest, proof.Head.ChainHash)
	}
	sort.Strings(digests)
	operation := "evidence.hold.placed"
	reason := "hold_placed"
	if record.Operation == ReleaseHold {
		operation, reason = "evidence.hold.released", "hold_released"
	}
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID:        deterministicUUID("COH-EVIDENCE-LIFECYCLE-AUDIT-ID-V1\x00", record.OperationID+"\x00completed"),
		OrganizationID: record.Case.OrganizationID, TenantID: record.Case.TenantID, CaseID: record.Case.CaseID,
		ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision, SourceSchema: RecordSchemaVersion,
		Operation: operation, Outcome: "allowed", ReasonCode: reason, SubjectID: record.OperationID,
		SubjectRevision: 1, SubjectDigest: precommit, EvidenceDigests: uniqueLifecycleDigests(digests),
		OccurredAt: formatTime(record.CompletedAt)}
	if tamperaudit.ValidateEvent(event) != nil {
		return tamperaudit.Event{}, "", newError(Unavailable, "hold_audit_event_invalid", false, nil)
	}
	canonical, err := tamperaudit.CanonicalEvent(event)
	if err != nil {
		return tamperaudit.Event{}, "", newError(Unavailable, "hold_audit_event_invalid", false, err)
	}
	return event, digest("COH-EVIDENCE-LIFECYCLE-AUDIT-EVENT-V1\x00", canonical), nil
}
