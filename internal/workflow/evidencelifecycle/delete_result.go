package evidencelifecycle

import (
	"context"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func (service *DeleteService) commitDelete(auditContext, operationContext context.Context, state deleteState,
	idempotency string, authorization CustodyProofSet, lifecycle LifecycleProof,
	attestation DispositionAttestation, completion CustodyProofSet, progress Progress) (Result, error) {
	progress.Phase, progress.Revision, progress.UpdatedAt = Completed, progress.Revision+1, service.clock.Now()
	progress.ProgressDigest = ""
	var err error
	progress.ProgressDigest, err = ProgressBindingDigest(progress)
	if err != nil || ValidateProgress(progress) != nil {
		return Result{}, newError(Unavailable, "delete_completed_progress_invalid", false, err)
	}
	artifactSet, authorizationDigest, lifecycleDigest := state.Evidence.ArtifactSetDigest,
		authorization.ReceiptSetDigest, lifecycle.ReceiptDigest
	attestationDigest, completionDigest := attestation.AttestationDigest, completion.ReceiptSetDigest
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion,
		OperationID: progress.OperationID, Case: state.Command.Case, Operation: Delete,
		CommandDigest: progress.CommandDigest, IntentDigest: state.IntentDigest,
		DecisionDigest: state.FinalDecisionDigest, RevocationDigest: state.FinalRevocationDigest,
		Artifacts: []EvidenceReference{}, ArtifactSetDigest: &artifactSet,
		LifecycleReceiptDigest: &lifecycleDigest, AuthorizationCustodyReceiptDigest: &authorizationDigest,
		CompletionCustodyReceiptDigest: &completionDigest, DispositionAttestationDigest: &attestationDigest,
		CompletedAt: progress.UpdatedAt, PreviousProvenanceDigest: lifecycle.ProvenanceDigest}
	record.ProvenanceDigest, err = RecordProvenanceDigest(record)
	if err != nil {
		return Result{}, newError(Unavailable, "delete_record_build_failed", false, err)
	}
	event, expectedEvent, err := completedDeleteEvent(record, state, authorization, attestation, completion)
	if err != nil {
		return Result{}, err
	}
	if err = service.appendAndVerifyDeleteAudit(auditContext, state.Command.Case, event, expectedEvent); err != nil {
		return Result{}, err
	}
	record.AuditEventDigest = expectedEvent
	record.RecordDigest, err = RecordBindingDigest(record)
	if err != nil {
		return Result{}, newError(Unavailable, "delete_record_build_failed", false, err)
	}
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: state.Command.RequestID, OperationID: progress.OperationID, Case: state.Command.Case,
		Operation: Delete, IdempotencyDigest: idempotency, IntentDigest: state.IntentDigest,
		DecisionDigest: state.FinalDecisionDigest, RecordDigest: record.RecordDigest, Artifacts: []EvidenceReference{},
		ArtifactSetDigest: &artifactSet, LifecycleReceiptDigest: &lifecycleDigest,
		AuthorizationCustodyReceiptDigest: &authorizationDigest,
		CompletionCustodyReceiptDigest:    &completionDigest, DispositionAttestationDigest: &attestationDigest,
		AuditEventDigest: expectedEvent, ProvenanceDigest: record.ProvenanceDigest, CreatedAt: progress.UpdatedAt}
	receipt.ReceiptDigest, err = ReceiptBindingDigest(receipt)
	if err != nil || ValidateRecord(record) != nil || ValidateReceipt(receipt) != nil {
		return Result{}, newError(Unavailable, "delete_result_build_failed", false, err)
	}
	stored, replayed, err := service.store.Commit(operationContext, state.Command.IdempotencyKey,
		state.IntentDigest, progress, record, receipt)
	if err != nil {
		return Result{}, mapExportDependency(operationContext, "delete_commit_unavailable", err)
	}
	if ValidateReceipt(stored) != nil || stored.Operation != Delete || stored.IntentDigest != state.IntentDigest ||
		stored.IdempotencyDigest != idempotency || stored.DispositionAttestationDigest == nil ||
		*stored.DispositionAttestationDigest != attestationDigest {
		return Result{}, newError(Denied, "stored_delete_receipt_invalid", false, nil)
	}
	return Result{Receipt: stored, Replayed: replayed}, nil
}

func completedDeleteEvent(record Record, state deleteState, authorization CustodyProofSet,
	attestation DispositionAttestation, completion CustodyProofSet) (tamperaudit.Event, string, error) {
	precommit, err := RecordPrecommitDigest(record)
	if err != nil {
		return tamperaudit.Event{}, "", err
	}
	digests := []string{precommit, record.IntentDigest, record.DecisionDigest, record.RevocationDigest,
		*state.Command.ApprovalDigest, *record.ArtifactSetDigest, *record.LifecycleReceiptDigest,
		*record.AuthorizationCustodyReceiptDigest, *record.CompletionCustodyReceiptDigest,
		attestation.AttestationDigest, record.ProvenanceDigest}
	for _, object := range attestation.Objects {
		digests = append(digests, object.ArtifactDigest, object.EncryptedObjectDigest, object.OutcomeDigest)
	}
	for _, proof := range append(append([]CustodyProof(nil), authorization.Proofs...), completion.Proofs...) {
		digests = append(digests, proof.ReceiptDigest, proof.RecordDigest, proof.AuditDigest, proof.Head.ChainHash)
	}
	sort.Strings(digests)
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID:        deterministicUUID("COH-EVIDENCE-LIFECYCLE-AUDIT-ID-V1\x00", record.OperationID+"\x00completed"),
		OrganizationID: record.Case.OrganizationID, TenantID: record.Case.TenantID, CaseID: record.Case.CaseID,
		ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision, SourceSchema: RecordSchemaVersion,
		Operation: "evidence.delete.completed", Outcome: "allowed", ReasonCode: "delete_completed",
		SubjectID: record.OperationID, SubjectRevision: 1, SubjectDigest: precommit,
		EvidenceDigests: uniqueLifecycleDigests(digests), OccurredAt: formatTime(record.CompletedAt)}
	if tamperaudit.ValidateEvent(event) != nil {
		return tamperaudit.Event{}, "", newError(Unavailable, "delete_audit_event_invalid", false, nil)
	}
	canonical, err := tamperaudit.CanonicalEvent(event)
	if err != nil {
		return tamperaudit.Event{}, "", newError(Unavailable, "delete_audit_event_invalid", false, err)
	}
	return event, digest("COH-EVIDENCE-LIFECYCLE-AUDIT-EVENT-V1\x00", canonical), nil
}
