package evidencelifecycle

import (
	"context"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func (service *ImportService) commitImport(auditContext, operationContext context.Context, state importState,
	idempotency string, published PublishedImport, custody CustodyProofSet, progress Progress) (Result, error) {
	progress.Phase, progress.Revision, progress.UpdatedAt = Completed, progress.Revision+1, service.clock.Now()
	progress.ProgressDigest = ""
	var err error
	progress.ProgressDigest, err = ProgressBindingDigest(progress)
	if err != nil || ValidateProgress(progress) != nil {
		return Result{}, newError(Unavailable, "import_completed_progress_invalid", false, err)
	}
	manifestDigest, signatureDigest := state.Verified.Manifest.ManifestDigest, state.Verified.Package.SignatureDigest
	packageDigest, verificationDigest := state.Verified.Package.PackageDigest, state.Verified.Verification.ReportDigest
	artifactSet, custodyDigest := state.Verified.Verification.ArtifactSetDigest, custody.ReceiptSetDigest
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion,
		OperationID: progress.OperationID, Case: state.Command.Case, Operation: Import,
		CommandDigest: progress.CommandDigest, IntentDigest: state.IntentDigest,
		DecisionDigest: state.FinalDecisionDigest, RevocationDigest: state.FinalRevocationDigest,
		Artifacts: published.Artifacts, ArtifactSetDigest: &artifactSet, PackageDigest: &packageDigest,
		ManifestDigest: &manifestDigest, SignatureDigest: &signatureDigest,
		VerificationReportDigest: &verificationDigest, CompletionCustodyReceiptDigest: &custodyDigest,
		CompletedAt: progress.UpdatedAt, PreviousProvenanceDigest: state.Case.ProvenanceDigest}
	record.ProvenanceDigest, err = RecordProvenanceDigest(record)
	if err != nil {
		return Result{}, newError(Unavailable, "import_record_build_failed", false, err)
	}
	event, expectedEvent, err := completedImportEvent(record, state, custody)
	if err != nil {
		return Result{}, err
	}
	if err = service.appendAndVerifyImportAudit(auditContext, state.Command.Case, event, expectedEvent); err != nil {
		return Result{}, err
	}
	record.AuditEventDigest = expectedEvent
	record.RecordDigest, err = RecordBindingDigest(record)
	if err != nil {
		return Result{}, newError(Unavailable, "import_record_build_failed", false, err)
	}
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: state.Command.RequestID, OperationID: progress.OperationID, Case: state.Command.Case,
		Operation: Import, IdempotencyDigest: idempotency, IntentDigest: state.IntentDigest,
		DecisionDigest: state.FinalDecisionDigest, RecordDigest: record.RecordDigest,
		Artifacts: published.Artifacts, ArtifactSetDigest: &artifactSet, PackageDigest: &packageDigest,
		ManifestDigest: &manifestDigest, SignatureDigest: &signatureDigest,
		VerificationReportDigest: &verificationDigest, CompletionCustodyReceiptDigest: &custodyDigest,
		AuditEventDigest: expectedEvent, ProvenanceDigest: record.ProvenanceDigest, CreatedAt: progress.UpdatedAt}
	receipt.ReceiptDigest, err = ReceiptBindingDigest(receipt)
	if err != nil || ValidateRecord(record) != nil || ValidateReceipt(receipt) != nil {
		return Result{}, newError(Unavailable, "import_result_build_failed", false, err)
	}
	stored, replayed, err := service.store.Commit(operationContext, state.Command.IdempotencyKey,
		state.IntentDigest, progress, record, receipt)
	if err != nil {
		return Result{}, mapExportDependency(operationContext, "import_commit_unavailable", err)
	}
	if ValidateReceipt(stored) != nil || stored.Operation != Import || stored.IntentDigest != state.IntentDigest ||
		stored.IdempotencyDigest != idempotency || stored.PackageDigest == nil ||
		*stored.PackageDigest != packageDigest || !sameEvidenceReferences(stored.Artifacts, published.Artifacts) {
		return Result{}, newError(Denied, "stored_import_receipt_invalid", false, nil)
	}
	return Result{Receipt: stored, Imported: append([]EvidenceReference(nil), stored.Artifacts...), Replayed: replayed}, nil
}

func completedImportEvent(record Record, state importState,
	custody CustodyProofSet) (tamperaudit.Event, string, error) {
	precommit, err := RecordPrecommitDigest(record)
	if err != nil {
		return tamperaudit.Event{}, "", err
	}
	digests := []string{precommit, record.IntentDigest, record.DecisionDigest, record.RevocationDigest,
		*record.ArtifactSetDigest, *record.ManifestDigest, *record.SignatureDigest, *record.PackageDigest,
		*record.VerificationReportDigest, custody.ReceiptSetDigest, record.ProvenanceDigest}
	for _, proof := range custody.Proofs {
		digests = append(digests, proof.ReceiptDigest, proof.RecordDigest, proof.AuditDigest, proof.Head.ChainHash)
	}
	sort.Strings(digests)
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID:        deterministicUUID("COH-EVIDENCE-LIFECYCLE-AUDIT-ID-V1\x00", record.OperationID+"\x00completed"),
		OrganizationID: record.Case.OrganizationID, TenantID: record.Case.TenantID, CaseID: record.Case.CaseID,
		ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision, SourceSchema: RecordSchemaVersion,
		Operation: "evidence.import.completed", Outcome: "allowed", ReasonCode: "import_completed",
		SubjectID: record.OperationID, SubjectRevision: 1, SubjectDigest: precommit,
		EvidenceDigests: uniqueLifecycleDigests(digests), OccurredAt: formatTime(record.CompletedAt)}
	if tamperaudit.ValidateEvent(event) != nil {
		return tamperaudit.Event{}, "", newError(Unavailable, "import_audit_event_invalid", false, nil)
	}
	canonical, err := tamperaudit.CanonicalEvent(event)
	if err != nil {
		return tamperaudit.Event{}, "", newError(Unavailable, "import_audit_event_invalid", false, err)
	}
	return event, digest("COH-EVIDENCE-LIFECYCLE-AUDIT-EVENT-V1\x00", canonical), nil
}

func sameEvidenceReferences(left, right []EvidenceReference) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
