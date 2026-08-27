package evidencelifecycle

import (
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func buildExportResult(state exportState, idempotency string, authorization, completion CustodyProof,
	lifecycle LifecycleProof, manifest ExportManifest, signature DetachedSignature, packaged QuarantinedPackage,
	progress Progress) (Record, Receipt, Progress, tamperaudit.Event, string, error) {
	signatureDigest, err := SignatureBindingDigest(signature)
	if err != nil {
		return Record{}, Receipt{}, Progress{}, tamperaudit.Event{}, "", err
	}
	progress.Phase, progress.Revision = Completed, progress.Revision+1
	progress.ProgressDigest = ""
	progress.ProgressDigest, err = ProgressBindingDigest(progress)
	if err != nil || ValidateProgress(progress) != nil {
		return Record{}, Receipt{}, Progress{}, tamperaudit.Event{}, "",
			newError(Unavailable, "export_completed_progress_invalid", false, err)
	}
	packageDigest, manifestDigest := packaged.PackageDigest, manifest.ManifestDigest
	lifecycleDigest, authorizationDigest, completionDigest := lifecycle.ReceiptDigest,
		authorization.ReceiptDigest, completion.ReceiptDigest
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion,
		OperationID: progress.OperationID, Case: state.Command.Case, Operation: Export,
		CommandDigest: progress.CommandDigest, IntentDigest: state.IntentDigest,
		DecisionDigest: state.Decision.DecisionDigest, RevocationDigest: state.Decision.RevocationDigest,
		ArtifactSetDigest: state.Command.ArtifactSetDigest, PackageDigest: &packageDigest,
		ManifestDigest: &manifestDigest, SignatureDigest: &signatureDigest,
		LifecycleReceiptDigest: &lifecycleDigest, AuthorizationCustodyReceiptDigest: &authorizationDigest,
		CompletionCustodyReceiptDigest: &completionDigest, CompletedAt: progress.UpdatedAt,
		PreviousProvenanceDigest: state.Case.ProvenanceDigest}
	record.ProvenanceDigest, err = RecordProvenanceDigest(record)
	if err != nil {
		return Record{}, Receipt{}, Progress{}, tamperaudit.Event{}, "", err
	}
	event, expected, err := completedExportEvent(record, manifest, signatureDigest, authorization, completion, lifecycle)
	if err != nil {
		return Record{}, Receipt{}, Progress{}, tamperaudit.Event{}, "", err
	}
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: state.Command.RequestID, OperationID: progress.OperationID, Case: state.Command.Case,
		Operation: Export, IdempotencyDigest: idempotency, IntentDigest: state.IntentDigest,
		DecisionDigest: state.Decision.DecisionDigest, ArtifactSetDigest: state.Command.ArtifactSetDigest,
		PackageDigest: &packageDigest, ManifestDigest: &manifestDigest, SignatureDigest: &signatureDigest,
		LifecycleReceiptDigest: &lifecycleDigest, CompletionCustodyReceiptDigest: &completionDigest,
		ProvenanceDigest: record.ProvenanceDigest, CreatedAt: progress.UpdatedAt}
	return record, receipt, progress, event, expected, nil
}

func completedExportEvent(record Record, manifest ExportManifest, signatureDigest string,
	authorization, completion CustodyProof, lifecycle LifecycleProof) (tamperaudit.Event, string, error) {
	precommit, err := RecordPrecommitDigest(record)
	if err != nil {
		return tamperaudit.Event{}, "", err
	}
	digests := []string{precommit, record.IntentDigest, record.DecisionDigest, record.RevocationDigest,
		*record.ArtifactSetDigest, manifest.ManifestDigest, signatureDigest, *record.PackageDigest,
		authorization.ReceiptDigest, authorization.RecordDigest, authorization.AuditDigest,
		completion.ReceiptDigest, completion.RecordDigest, completion.AuditDigest,
		lifecycle.ReceiptDigest, lifecycle.ProvenanceDigest, record.ProvenanceDigest}
	sort.Strings(digests)
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID:        deterministicUUID("COH-EVIDENCE-LIFECYCLE-AUDIT-ID-V1\x00", record.OperationID+"\x00completed"),
		OrganizationID: record.Case.OrganizationID, TenantID: record.Case.TenantID, CaseID: record.Case.CaseID,
		ActorID: manifest.ActorID, ActorRevision: manifest.ActorRevision, SourceSchema: RecordSchemaVersion,
		Operation: "evidence.export.completed", Outcome: "allowed", ReasonCode: "export_completed",
		SubjectID: record.OperationID, SubjectRevision: 1, SubjectDigest: precommit,
		EvidenceDigests: uniqueLifecycleDigests(digests), OccurredAt: formatTime(record.CompletedAt)}
	if tamperaudit.ValidateEvent(event) != nil {
		return tamperaudit.Event{}, "", newError(Unavailable, "export_audit_event_invalid", false, nil)
	}
	canonical, err := tamperaudit.CanonicalEvent(event)
	if err != nil {
		return tamperaudit.Event{}, "", newError(Unavailable, "export_audit_event_invalid", false, err)
	}
	return event, digest("COH-EVIDENCE-LIFECYCLE-AUDIT-EVENT-V1\x00", canonical), nil
}

func uniqueLifecycleDigests(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
