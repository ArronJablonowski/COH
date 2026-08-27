package redaction

import (
	"context"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func buildRedactionRecord(state authorizedState, published publicationResult,
	custody CustodyProof, now time.Time) (Record, error) {
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion,
		RedactionID: deterministicUUID("COH-REDACTION-RECORD-ID-V1\x00",
			state.Command.RequestID+"\x00"+state.Decision.DecisionDigest+"\x00"+published.Derivation.DerivedArtifact.Digest),
		Case: state.Command.Case, Command: cloneCommand(state.Command), IntentDigest: state.IntentDigest,
		PlanDigest: state.Plan.PlanDigest, DecisionDigest: state.Decision.DecisionDigest,
		RevocationDigest: state.Decision.RevocationDigest, ApprovalUseDigest: state.Approval.UseDigest,
		SourceVerificationDigest: state.Source.VerificationDigest, Derived: published.Derived.Reference,
		DerivedIngestionReceiptDigest: published.Derived.ReceiptDigest, MappingReference: published.Mapping.Reference,
		MappingDigest:                 published.Derivation.Mapping.MappingDigest,
		MappingIngestionReceiptDigest: published.Mapping.ReceiptDigest, CustodyReceiptDigest: custody.ReceiptDigest,
		CreatedAt: now, PreviousProvenanceDigest: state.Command.Source.ManifestProvenanceDigest}
	record.ProvenanceDigest, _ = RecordProvenanceDigest(record)
	if !digestPattern.MatchString(record.ProvenanceDigest) {
		return Record{}, newError(InternalFailure, "record_provenance_build_failed", false, nil)
	}
	return record, nil
}

func completedRedactionEvent(record Record, custody CustodyProof) (tamperaudit.Event, string, error) {
	precommit, err := RecordPrecommitDigest(record)
	if err != nil {
		return tamperaudit.Event{}, "", err
	}
	digests := []string{precommit, record.IntentDigest, record.PlanDigest, record.DecisionDigest,
		record.RevocationDigest, record.ApprovalUseDigest, record.SourceVerificationDigest,
		record.Command.Source.Artifact.Digest, record.Command.Source.Manifest.Digest,
		record.Derived.Artifact.Digest, record.Derived.Manifest.Digest, record.DerivedIngestionReceiptDigest,
		record.MappingReference.Artifact.Digest, record.MappingReference.Manifest.Digest, record.MappingDigest,
		record.MappingIngestionReceiptDigest, custody.ReceiptDigest, custody.RecordDigest, custody.ChainHash,
		custody.AuditDigest, record.ProvenanceDigest}
	sort.Strings(digests)
	digests = uniqueDigests(digests)
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID:        deterministicUUID("COH-REDACTION-AUDIT-ID-V1\x00", record.RedactionID+"\x00completed"),
		OrganizationID: record.Case.OrganizationID, TenantID: record.Case.TenantID, CaseID: record.Case.CaseID,
		ActorID: record.Command.ActorID, ActorRevision: record.Command.ActorRevision,
		SourceSchema: RecordSchemaVersion, Operation: "evidence.redaction.completed", Outcome: "allowed",
		ReasonCode: "redaction_completed", SubjectID: record.RedactionID, SubjectRevision: 1,
		SubjectDigest: precommit, EvidenceDigests: digests, OccurredAt: formatTime(record.CreatedAt)}
	if tamperaudit.ValidateEvent(event) != nil {
		return tamperaudit.Event{}, "", newError(InternalFailure, "audit_event_invalid", false, nil)
	}
	canonical, err := tamperaudit.CanonicalEvent(event)
	if err != nil {
		return tamperaudit.Event{}, "", newError(InternalFailure, "audit_event_invalid", false, err)
	}
	return event, digest("COH-REDACTION-AUDIT-EVENT-V1\x00", canonical), nil
}

func (service *orchestrator) appendAndVerifyAudit(ctx context.Context, scope domain.CaseRef,
	event tamperaudit.Event, expected string) (AuditProof, error) {
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	proof, err := service.auditor.AppendRedactionEvent(auditCtx, event)
	if err != nil {
		return AuditProof{}, newError(Unavailable, "audit_append_unavailable", true, err)
	}
	if !validAuditProof(proof) || proof.EventDigest != expected {
		return AuditProof{}, newError(Denied, "audit_proof_invalid", false, nil)
	}
	verified, err := service.auditor.VerifyRedactionEvent(auditCtx, scope, event.EventID, expected)
	if err != nil {
		return AuditProof{}, newError(Unavailable, "audit_verification_unavailable", true, err)
	}
	if !validAuditProof(verified) || verified != proof {
		return AuditProof{}, newError(Denied, "audit_verification_invalid", false, nil)
	}
	return proof, nil
}

func validAuditProof(value AuditProof) bool {
	return value.Sequence > 0 && allDigests(value.EventDigest, value.ChainHash)
}
func uniqueDigests(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func buildRedactionReceipt(state authorizedState, record Record, now time.Time) (Receipt, error) {
	idempotency, err := IdempotencyBindingDigest(state.Command.IdempotencyKey)
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: state.Command.RequestID, Case: state.Command.Case, IdempotencyDigest: idempotency,
		IntentDigest: state.IntentDigest, RedactionID: record.RedactionID, RecordDigest: record.RecordDigest,
		Derived: cloneEvidence(record.Derived), MappingReference: cloneEvidence(record.MappingReference),
		MappingDigest: record.MappingDigest, CustodyReceiptDigest: record.CustodyReceiptDigest,
		AuditEventDigest: record.AuditEventDigest, ProvenanceDigest: record.ProvenanceDigest, CreatedAt: now}
	receipt.ReceiptDigest, err = ReceiptBindingDigest(receipt)
	if err != nil || ValidateReceipt(receipt) != nil {
		return Receipt{}, newError(InternalFailure, "receipt_build_failed", false, err)
	}
	return receipt, nil
}
