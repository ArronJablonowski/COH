package custody

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func allowedAuditEvent(record Record) (tamperaudit.Event, error) {
	precommit, err := RecordPrecommitDigest(record)
	if err != nil {
		return tamperaudit.Event{}, err
	}
	command := record.Command
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion,
		ContractVersion: tamperaudit.ContractVersion,
		EventID:         deterministicUUID("COH-CUSTODY-AUDIT-ID-V1\x00", record.CustodyID+"\x00recorded"),
		OrganizationID:  command.Case.OrganizationID, TenantID: command.Case.TenantID,
		CaseID: command.Case.CaseID, ActorID: command.ActorID, ActorRevision: command.ActorRevision,
		SourceSchema: CommandSchemaVersion, Operation: "evidence.custody." + string(command.Operation),
		Outcome: "allowed", ReasonCode: "custody_recorded", SubjectID: record.CustodyID,
		SubjectRevision: record.Sequence, SubjectDigest: command.Subject.Artifact.Digest,
		EvidenceDigests: sortedDigests(precommit, record.PreviousChainHash, record.IntentDigest,
			record.AuthorizationDigest, record.DecisionDigest, record.RevocationDigest,
			record.EvidenceVerifiedDigest, command.Subject.Artifact.Digest, command.Subject.Manifest.Digest,
			command.Subject.ManifestProvenanceDigest, command.Subject.IngestionReceiptDigest,
			record.ProvenanceDigest), OccurredAt: formatTime(record.OccurredAt)}
	if tamperaudit.ValidateEvent(event) != nil {
		return tamperaudit.Event{}, newError(InternalFailure, "audit_event_invalid", false, nil)
	}
	return event, nil
}

func replayAuditEvent(command Command, decision Decision, receipt Receipt, now time.Time) tamperaudit.Event {
	return tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion,
		ContractVersion: tamperaudit.ContractVersion,
		EventID: deterministicUUID("COH-CUSTODY-AUDIT-ID-V1\x00",
			receipt.CustodyID+"\x00"+decision.DecisionDigest+"\x00replay"),
		OrganizationID: command.Case.OrganizationID, TenantID: command.Case.TenantID,
		CaseID: command.Case.CaseID, ActorID: command.ActorID, ActorRevision: command.ActorRevision,
		SourceSchema: CommandSchemaVersion, Operation: "evidence.custody.replay", Outcome: "allowed",
		ReasonCode: "replay_authorized", SubjectID: receipt.CustodyID, SubjectRevision: receipt.Sequence,
		SubjectDigest: receipt.RecordDigest, EvidenceDigests: sortedDigests(receipt.IntentDigest,
			receipt.ReceiptDigest, receipt.AuditEventDigest, decision.DecisionDigest,
			decision.RevocationDigest), OccurredAt: formatTime(now)}
}

func auditEventBindingDigest(value tamperaudit.Event) (string, error) {
	canonical, err := tamperaudit.CanonicalEvent(value)
	if err != nil {
		return "", newError(InternalFailure, "audit_event_invalid", false, err)
	}
	return digest("COH-CUSTODY-AUDIT-EVENT-V1\x00", canonical), nil
}

func (controller *Controller) appendAudit(ctx context.Context, event tamperaudit.Event) (AuditProof, error) {
	if tamperaudit.ValidateEvent(event) != nil {
		return AuditProof{}, newError(InternalFailure, "audit_event_invalid", false, nil)
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	proof, err := controller.auditor.AppendCustodyEvent(auditCtx, event)
	if err != nil {
		return AuditProof{}, newError(Unavailable, "audit_unavailable", true, nil)
	}
	want, err := auditEventBindingDigest(event)
	if err != nil || !validAuditProof(proof) || proof.EventDigest != want {
		return AuditProof{}, newError(Denied, "audit_proof_invalid", false, err)
	}
	return proof, nil
}

func validAuditProof(value AuditProof) bool {
	if !allDigests(value.EventDigest, value.ChainHash) || value.Sequence == 0 ||
		(value.CheckpointID == nil) != (value.CheckpointDigest == nil) {
		return false
	}
	return value.CheckpointID == nil || uuidPattern.MatchString(*value.CheckpointID) &&
		digestPattern.MatchString(*value.CheckpointDigest)
}
