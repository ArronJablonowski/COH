package evidenceingest

import (
	"context"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func allowedEvent(command Command, intent string, decision Decision, now time.Time) tamperaudit.Event {
	contextDigest := stageRequest(command.Case, command.ExpectedDigest, command.ExpectedLength, command.MediaType,
		command.Classification, command.KeyProfile, command.KeyProfileDigest, command.Deadline).EncryptionContextDigest
	return makeAuditEvent(command, "allowed", "evidence_ingested", command.ExpectedDigest,
		sortedDigests(intent, command.PolicyDigest, command.KeyProfileDigest, command.Source.IdentityDigest,
			contextDigest, decision.AuthorizationDigest, decision.DecisionDigest, decision.RevocationDigest,
			decision.TransportDigest),
		decision.DecisionDigest, now)
}

func allowedEventFromReceipt(command Command, receipt Receipt) (tamperaudit.Event, error) {
	event := makeAuditEvent(command, "allowed", "evidence_ingested", receipt.Artifact.Digest,
		sortedDigests(receipt.IntentDigest, command.PolicyDigest, command.KeyProfileDigest, command.Source.IdentityDigest,
			receipt.EncryptedArtifact.EncryptionContextDigest, receipt.AuthorizationDigest, receipt.DecisionDigest,
			receipt.RevocationDigest, receipt.TransportDigest),
		receipt.DecisionDigest, receipt.CreatedAt)
	bound, err := auditEventBindingDigest(event)
	if err != nil || bound != receipt.AuditEventDigest {
		return tamperaudit.Event{}, newError(Denied, "audit_proof_invalid", false, err)
	}
	return event, nil
}

func replayEvent(command Command, decision Decision, receipt Receipt, now time.Time) tamperaudit.Event {
	return makeAuditEvent(command, "allowed", "replay_authorized", receipt.Artifact.Digest,
		sortedDigests(receipt.IntentDigest, receipt.ReceiptDigest, receipt.AuditEventDigest,
			decision.DecisionDigest, decision.RevocationDigest), decision.DecisionDigest, now)
}

func (controller *Controller) deny(ctx context.Context, command Command, intent string, decision Decision,
	reason string, now time.Time) error {
	if !tokenPattern.MatchString(reason) {
		reason = "request_denied"
	}
	event := makeAuditEvent(command, "denied", reason, command.ExpectedDigest,
		sortedDigests(intent, command.PolicyDigest, command.KeyProfileDigest, decision.AuthorizationDigest,
			decision.DecisionDigest, decision.RevocationDigest), decision.DecisionDigest, now)
	if err := controller.appendAudit(ctx, event); err != nil {
		return err
	}
	code := Denied
	if reason == "case_not_found" {
		code = NotFound
	}
	if reason == "changed_replay" || reason == "concurrent_conflict" {
		code = Conflict
	}
	return newError(code, reason, false, nil)
}

func makeAuditEvent(command Command, outcome, reason, subjectDigest string, evidence []string,
	identity string, now time.Time) tamperaudit.Event {
	if identity == "" {
		identity = subjectDigest
	}
	return tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion,
		ContractVersion: tamperaudit.ContractVersion,
		EventID: deterministicUUID("COH-EVIDENCE-INGEST-AUDIT-ID-V1\x00",
			command.RequestID+"\x00"+identity+"\x00"+outcome+"\x00"+reason),
		OrganizationID: command.Case.OrganizationID, TenantID: command.Case.TenantID, CaseID: command.Case.CaseID,
		ActorID: command.ActorID, ActorRevision: command.ActorRevision, SourceSchema: CommandSchemaVersion,
		Operation: "evidence.ingest", Outcome: outcome, ReasonCode: reason, SubjectID: command.Case.CaseID,
		SubjectDigest: subjectDigest, EvidenceDigests: evidence, OccurredAt: formatTime(now)}
}

func auditEventBindingDigest(value tamperaudit.Event) (string, error) {
	canonical, err := tamperaudit.CanonicalEvent(value)
	if err != nil {
		return "", newError(InternalFailure, "audit_event_invalid", false, err)
	}
	return digest("COH-EVIDENCE-INGEST-AUDIT-EVENT-V1\x00", canonical), nil
}

func sortedDigests(values ...string) []string {
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if digestPattern.MatchString(value) {
			unique[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func (controller *Controller) appendAudit(ctx context.Context, event tamperaudit.Event) error {
	if tamperaudit.ValidateEvent(event) != nil {
		return newError(InternalFailure, "audit_event_invalid", false, nil)
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := controller.auditor.AppendAuditEvent(auditCtx, event); err != nil {
		return newError(Unavailable, "audit_unavailable", true, nil)
	}
	return nil
}
