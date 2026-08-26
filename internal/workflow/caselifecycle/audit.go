package caselifecycle

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type auditEvent = tamperaudit.Event

func allowedEvent(command Command, intent string, decision Decision, record Record,
	now time.Time) (auditEvent, string, error) {
	subject, err := transitionSubjectDigest(record)
	if err != nil {
		return auditEvent{}, "", err
	}
	event := makeAuditEvent(command, "allowed", "case_transition_applied", subject,
		record.Revision, sortedDigests(intent, command.PolicyDigest, decision.DecisionDigest,
			decision.RevocationDigest, previousDigest(record), commandReasonDigest(command)),
		decision.DecisionDigest, now)
	bound, err := auditEventBindingDigest(event)
	return event, bound, err
}

func allowedEventFromReceipt(receipt Receipt) (auditEvent, error) {
	subject, err := transitionSubjectDigest(receipt.Record)
	if err != nil {
		return auditEvent{}, err
	}
	command := cloneCommand(receipt.Command)
	event := makeAuditEvent(command, "allowed", "case_transition_applied", subject,
		receipt.Record.Revision, sortedDigests(receipt.IntentDigest, receipt.Record.PolicyDigest,
			receipt.DecisionDigest, receipt.RevocationDigest, previousDigest(receipt.Record), commandReasonDigest(command)),
		receipt.DecisionDigest, receipt.CreatedAt)
	bound, digestErr := auditEventBindingDigest(event)
	if digestErr != nil || bound != receipt.AuditEventDigest {
		return auditEvent{}, newError(Denied, "audit_proof_invalid", false, digestErr)
	}
	return event, nil
}

func replayEvent(command Command, decision Decision, receipt Receipt, now time.Time) auditEvent {
	return makeAuditEvent(command, "allowed", "replay_authorized", receipt.Record.ProvenanceDigest,
		receipt.Record.Revision, sortedDigests(receipt.IntentDigest, receipt.ReceiptDigest,
			receipt.AuditEventDigest, decision.DecisionDigest, decision.RevocationDigest),
		decision.DecisionDigest, now)
}

func (controller *Controller) deny(ctx context.Context, command Command, intent string, decision Decision,
	reason string, now time.Time, revision uint64) error {
	if !tokenPattern.MatchString(reason) {
		reason = "request_denied"
	}
	event := makeAuditEvent(command, "denied", reason, intent, revision,
		sortedDigests(intent, command.PolicyDigest, decision.DecisionDigest, decision.RevocationDigest,
			commandReasonDigest(command)), decision.DecisionDigest, now)
	if err := controller.appendAudit(ctx, event); err != nil {
		return err
	}
	code := Denied
	if reason == "case_not_found" {
		code = NotFound
	}
	if reason == "stale_revision" || reason == "case_already_exists" || reason == "concurrent_conflict" {
		code = Conflict
	}
	return newError(code, reason, false, nil)
}

func makeAuditEvent(command Command, outcome, reason, subjectDigest string, revision uint64,
	evidence []string, identity string, now time.Time) auditEvent {
	if identity == "" {
		identity = subjectDigest
	}
	return auditEvent{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID:        deterministicUUID("COH-CASE-AUDIT-ID-V1\x00", command.RequestID+"\x00"+identity+"\x00"+outcome+"\x00"+reason),
		OrganizationID: command.Case.OrganizationID, TenantID: command.Case.TenantID, CaseID: command.Case.CaseID,
		ActorID: command.ActorID, ActorRevision: command.ActorRevision, SourceSchema: CommandSchemaVersion,
		Operation: "case." + string(command.Operation), Outcome: outcome, ReasonCode: reason,
		SubjectID: command.Case.CaseID, SubjectRevision: revision, SubjectDigest: subjectDigest,
		EvidenceDigests: evidence, OccurredAt: formatTime(now)}
}

func auditEventBindingDigest(value auditEvent) (string, error) {
	canonical, err := tamperaudit.CanonicalEvent(value)
	if err != nil {
		return "", newError(InternalFailure, "audit_event_invalid", false, err)
	}
	return digest("COH-CASE-AUDIT-EVENT-V1\x00", canonical), nil
}

func transitionSubjectDigest(value Record) (string, error) {
	copyValue := cloneRecord(value)
	copyValue.AuditEventDigest = ""
	copyValue.ProvenanceDigest = ""
	canonical, err := canonicalValue(recordToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-CASE-TRANSITION-V1\x00", canonical), nil
}

func previousDigest(value Record) string {
	if value.PreviousProvenanceDigest == nil {
		return ""
	}
	return *value.PreviousProvenanceDigest
}

func commandReasonDigest(value Command) string {
	if value.ReasonDigest != nil {
		return *value.ReasonDigest
	}
	if value.ExportManifestDigest != nil {
		return *value.ExportManifestDigest
	}
	return ""
}

func sortedDigests(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if digestPattern.MatchString(value) && !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func (controller *Controller) appendAudit(ctx context.Context, event auditEvent) error {
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
