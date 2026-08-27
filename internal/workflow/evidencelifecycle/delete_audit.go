package evidencelifecycle

import (
	"context"
	"sort"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func (service *DeleteService) appendAndVerifyDeleteAudit(ctx context.Context, scope domain.CaseRef,
	event tamperaudit.Event, expected string) error {
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if err := service.auditor.AppendLifecycleEvent(auditCtx, event); err != nil {
		return newError(Unavailable, "delete_audit_append_unavailable", true, err)
	}
	if err := service.auditor.VerifyLifecycleEvent(auditCtx, scope, event.EventID, expected); err != nil {
		return newError(Unavailable, "delete_audit_verification_unavailable", true, err)
	}
	return nil
}

func (service *DeleteService) auditDeleteDenial(ctx context.Context, command Command, failure error) error {
	if ctx == nil || command.Operation != Delete || validateCommandShape(command) != nil {
		return nil
	}
	now := service.clock.Now()
	if !validTime(now) {
		return newError(Unavailable, "clock_invalid", false, nil)
	}
	intent, err := IntentBindingDigest(command)
	if err != nil {
		return nil
	}
	reason := Reason(failure)
	if !tokenPattern.MatchString(reason) {
		reason = "dependency_unavailable"
	}
	digests := []string{intent, *command.ArtifactSetDigest, *command.ReasonDigest, *command.ApprovalDigest,
		command.PolicyDigest, command.ExpectedCustodyHead.ChainHash}
	sort.Strings(digests)
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: deterministicUUID("COH-EVIDENCE-LIFECYCLE-AUDIT-ID-V1\x00",
			command.RequestID+"\x00"+intent+"\x00denied\x00"+reason),
		OrganizationID: command.Case.OrganizationID, TenantID: command.Case.TenantID, CaseID: command.Case.CaseID,
		ActorID: command.ActorID, ActorRevision: command.ActorRevision, SourceSchema: CommandSchemaVersion,
		Operation: "evidence.delete.denied", Outcome: "denied", ReasonCode: reason,
		SubjectID: command.RequestID, SubjectDigest: intent, EvidenceDigests: uniqueLifecycleDigests(digests),
		OccurredAt: formatTime(now)}
	if tamperaudit.ValidateEvent(event) != nil {
		return newError(Unavailable, "delete_denial_audit_invalid", false, nil)
	}
	canonical, err := tamperaudit.CanonicalEvent(event)
	if err != nil {
		return newError(Unavailable, "delete_denial_audit_invalid", false, err)
	}
	expected := digest("COH-EVIDENCE-LIFECYCLE-AUDIT-EVENT-V1\x00", canonical)
	return service.appendAndVerifyDeleteAudit(ctx, command.Case, event, expected)
}
