package redaction

import (
	"context"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

func (service *orchestrator) auditDenial(ctx context.Context, command Command, failure error) error {
	if ctx == nil || validateCommandShape(command) != nil {
		return nil
	}
	now := service.clock.Now()
	if !validTime(now) {
		return newError(InternalFailure, "clock_invalid", false, nil)
	}
	intent, err := IntentBindingDigest(command)
	if err != nil {
		return nil
	}
	reason := Reason(failure)
	if !tokenPattern.MatchString(reason) {
		reason = "dependency_unavailable"
	}
	digests := []string{intent, command.Source.Artifact.Digest, command.Source.Manifest.Digest,
		command.Source.ManifestProvenanceDigest, command.Source.IngestionReceiptDigest, command.RuleDigest,
		command.PlanDigest, command.ReasonDigest, command.KeyProfileDigest, command.PolicyDigest,
		command.ExpectedCustodyHead.ChainHash}
	sort.Strings(digests)
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: deterministicUUID("COH-REDACTION-AUDIT-ID-V1\x00",
			command.RequestID+"\x00"+intent+"\x00denied\x00"+reason),
		OrganizationID: command.Case.OrganizationID, TenantID: command.Case.TenantID, CaseID: command.Case.CaseID,
		ActorID: command.ActorID, ActorRevision: command.ActorRevision, SourceSchema: CommandSchemaVersion,
		Operation: "evidence.redaction.denied", Outcome: "denied", ReasonCode: reason,
		SubjectID: command.RequestID, SubjectDigest: intent, EvidenceDigests: uniqueDigests(digests),
		OccurredAt: formatTime(now)}
	if tamperaudit.ValidateEvent(event) != nil {
		return newError(InternalFailure, "denial_audit_event_invalid", false, nil)
	}
	canonical, err := tamperaudit.CanonicalEvent(event)
	if err != nil {
		return newError(InternalFailure, "denial_audit_event_invalid", false, err)
	}
	expected := digest("COH-REDACTION-AUDIT-EVENT-V1\x00", canonical)
	if _, err = service.appendAndVerifyAudit(ctx, command.Case, event, expected); err != nil {
		return err
	}
	return nil
}
