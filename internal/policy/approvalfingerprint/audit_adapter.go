package approvalfingerprint

import (
	"context"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/policy"
)

type durableAuditAppender interface {
	AppendAuditEvent(context.Context, tamperaudit.Event) error
}

type DurableAuditSink struct{ appender durableAuditAppender }

func NewDurableAuditSink(appender durableAuditAppender) (*DurableAuditSink, error) {
	if appender == nil {
		return nil, policy.NewError(policy.InvalidInput, "audit_dependencies")
	}
	return &DurableAuditSink{appender: appender}, nil
}

func (sink *DurableAuditSink) AppendApprovalFingerprintEvent(ctx context.Context, source AuditEvent) error {
	if sink == nil || sink.appender == nil {
		return policy.NewError(policy.Unavailable, "audit_unavailable")
	}
	evidence := []string{}
	for _, digest := range []string{source.FingerprintDigest, source.ManifestDigest, source.PolicyDecisionDigest} {
		if digest != "" {
			evidence = append(evidence, digest)
		}
	}
	slices.Sort(evidence)
	evidence = slices.Compact(evidence)
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: source.EventID, OrganizationID: source.OrganizationID, TenantID: source.TenantID,
		CaseID: source.CaseID, ActorID: source.ActorID, ActorRevision: source.ActorRevision,
		SourceSchema: SchemaVersion, Operation: source.Operation, Outcome: source.Outcome,
		ReasonCode: source.ReasonCode, SubjectDigest: source.FingerprintDigest,
		EvidenceDigests: evidence, OccurredAt: source.OccurredAt}
	if tamperaudit.ValidateEvent(event) != nil || sink.appender.AppendAuditEvent(ctx, event) != nil {
		return policy.NewError(policy.Unavailable, "audit_unavailable")
	}
	return nil
}
