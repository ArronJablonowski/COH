package broker

import (
	"context"

	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type durableApprovalAppender interface {
	AppendAuditEvent(context.Context, tamperaudit.Event) error
}

type durableApprovalAuditSink struct{ appender durableApprovalAppender }

func newDurableApprovalAuditSink(appender durableApprovalAppender) (*durableApprovalAuditSink, error) {
	if appender == nil {
		return nil, lifecycle.NewError(lifecycle.InvalidInput, "audit_dependencies")
	}
	return &durableApprovalAuditSink{appender: appender}, nil
}

func (sink *durableApprovalAuditSink) AppendApprovalLifecycleEvent(ctx context.Context, source lifecycle.Event) error {
	if sink == nil || sink.appender == nil || lifecycle.ValidateEvent(source) != nil {
		return lifecycle.NewError(lifecycle.Unavailable, "audit_unavailable")
	}
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: source.EventID, OrganizationID: source.OrganizationID, TenantID: source.TenantID,
		CaseID: source.CaseID, ActorID: source.ActorID, ActorRevision: source.ActorRevision,
		SourceSchema: lifecycle.SchemaVersion, Operation: source.Operation, Outcome: source.Outcome,
		ReasonCode: source.ReasonCode, SubjectID: source.ApprovalID, SubjectRevision: source.RecordRevision,
		EvidenceDigests: []string{}, OccurredAt: source.OccurredAt}
	if source.FingerprintDigest != "" {
		event.SubjectDigest = source.FingerprintDigest
	}
	if tamperaudit.ValidateEvent(event) != nil || sink.appender.AppendAuditEvent(ctx, event) != nil {
		return lifecycle.NewError(lifecycle.Unavailable, "audit_unavailable")
	}
	return nil
}
