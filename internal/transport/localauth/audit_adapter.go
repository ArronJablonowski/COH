package localauth

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type durableAuditAppender interface {
	AppendAuditEvent(context.Context, tamperaudit.Event) error
}

type DurableAuditSink struct{ appender durableAuditAppender }

func NewDurableAuditSink(appender durableAuditAppender) (*DurableAuditSink, error) {
	if appender == nil {
		return nil, authError(localidentity.InvalidInput, "audit_dependencies")
	}
	return &DurableAuditSink{appender: appender}, nil
}

func (sink *DurableAuditSink) AppendAuthenticationEvent(ctx context.Context, source AuthenticationEvent) error {
	subjectID := source.SessionID
	if subjectID == "" {
		subjectID = source.ChallengeID
	}
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: source.EventDigest, OrganizationID: source.OrganizationID,
		TenantID: tamperaudit.OrganizationAuditTenantID, ActorID: source.ActorID, ActorRevision: source.ActorRevision,
		SourceSchema: SchemaVersion, Operation: "authentication", Outcome: source.Outcome,
		ReasonCode: source.ReasonCode, SubjectID: subjectID, EvidenceDigests: []string{},
		OccurredAt: localAuditTime(source.OccurredAt)}
	return sink.append(ctx, event)
}

func (sink *DurableAuditSink) AppendAuthorizationDecision(ctx context.Context, decision localidentity.Decision) error {
	occurredAt, err := tamperaudit.UUIDv7Time(decision.RequestID)
	if err != nil {
		return authError(localidentity.Unavailable, "audit_unavailable")
	}
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: decision.RequestID, OrganizationID: decision.Context.OrganizationID,
		TenantID: decision.Context.TenantID, CaseID: decision.Context.CaseID,
		ActorID: decision.Context.ActorID, ActorRevision: decision.ActorRevision,
		SourceSchema: localidentity.SchemaVersion, Operation: "authorization", Outcome: decision.Outcome,
		ReasonCode: decision.ReasonCode, SubjectID: decision.RequestID, SubjectDigest: decision.PayloadDigest,
		EvidenceDigests: []string{}, OccurredAt: occurredAt}
	return sink.append(ctx, event)
}

func (sink *DurableAuditSink) append(ctx context.Context, event tamperaudit.Event) error {
	if sink == nil || sink.appender == nil || tamperaudit.ValidateEvent(event) != nil ||
		sink.appender.AppendAuditEvent(ctx, event) != nil {
		return authError(localidentity.Unavailable, "audit_unavailable")
	}
	return nil
}

func localAuditTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
