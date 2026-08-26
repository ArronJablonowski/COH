package policy

import (
	"context"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type durableAuditAppender interface {
	AppendAuditEvent(context.Context, tamperaudit.Event) error
}

type DurableAuditSink struct{ appender durableAuditAppender }

func NewDurableAuditSink(appender durableAuditAppender) (*DurableAuditSink, error) {
	if appender == nil {
		return nil, NewError(InvalidInput, "audit_dependencies")
	}
	return &DurableAuditSink{appender: appender}, nil
}

func (sink *DurableAuditSink) AppendPolicyEvent(ctx context.Context, source AuditEvent) error {
	if sink == nil || sink.appender == nil {
		return NewError(Unavailable, "audit_unavailable")
	}
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: source.EventID, OrganizationID: source.OrganizationID, TenantID: source.TenantID,
		CaseID: source.CaseID, ActorID: source.ActorID, ActorRevision: source.ActorRevision,
		Operation: source.Kind, OccurredAt: source.OccurredAt, EvidenceDigests: []string{}}
	switch source.Kind {
	case "policy_activation":
		if source.Activation == nil || source.Decision != nil {
			return NewError(InvalidInput, "audit_event")
		}
		event.SourceSchema, event.Outcome, event.ReasonCode = "coh.opa-policy-bundle/v1", "allowed", "policy_activated"
		event.SubjectID, event.SubjectRevision, event.SubjectDigest = source.Activation.BundleID, source.Activation.PolicyRevision, source.Activation.PolicyDigest
	case "policy_evaluation":
		if source.Decision == nil || source.Activation != nil {
			return NewError(InvalidInput, "audit_event")
		}
		decision := source.Decision
		event.SourceSchema, event.Outcome, event.ReasonCode = SchemaVersion, decision.Outcome, decision.ReasonCode
		event.SubjectID, event.SubjectRevision, event.SubjectDigest = decision.BundleID, decision.PolicyRevision, decision.DecisionDigest
		for _, digest := range []string{decision.InputDigest, decision.ManifestDigest, decision.PolicyDigest} {
			if digest != "" {
				event.EvidenceDigests = append(event.EvidenceDigests, digest)
			}
		}
		slices.Sort(event.EvidenceDigests)
		event.EvidenceDigests = slices.Compact(event.EvidenceDigests)
	default:
		return NewError(InvalidInput, "audit_event")
	}
	if tamperaudit.ValidateEvent(event) != nil || sink.appender.AppendAuditEvent(ctx, event) != nil {
		return NewError(Unavailable, "audit_unavailable")
	}
	return nil
}
