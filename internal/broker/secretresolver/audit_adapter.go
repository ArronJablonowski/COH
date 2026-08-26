package secretresolver

import (
	"context"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/secretref"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type durableAuditAppender interface {
	AppendAuditEvent(context.Context, tamperaudit.Event) error
}

type DurableAuditSink struct{ appender durableAuditAppender }

func NewDurableAuditSink(appender durableAuditAppender) (*DurableAuditSink, error) {
	if appender == nil {
		return nil, resolverError(secretref.InvalidInput, "audit_dependencies")
	}
	return &DurableAuditSink{appender: appender}, nil
}

func (sink *DurableAuditSink) AppendSecretDecision(ctx context.Context, decision secretref.Decision) error {
	if sink == nil || sink.appender == nil {
		return resolverError(secretref.Unavailable, "audit_unavailable")
	}
	evidence := []string{}
	for _, digest := range []string{decision.DecisionDigest, decision.ReferenceDigest, decision.AuthorityDigest} {
		if digest != "" {
			evidence = append(evidence, digest)
		}
	}
	slices.Sort(evidence)
	evidence = slices.Compact(evidence)
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: decision.RequestID, OrganizationID: decision.Context.OrganizationID, TenantID: decision.Context.TenantID,
		CaseID: decision.Context.CaseID, ActorID: decision.Context.ActorID, ActorRevision: decision.ActorRevision,
		SourceSchema: secretref.SchemaVersion, Operation: "secret_resolution", Outcome: decision.Outcome,
		ReasonCode: decision.ReasonCode, SubjectID: decision.RequestID, SubjectRevision: decision.RecordRevision,
		SubjectDigest: decision.ActionDigest, EvidenceDigests: evidence}
	if decision.RecordRevision == 0 {
		event.SubjectRevision = 0
	}
	if tamperaudit.ValidateEvent(event) != nil || sink.appender.AppendAuditEvent(ctx, event) != nil {
		return resolverError(secretref.Unavailable, "audit_unavailable")
	}
	return nil
}
