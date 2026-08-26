package credentiallease

import (
	"context"
	"slices"
	"time"

	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type durableAuditAppender interface {
	AppendAuditEvent(context.Context, tamperaudit.Event) error
}

type DurableAuditSink struct{ appender durableAuditAppender }

func NewDurableAuditSink(appender durableAuditAppender) (*DurableAuditSink, error) {
	if appender == nil {
		return nil, brokerError(leasecontract.InvalidInput, "audit_dependencies")
	}
	return &DurableAuditSink{appender: appender}, nil
}

func (sink *DurableAuditSink) AppendCredentialLeaseDecision(ctx context.Context, decision leasecontract.Decision) error {
	if sink == nil || sink.appender == nil {
		return brokerError(leasecontract.Unavailable, "audit_unavailable")
	}
	evidence := []string{}
	for _, digest := range []string{decision.DecisionDigest, decision.TargetScopeDigest, decision.TransportIdentityDigest,
		decision.CredentialReferenceDigest, decision.AuthorizationDecisionDigest, decision.PolicyDecisionDigest,
		decision.ApprovalDecisionDigest, decision.SecretDecisionDigest} {
		if digest != "" {
			evidence = append(evidence, digest)
		}
	}
	slices.Sort(evidence)
	evidence = slices.Compact(evidence)
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: decision.DecisionDigest, OrganizationID: decision.OrganizationID, TenantID: decision.TenantID,
		CaseID: decision.CaseID, ActorID: decision.ActorID, ActorRevision: decision.ActorRevision,
		SourceSchema: leasecontract.SchemaVersion, Operation: decision.Event, Outcome: decision.Outcome,
		ReasonCode: decision.ReasonCode, SubjectID: decision.RequestID, SubjectDigest: decision.ActionDigest,
		EvidenceDigests: evidence, OccurredAt: formatAuditTime(decision.OccurredAt)}
	if tamperaudit.ValidateEvent(event) != nil || sink.appender.AppendAuditEvent(ctx, event) != nil {
		return brokerError(leasecontract.Unavailable, "audit_unavailable")
	}
	return nil
}

func formatAuditTime(value time.Time) string {
	return value.UTC().Format("2006-01-02T15:04:05.000000000Z")
}
