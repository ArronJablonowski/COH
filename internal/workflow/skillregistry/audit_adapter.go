package skillregistry

import (
	"context"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

type durableAuditAppender interface {
	AppendAuditEvent(context.Context, tamperaudit.Event) error
}

// DurableAuditor projects redacted registry events into the tenant tamper-
// evident chain. A successful append is required before it returns a receipt.
type DurableAuditor struct{ appender durableAuditAppender }

func NewDurableAuditor(appender durableAuditAppender) (*DurableAuditor, error) {
	if appender == nil {
		return nil, newError(InvalidInput, "audit_appender_required", false, nil)
	}
	return &DurableAuditor{appender: appender}, nil
}

func (auditor *DurableAuditor) Append(ctx context.Context, source AuditEvent) (AuditReceipt, error) {
	if auditor == nil || auditor.appender == nil {
		return AuditReceipt{}, newError(Unavailable, "audit_unavailable", true, nil)
	}
	if err := contextError(ctx); err != nil {
		return AuditReceipt{}, err
	}
	sourceDigest, err := auditEventDigest(source)
	if err != nil {
		return AuditReceipt{}, err
	}
	schema := StateSchemaVersion
	if source.Action == Resolve {
		schema = ResolveSchemaVersion
	}
	evidence := []string{source.PolicyDigest, source.ReviewDigest, sourceDigest}
	if source.CommandDigest != "" {
		evidence = append(evidence, source.CommandDigest)
	}
	slices.Sort(evidence)
	evidence = slices.Compact(evidence)
	event := tamperaudit.Event{
		SchemaVersion: tamperaudit.EventSchemaVersion, ContractVersion: tamperaudit.ContractVersion,
		EventID: source.EventID, OrganizationID: source.OrganizationID, TenantID: source.TenantID,
		CaseID: source.CaseID, SourceSchema: schema, Operation: "skill_" + string(source.Action),
		Outcome: "allowed", ReasonCode: "skill_" + string(source.Action) + "_allowed",
		SubjectDigest: source.ManifestDigest, EvidenceDigests: evidence,
		OccurredAt: formatTime(source.OccurredAt),
	}
	if tamperaudit.ValidateEvent(event) != nil {
		return AuditReceipt{}, newError(Denied, "audit_projection_invalid", false, nil)
	}
	if err := auditor.appender.AppendAuditEvent(ctx, event); err != nil {
		return AuditReceipt{}, mapDependency(ctx, "audit_append_failed", err)
	}
	receiptDigest := digestBytes(append([]byte("COH-SKILL-AUDIT-RECEIPT-V1\x00"), []byte(sourceDigest)...))
	return AuditReceipt{EventID: source.EventID, EventDigest: sourceDigest,
		ReceiptDigest: receiptDigest}, nil
}

var _ Auditor = (*DurableAuditor)(nil)
