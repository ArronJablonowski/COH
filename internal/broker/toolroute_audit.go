package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/domain/toolroute"
)

const toolRouteAuditDomain = "COH-TOOL-ROUTE-AUDIT-V1\x00"

func (authority *toolRouteAuthority) appendRouteAudit(ctx context.Context, record toolRouteRecord,
	outcome, reason string, evidence ...string) (string, error) {
	if authority == nil || authority.audit == nil || authority.clock == nil {
		return "", newRouteError(routeCodeUnavailable, "route_audit_unavailable", false, nil)
	}
	now := authority.clock.Now().UTC()
	if now.IsZero() {
		return "", newRouteError(routeCodeUnavailable, "route_clock_unavailable", false, nil)
	}
	actorID, actorRevision := record.ActionOwnerActorID, record.ActionOwnerActorRevision
	if !uuidPattern.MatchString(actorID) || actorRevision == 0 {
		actorID, actorRevision = authority.identity.ActorID, authority.identity.ActorRevision
	}
	event := tamperaudit.Event{SchemaVersion: tamperaudit.EventSchemaVersion,
		ContractVersion: tamperaudit.ContractVersion, OrganizationID: record.Case.OrganizationID,
		TenantID: record.Case.TenantID, CaseID: record.Case.CaseID, ActorID: actorID,
		ActorRevision: actorRevision, SourceSchema: toolroute.SchemaVersion, Operation: "route_tool",
		Outcome: outcome, ReasonCode: reason, SubjectID: record.OperationID, SubjectRevision: record.Revision,
		SubjectDigest: record.IntentDigest, EvidenceDigests: routeEvidence(append(evidence,
			record.ContextDigest, record.ManifestDigest, record.IntentPolicyDecisionDigest,
			record.PreDispatchDecisionDigest, record.ApprovalFingerprintDigest)...), OccurredAt: formatTime(now)}
	eventID, err := toolRouteAuditID(event)
	if err != nil {
		return "", err
	}
	event.EventID = eventID
	if err := tamperaudit.ValidateEvent(event); err != nil {
		return "", newRouteError(routeCodeUnavailable, "route_audit_event_invalid", false, nil)
	}
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := authority.audit.AppendAuditEvent(auditCtx, event); err != nil {
		return "", newRouteError(routeCodeUnavailable, "route_audit_unavailable", false, nil)
	}
	return eventID, nil
}

func (authority *toolRouteAuthority) appendUnboundAudit(ctx context.Context, intent domain.ToolIntent,
	intentDigest, outcome, reason string) (string, error) {
	record := toolRouteRecord{OperationID: intent.OperationID, Case: intent.Case, IntentDigest: intentDigest,
		RequestorActorID: authority.identity.ActorID, RequestorActorRevision: authority.identity.ActorRevision,
		ActionOwnerActorID: authority.identity.ActorID, ActionOwnerActorRevision: authority.identity.ActorRevision,
		Revision: 1}
	return authority.appendRouteAudit(ctx, record, outcome, reason)
}

func toolRouteAuditID(event tamperaudit.Event) (string, error) {
	event.EventID = ""
	encoded, err := json.Marshal(event)
	if err != nil {
		return "", newRouteError(routeCodeUnavailable, "route_audit_encoding", false, nil)
	}
	sum := sha256.Sum256(append([]byte(toolRouteAuditDomain), encoded...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func routeReceipt(intentDigest, outcome, evidence string) domain.ActionReceipt {
	return domain.ActionReceipt{IntentDigest: intentDigest, Outcome: outcome,
		Evidence: domain.ArtifactRef{Digest: evidence, MediaType: "application/vnd.coh.tool-route.audit+json",
			Classification: "restricted", Length: 0}}
}
