package broker

import (
	"context"
	"errors"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/domain/toolroute"
)

func (authority *toolRouteAuthority) Submit(ctx context.Context, intent domain.ToolIntent) (domain.ActionReceipt, error) {
	if authority == nil || authority.store == nil || authority.resolver == nil || authority.gate == nil ||
		authority.stop == nil || authority.connector == nil || authority.audit == nil || authority.clock == nil {
		return domain.ActionReceipt{}, newRouteError(routeCodeUnavailable, "route_unavailable", false, nil)
	}
	if ctx == nil {
		return domain.ActionReceipt{}, newRouteError(routeCodeInvalidInput, "context_required", false, nil)
	}
	intentDigest, err := toolroute.Digest(intent)
	if err != nil {
		return domain.ActionReceipt{}, newRouteError(routeCodeInvalidInput, toolroute.ErrorReason(err), false, nil)
	}
	if err := ctx.Err(); err != nil {
		mapped := mapRouteContext(ctx, "route_context", false, err)
		if _, auditErr := authority.appendUnboundAudit(ctx, intent, intentDigest,
			routeAuditOutcome(mapped), routeReason(mapped)); auditErr != nil {
			return domain.ActionReceipt{}, auditErr
		}
		return domain.ActionReceipt{}, mapped
	}
	key := "tool-route:" + intent.Case.OrganizationID + ":" + intent.Case.TenantID + ":" +
		intent.Case.CaseID + ":" + intent.OperationID
	current, found, err := authority.store.lookup(ctx, intent.Case, intent.OperationID)
	if err != nil {
		return domain.ActionReceipt{}, mapRouteContext(ctx, "route_store_lookup", false, err)
	}
	if found {
		if err := validateToolRouteRecord(current); err != nil {
			return domain.ActionReceipt{}, err
		}
		if current.IntentDigest != intentDigest {
			denied := newRouteError(routeCodeDenied, "route_replay_binding", false, nil)
			if _, auditErr := authority.appendUnboundAudit(ctx, intent, intentDigest, "denied", routeReason(denied)); auditErr != nil {
				return domain.ActionReceipt{}, auditErr
			}
			return domain.ActionReceipt{}, denied
		}
		if terminalToolRouteStatus(current.Status) {
			return current.Receipt, nil
		}
		if current.Status == routeDispatching {
			return authority.finishRoute(ctx, key, current, routeUncertain, "dispatch_receipt_missing", nil)
		}
	}
	command, err := authority.resolver.resolveToolRoute(ctx, intent, intentDigest)
	if err != nil {
		mapped := mapRouteContext(ctx, "route_context_resolution", false, err)
		if _, auditErr := authority.appendUnboundAudit(ctx, intent, intentDigest,
			routeAuditOutcome(mapped), routeReason(mapped)); auditErr != nil {
			return domain.ActionReceipt{}, auditErr
		}
		return domain.ActionReceipt{}, mapped
	}
	verified, err := actionmanifest.Verify(ctx, command.SignedManifest, command.ManifestSigner)
	if err != nil {
		mapped := mapRouteContext(ctx, "manifest_authority", false, mapManifestError(err))
		if _, auditErr := authority.appendUnboundAudit(ctx, intent, intentDigest,
			routeAuditOutcome(mapped), routeReason(mapped)); auditErr != nil {
			return domain.ActionReceipt{}, auditErr
		}
		return domain.ActionReceipt{}, mapped
	}
	contextDigest, err := toolRouteContextDigest(command)
	if err != nil {
		return domain.ActionReceipt{}, err
	}
	now := authority.clock.Now().UTC()
	if now.IsZero() {
		return domain.ActionReceipt{}, newRouteError(routeCodeUnavailable, "route_clock_unavailable", false, nil)
	}
	idempotencyDigest := routeDigest("COH-TOOL-ROUTE-IDEMPOTENCY-V1\x00", []byte(key))
	candidate, err := newToolRouteRecord(intent, intentDigest, idempotencyDigest, contextDigest, verified, command, now)
	if err != nil {
		return domain.ActionReceipt{}, err
	}
	current, replayed, err := authority.store.begin(ctx, key, candidate)
	if err != nil {
		return domain.ActionReceipt{}, mapRouteContext(ctx, "route_store_begin", false, err)
	}
	if replayed {
		if err := validateRouteReplay(current, candidate); err != nil {
			if _, auditErr := authority.appendUnboundAudit(ctx, intent, intentDigest, "denied", routeReason(err)); auditErr != nil {
				return domain.ActionReceipt{}, auditErr
			}
			return domain.ActionReceipt{}, err
		}
		if terminalToolRouteStatus(current.Status) {
			return current.Receipt, nil
		}
		if current.Status == routeDispatching {
			return authority.finishRoute(ctx, key, current, routeUncertain, "dispatch_receipt_missing", nil)
		}
	}
	if err := validateIntentManifestBinding(intent, verified); err != nil {
		return authority.finishRoute(ctx, key, current, routeDenied, routeReason(err), nil)
	}
	if err := authority.checkStop(ctx, current.Case); err != nil {
		return authority.finishRouteError(ctx, key, current, err)
	}
	return authority.authorizeAndDispatch(ctx, key, current, intent, command)
}

func (authority *toolRouteAuthority) authorizeAndDispatch(ctx context.Context, key string, current toolRouteRecord,
	intent domain.ToolIntent, command preDispatchCommand) (domain.ActionReceipt, error) {
	if current.Status == routePending {
		next, err := authority.transitionRoute(current, routeAuthorizing, "authorization_started")
		if err != nil {
			return domain.ActionReceipt{}, err
		}
		if err := validateToolRouteTransition(current, next); err != nil {
			return domain.ActionReceipt{}, err
		}
		current, err = authority.store.save(ctx, key+":authorizing", current, next)
		if err != nil {
			return domain.ActionReceipt{}, mapRouteContext(ctx, "route_store_authorizing", false, err)
		}
	}
	capability, err := authority.gate.authorize(ctx, command)
	if err != nil {
		return authority.finishRouteError(ctx, key, current, mapRouteContext(ctx, "predispatch_authority", false, err))
	}
	if err := validateIntentManifestBinding(intent, capability.Manifest); err != nil ||
		capability.PreDispatchDecision.DecisionDigest == "" || capability.Approval.FingerprintDigest == "" {
		return authority.finishRoute(ctx, key, current, routeDenied, "predispatch_binding", nil)
	}
	authorized := current
	authorized.PreDispatchDecisionDigest = capability.PreDispatchDecision.DecisionDigest
	authorized.ApprovalRevision = capability.Approval.Revision
	authorized.ApprovalFingerprintDigest = capability.Approval.FingerprintDigest
	if err := authority.checkStop(ctx, current.Case); err != nil {
		return authority.finishAuthorizedRouteError(ctx, key, current, authorized, err)
	}
	dispatchAuditID, err := authority.appendRouteAudit(ctx, authorized, "allowed", "route_dispatching",
		capability.AuditEventID, capability.PreDispatchDecision.DecisionDigest,
		capability.Approval.FingerprintDigest)
	if err != nil {
		return domain.ActionReceipt{}, err
	}
	next, err := authority.transitionRoute(current, routeDispatching, "dispatch_started")
	if err != nil {
		return domain.ActionReceipt{}, err
	}
	next.DispatchAuditID = dispatchAuditID
	next.PreDispatchDecisionDigest = capability.PreDispatchDecision.DecisionDigest
	next.ApprovalRevision = capability.Approval.Revision
	next.ApprovalFingerprintDigest = capability.Approval.FingerprintDigest
	provenance, err := toolRouteProvenance(current.ProvenanceDigest, "dispatch_started", next)
	if err != nil {
		return domain.ActionReceipt{}, err
	}
	next.ProvenanceDigest = provenance
	if err := validateToolRouteTransition(current, next); err != nil {
		return domain.ActionReceipt{}, err
	}
	current, err = authority.store.save(ctx, key+":dispatching", current, next)
	if err != nil {
		return domain.ActionReceipt{}, mapRouteContext(ctx, "route_store_dispatching", false, err)
	}
	receipt, dispatchErr := authority.connector.Dispatch(ctx, intent)
	if dispatchErr != nil {
		mapped := mapRouteContext(ctx, "connector_dispatch", true, dispatchErr)
		return authority.finishRoute(ctx, key, current, routeUncertain, routeReason(mapped), nil)
	}
	if err := toolroute.ValidateReceipt(receipt, current.IntentDigest); err != nil {
		return authority.finishRoute(ctx, key, current, routeUncertain, "connector_receipt_invalid", nil)
	}
	return authority.finishRoute(ctx, key, current, routeStatusForOutcome(receipt.Outcome),
		"connector_"+receipt.Outcome, &receipt)
}

func (authority *toolRouteAuthority) finishRouteError(ctx context.Context, key string, current toolRouteRecord,
	err error) (domain.ActionReceipt, error) {
	return authority.finishAuthorizedRouteError(ctx, key, current, current, err)
}

func (authority *toolRouteAuthority) finishAuthorizedRouteError(ctx context.Context, key string,
	current, authorized toolRouteRecord, err error) (domain.ActionReceipt, error) {
	status := routeStatusForCode(routeCode(err))
	receipt, finishErr := authority.finishRouteBound(ctx, key, current, authorized, status, routeReason(err), nil)
	if finishErr != nil {
		return receipt, finishErr
	}
	if routeCode(err) == routeCodeCanceled || routeCode(err) == routeCodeTimeout || routeCode(err) == routeCodeInvalidInput ||
		routeCode(err) == routeCodeUnavailable {
		return receipt, err
	}
	return receipt, nil
}

func (authority *toolRouteAuthority) finishRoute(ctx context.Context, key string, current toolRouteRecord,
	status toolRouteStatus, reason string, supplied *domain.ActionReceipt) (domain.ActionReceipt, error) {
	return authority.finishRouteBound(ctx, key, current, current, status, reason, supplied)
}

func (authority *toolRouteAuthority) finishRouteBound(ctx context.Context, key string, current,
	auditRecord toolRouteRecord, status toolRouteStatus, reason string,
	supplied *domain.ActionReceipt) (domain.ActionReceipt, error) {
	outcome := routeOutcomeForStatus(status)
	evidence := routeEvidence(auditRecord.DispatchAuditID)
	if supplied != nil {
		evidence = routeEvidence(auditRecord.DispatchAuditID, supplied.Evidence.Digest)
	}
	auditID, err := authority.appendRouteAudit(ctx, auditRecord, routeAuditOutcomeForStatus(status), reason, evidence...)
	if err != nil {
		return domain.ActionReceipt{}, newRouteError(routeCodeUnavailable, "route_completion_audit", current.Status == routeDispatching, err)
	}
	receipt := routeReceipt(current.IntentDigest, outcome, auditID)
	if supplied != nil {
		receipt = *supplied
	}
	next, err := authority.transitionRoute(current, status, reason)
	if err != nil {
		return domain.ActionReceipt{}, err
	}
	next.CompletionAuditID = auditID
	next.PreDispatchDecisionDigest = auditRecord.PreDispatchDecisionDigest
	next.ApprovalRevision = auditRecord.ApprovalRevision
	next.ApprovalFingerprintDigest = auditRecord.ApprovalFingerprintDigest
	next.Receipt = receipt
	next.ReceiptDigest, err = toolRouteReceiptDigest(receipt)
	if err != nil {
		return domain.ActionReceipt{}, err
	}
	provenance, err := toolRouteProvenance(current.ProvenanceDigest, reason, next)
	if err != nil {
		return domain.ActionReceipt{}, err
	}
	next.ProvenanceDigest = provenance
	if err := validateToolRouteTransition(current, next); err != nil {
		return domain.ActionReceipt{}, err
	}
	persistCtx, cancel := auditContext(ctx)
	defer cancel()
	saved, err := authority.store.save(persistCtx, key+":terminal:"+outcome, current, next)
	if err != nil {
		return domain.ActionReceipt{}, newRouteError(routeCodeUnavailable, "route_store_terminal", current.Status == routeDispatching, err)
	}
	return saved.Receipt, nil
}

func (authority *toolRouteAuthority) transitionRoute(current toolRouteRecord, status toolRouteStatus,
	operation string) (toolRouteRecord, error) {
	next := current
	next.Status = status
	next.ReasonCode = operation
	next.PreviousProvenanceDigest = current.ProvenanceDigest
	next.Revision++
	next.UpdatedAt = authority.clock.Now().UTC()
	provenance, err := toolRouteProvenance(current.ProvenanceDigest, operation, next)
	if err != nil {
		return toolRouteRecord{}, err
	}
	next.ProvenanceDigest = provenance
	return next, nil
}

func (authority *toolRouteAuthority) checkStop(ctx context.Context, scope domain.CaseRef) error {
	if err := authority.stop.Allow(ctx, scope.OrganizationID, scope.TenantID, scope.CaseID); err != nil {
		return mapRouteContext(ctx, "emergency_stop", false, err)
	}
	return nil
}

func routeStatusForOutcome(outcome string) toolRouteStatus {
	switch outcome {
	case "succeeded":
		return routeSucceeded
	case "denied":
		return routeDenied
	case "canceled":
		return routeCanceled
	case "timeout":
		return routeTimeout
	case "failed":
		return routeFailed
	default:
		return routeUncertain
	}
}

func routeStatusForCode(code toolRouteCode) toolRouteStatus {
	switch code {
	case routeCodeDenied, routeCodeInvalidInput:
		return routeDenied
	case routeCodeCanceled:
		return routeCanceled
	case routeCodeTimeout:
		return routeTimeout
	case routeCodeUncertain:
		return routeUncertain
	default:
		return routeFailed
	}
}

func routeOutcomeForStatus(status toolRouteStatus) string { return string(status) }

func routeAuditOutcomeForStatus(status toolRouteStatus) string {
	if status == routeSucceeded {
		return "allowed"
	}
	return string(status)
}

func routeAuditOutcome(err error) string {
	if errors.Is(err, context.Canceled) || routeCode(err) == routeCodeCanceled {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) || routeCode(err) == routeCodeTimeout {
		return "timeout"
	}
	if routeCode(err) == routeCodeDenied || routeCode(err) == routeCodeInvalidInput || lifecycle.Code(err) == lifecycle.Denied {
		return "denied"
	}
	return "failed"
}
