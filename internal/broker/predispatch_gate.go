package broker

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/policy"
)

func (gate *preDispatchGate) authorize(ctx context.Context, command preDispatchCommand) (preDispatchAuthority, error) {
	if gate == nil || gate.policy == nil || gate.approval == nil || gate.roe == nil || gate.audit == nil || gate.clock == nil {
		return preDispatchAuthority{}, lifecycle.NewError(lifecycle.Unavailable, "predispatch_unavailable")
	}
	if err := contextError(ctx); err != nil {
		return preDispatchAuthority{}, err
	}
	startedAt := gate.now()
	if startedAt.IsZero() {
		return preDispatchAuthority{}, lifecycle.NewError(lifecycle.Unavailable, "predispatch_clock")
	}
	verified, err := actionmanifest.Verify(ctx, command.SignedManifest, command.ManifestSigner)
	if err != nil {
		return preDispatchAuthority{}, mapManifestError(err)
	}
	manifest := verified.Manifest()
	if !consequentialTier(manifest.ActionTier) {
		return preDispatchAuthority{}, lifecycle.NewError(lifecycle.Denied, "action_not_consequential")
	}
	if err := validatePolicyActor(command.PolicyActor, manifest); err != nil {
		return preDispatchAuthority{}, err
	}
	request := policy.Request{EvaluationID: command.EvaluationID, Phase: policy.PreDispatch,
		Manifest: verified, Actor: command.PolicyActor, Runtime: command.Runtime}
	decision, err := gate.policy.Evaluate(ctx, request, command.PolicySigner)
	finishedAt := gate.now()
	if err != nil {
		return preDispatchAuthority{}, mapPolicyError(err)
	}
	if err := validatePreDispatchDecision(decision, request, command.PolicySigner, startedAt, finishedAt); err != nil {
		return preDispatchAuthority{}, err
	}
	roeAt := gate.now()
	if roeAt.IsZero() {
		return preDispatchAuthority{}, lifecycle.NewError(lifecycle.Unavailable, "predispatch_clock")
	}
	roe, err := gate.verifyROE(ctx, manifest, roeAt)
	if err != nil {
		return preDispatchAuthority{}, err
	}
	if err := validateApprovalCommand(command.Approval, manifest); err != nil {
		return preDispatchAuthority{}, err
	}
	if err := validateApprovalInputs(command, verified); err != nil {
		return preDispatchAuthority{}, err
	}
	consume := command.Approval
	consume.approvalProof = &approvalProof{Fingerprint: command.Fingerprint, Manifest: verified,
		Signer: command.ManifestSigner, Decision: command.IntentDecision}
	result, err := gate.approval.consumeApproval(ctx, consume)
	if err != nil {
		return preDispatchAuthority{}, err
	}
	if result.Replayed {
		replayErr := lifecycle.NewError(lifecycle.Denied, "approval_replayed")
		return preDispatchAuthority{}, gate.recordTerminal(ctx, manifest, decision, result.Record, roe, replayErr)
	}
	if err := validateConsumedApproval(result.Record, command, manifest); err != nil {
		return preDispatchAuthority{}, err
	}
	if err := contextError(ctx); err != nil {
		return preDispatchAuthority{}, gate.recordTerminal(ctx, manifest, decision, result.Record, roe, err)
	}
	event, err := preDispatchAuditEvent(manifest, decision, result.Record, roe, "allowed", "predispatch_authorized")
	if err != nil {
		return preDispatchAuthority{}, lifecycle.NewError(lifecycle.Unavailable, "audit_event_invalid")
	}
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := gate.audit.AppendAuditEvent(auditCtx, event); err != nil {
		return preDispatchAuthority{}, lifecycle.NewError(lifecycle.Unavailable, "audit_unavailable")
	}
	return preDispatchAuthority{Manifest: verified, PreDispatchDecision: decision,
		Approval: result.Record, ROE: roe, AuditEventID: event.EventID}, nil
}

func (gate *preDispatchGate) recordTerminal(ctx context.Context, manifest actionmanifest.Manifest, decision policy.Decision,
	record lifecycle.Record, roe *verifiedROEProof, resultErr error) error {
	outcome, reason := lifecycleOutcome(resultErr), lifecycle.Reason(resultErr)
	event, eventErr := preDispatchAuditEvent(manifest, decision, record, roe, outcome, reason)
	if eventErr != nil {
		return lifecycle.NewError(lifecycle.Unavailable, "audit_event_invalid")
	}
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := gate.audit.AppendAuditEvent(auditCtx, event); err != nil {
		return lifecycle.NewError(lifecycle.Unavailable, "audit_unavailable")
	}
	return resultErr
}

func validateApprovalCommand(command approvalTransitionCommand, manifest actionmanifest.Manifest) error {
	expected := domain.CaseRef{OrganizationID: manifest.OrganizationID, TenantID: manifest.TenantID, CaseID: manifest.CaseID}
	if command.Case != expected || command.Actor.ActorID != manifest.ActionOwnerActorID {
		return lifecycle.NewError(lifecycle.Denied, "approval_scope_mismatch")
	}
	return nil
}

func consequentialTier(tier string) bool { return tier == "T2" || tier == "T3" || tier == "T4" }
