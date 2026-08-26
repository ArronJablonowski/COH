package remoteworker

import (
	"context"
	"crypto/sha256"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

func (broker *Broker) Use(ctx context.Context, handle *Handle, request workercontract.DispatchRequest, authority workercontract.LeaseAuthority, callback func(context.Context, workercontract.DispatchEnvelope) error) (workercontract.Decision, error) {
	now := time.Time{}
	if broker != nil && broker.clock != nil {
		now = broker.clock.Now().UTC()
	}
	if broker == nil || broker.store == nil || broker.audit == nil || broker.stop == nil || broker.clock == nil {
		err := brokerError(workercontract.Unavailable, "broker_unavailable")
		return dispatchDecision(LeaseRecord{}, request, authority, leaseID(handle), err, now, "runner_dispatch"), err
	}
	if err := contextError(ctx); err != nil {
		return broker.recordDispatch(ctx, LeaseRecord{}, request, authority, leaseID(handle), err, now, "runner_dispatch")
	}
	if handle == nil || callback == nil {
		err := brokerError(workercontract.InvalidInput, "dispatch_input_invalid")
		return broker.recordDispatch(ctx, LeaseRecord{}, request, authority, leaseID(handle), err, now, "runner_dispatch")
	}
	tokenDigest, err := handle.digest()
	if err != nil {
		return broker.recordDispatch(ctx, LeaseRecord{}, request, authority, handle.LeaseID, err, now, "runner_dispatch")
	}
	record, err := broker.store.ClaimLease(ctx, handle.LeaseID, tokenDigest, now)
	if err != nil {
		if workercontract.Code(err) != workercontract.Unavailable && workercontract.Code(err) != workercontract.Canceled &&
			workercontract.Code(err) != workercontract.Timeout {
			handle.Destroy()
		}
		return broker.recordDispatch(ctx, record, request, authority, handle.LeaseID, normalizeStoreError(ctx, err), now, "runner_dispatch")
	}
	handle.Destroy()
	bound := record.Request.Scope
	if err := broker.stop.Allow(ctx, bound.OrganizationID, bound.TenantID, bound.CaseID); err != nil {
		return broker.recordDispatch(ctx, record, request, authority, record.LeaseID, mapStopError(err), now, "runner_dispatch")
	}
	if err = broker.validateDispatch(ctx, record, request, authority, now); err != nil {
		return broker.recordDispatch(ctx, record, request, authority, record.LeaseID, err, now, "runner_dispatch")
	}
	decision, err := broker.recordDispatch(ctx, record, request, authority, record.LeaseID, nil, now, "runner_dispatch")
	if err != nil {
		return decision, err
	}
	envelope := workercontract.DispatchEnvelope{LeaseID: record.LeaseID, Scope: cloneLease(record).Request.Scope,
		WorkerID: record.Request.WorkerID, WorkerRevision: record.Authority.Worker.Revision,
		CertificateRevision: record.Authority.Worker.CertificateRevision, AttestationDigest: record.Authority.Worker.AttestationDigest,
		AttestationKeyRevision:      record.Authority.Worker.AttestationKeyRevision,
		AttestationKeyDigest:        record.Authority.Worker.AttestationKeyDigest,
		AuthorizationDecisionDigest: record.Authority.AuthorizationDecisionDigest,
		PolicyDecisionDigest:        record.Authority.PolicyDecisionDigest, ApprovalDecisionDigest: record.Authority.ApprovalDecisionDigest,
		IssuedAt: record.IssuedAt, ExpiresAt: record.ExpiresAt}
	callbackErr := callback(ctx, envelope)
	completionNow := broker.clock.Now().UTC()
	if callbackErr != nil {
		resultErr := brokerError(workercontract.Unavailable, "runner_callback_failed")
		if err = contextError(ctx); err != nil {
			resultErr = err
		}
		_, auditErr := broker.recordDispatch(ctx, record, request, authority, record.LeaseID, resultErr, completionNow, "runner_dispatch_completion")
		if auditErr != nil && workercontract.Reason(auditErr) == "audit_unavailable" {
			return decision, auditErr
		}
		return decision, resultErr
	}
	completion, err := broker.recordDispatch(ctx, record, request, authority, record.LeaseID, nil, completionNow, "runner_dispatch_completion")
	if err != nil {
		return completion, err
	}
	return completion, nil
}

func (broker *Broker) validateDispatch(ctx context.Context, record LeaseRecord, request workercontract.DispatchRequest, authority workercontract.LeaseAuthority, now time.Time) error {
	if err := workercontract.ValidateDispatchRequest(request); err != nil {
		return err
	}
	if request.LeaseID != record.LeaseID || request.WorkerID != record.Request.WorkerID ||
		!sameLeaseScope(request.Scope, record.Request.Scope) {
		return brokerError(workercontract.Denied, "lease_scope_mismatch")
	}
	if err := validateLeaseAuthority(record.Request, authority, now); err != nil {
		return err
	}
	if !sameAuthority(record.Authority, authority) {
		return brokerError(workercontract.Denied, "lease_authority_stale")
	}
	current, err := broker.store.CurrentWorker(ctx, authority.Worker.Scope, authority.Worker.WorkerID)
	if err != nil {
		return normalizeStoreError(ctx, err)
	}
	if !sameWorker(current, record.Authority.Worker) {
		return brokerError(workercontract.Denied, "worker_state_stale")
	}
	return nil
}

func sameAuthority(left, right workercontract.LeaseAuthority) bool {
	return sameLeaseScope(left.Scope, right.Scope) && left.ActorActive == right.ActorActive &&
		left.ActorRevision == right.ActorRevision && left.TaskActive == right.TaskActive &&
		left.EmergencyStopActive == right.EmergencyStopActive && left.AuthorizationAllowed == right.AuthorizationAllowed &&
		left.AuthorizationDecisionDigest == right.AuthorizationDecisionDigest && left.PolicyAllowed == right.PolicyAllowed &&
		left.PolicyDecisionDigest == right.PolicyDecisionDigest && left.ApprovalRequired == right.ApprovalRequired &&
		left.ApprovalAllowed == right.ApprovalAllowed && left.ApprovalDecisionDigest == right.ApprovalDecisionDigest &&
		sameWorker(left.Worker, right.Worker) && left.Transport.Kind == right.Transport.Kind &&
		left.Transport.IdentityDigest == right.Transport.IdentityDigest && left.Transport.MutualTLS == right.Transport.MutualTLS &&
		left.Transport.CertificateFingerprint == right.Transport.CertificateFingerprint &&
		left.Transport.CertificateRevision == right.Transport.CertificateRevision && left.Transport.URISAN == right.Transport.URISAN
}

func (broker *Broker) recordDispatch(ctx context.Context, record LeaseRecord, request workercontract.DispatchRequest, authority workercontract.LeaseAuthority, publicLeaseID string, resultErr error, now time.Time, event string) (workercontract.Decision, error) {
	decision := dispatchDecision(record, request, authority, publicLeaseID, resultErr, now, event)
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := broker.audit.AppendRemoteWorkerDecision(auditCtx, decision); err != nil {
		auditErr := brokerError(workercontract.Unavailable, "audit_unavailable")
		return dispatchDecision(record, request, authority, publicLeaseID, auditErr, now, event), auditErr
	}
	return decision, resultErr
}

func dispatchDecision(record LeaseRecord, request workercontract.DispatchRequest, authority workercontract.LeaseAuthority, leaseID string, err error, now time.Time, event string) workercontract.Decision {
	result, reason := outcome(err, "dispatch_authorized")
	if event == "runner_dispatch_completion" && err == nil {
		reason = "dispatch_completed"
	}
	scope := request.Scope
	if record.LeaseID != "" {
		scope, authority = record.Request.Scope, record.Authority
	}
	decision := workercontract.Decision{Event: event, Outcome: result, ReasonCode: reason, LeaseID: leaseID,
		OrganizationID: scope.OrganizationID, TenantID: scope.TenantID, CaseID: scope.CaseID, ActorID: scope.ActorID,
		ActorRevision: authority.ActorRevision, TaskID: scope.TaskID, ActionDigest: scope.ActionDigest,
		TargetScopeDigest: workercontract.TargetScopeDigest(scope.TargetDigests), ToolDigest: scope.ToolDigest,
		Operation: scope.Operation, RequiredTier: scope.RequiredTier, IsolationClass: scope.IsolationClass,
		WorkerID: request.WorkerID, WorkerRevision: authority.Worker.Revision,
		TransportIdentityDigest: authority.Worker.TransportIdentityDigest, CertificateFingerprint: authority.Worker.CertificateFingerprint,
		CertificateRevision: authority.Worker.CertificateRevision, AttestationDigest: authority.Worker.AttestationDigest,
		AttestationKeyRevision:      authority.Worker.AttestationKeyRevision,
		AttestationKeyDigest:        authority.Worker.AttestationKeyDigest,
		AuthorizationDecisionDigest: authority.AuthorizationDecisionDigest, PolicyDecisionDigest: authority.PolicyDecisionDigest,
		ApprovalDecisionDigest: authority.ApprovalDecisionDigest, IssuedAt: record.IssuedAt, ExpiresAt: record.ExpiresAt, OccurredAt: now}
	if workercontract.Code(err) == workercontract.InvalidInput {
		decision.Operation, decision.WorkerID, decision.TransportIdentityDigest, decision.CertificateFingerprint = "", "", "", ""
	}
	return workercontract.FinalizeDecision(decision)
}

func (handle *Handle) digest() ([32]byte, error) {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.dead || len(handle.token) != tokenBytes {
		return [32]byte{}, brokerError(workercontract.Denied, "capability_destroyed")
	}
	return sha256.Sum256(handle.token), nil
}

func leaseID(handle *Handle) string {
	if handle == nil {
		return ""
	}
	return handle.LeaseID
}
