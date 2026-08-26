package remoteworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"reflect"
	"slices"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

func (broker *Broker) Issue(ctx context.Context, request workercontract.LeaseRequest, authority workercontract.LeaseAuthority) (*Handle, workercontract.Decision, error) {
	now := time.Time{}
	if broker != nil && broker.clock != nil {
		now = broker.clock.Now().UTC()
	}
	if broker == nil || broker.store == nil || broker.audit == nil || broker.clock == nil || broker.random == nil {
		err := brokerError(workercontract.Unavailable, "broker_unavailable")
		return nil, leaseDecision(request, authority, "", err, now, time.Time{}), err
	}
	if err := contextError(ctx); err != nil {
		return broker.recordIssue(ctx, request, authority, "", nil, err, now, time.Time{})
	}
	if err := workercontract.ValidateLeaseRequest(request); err != nil {
		return broker.recordIssue(ctx, request, authority, "", nil, err, now, time.Time{})
	}
	if err := validateLeaseAuthority(request, authority, now); err != nil {
		return broker.recordIssue(ctx, request, authority, "", nil, err, now, time.Time{})
	}
	current, err := broker.store.CurrentWorker(ctx, authority.Worker.Scope, authority.Worker.WorkerID)
	if err != nil {
		return broker.recordIssue(ctx, request, authority, "", nil, normalizeStoreError(ctx, err), now, time.Time{})
	}
	if !sameWorker(current, authority.Worker) {
		err = brokerError(workercontract.Denied, "worker_state_stale")
		return broker.recordIssue(ctx, request, authority, "", nil, err, now, time.Time{})
	}
	token := make([]byte, tokenBytes)
	if _, err = io.ReadFull(broker.random, token); err != nil {
		zero(token)
		err = brokerError(workercontract.Unavailable, "entropy_unavailable")
		return broker.recordIssue(ctx, request, authority, "", nil, err, now, time.Time{})
	}
	leaseID, err := newLeaseID(now, broker.random)
	if err != nil {
		zero(token)
		err = brokerError(workercontract.Unavailable, "entropy_unavailable")
		return broker.recordIssue(ctx, request, authority, "", nil, err, now, time.Time{})
	}
	ttl := time.Duration(request.RequestedTTLSeconds) * time.Second
	if ttl > broker.maxTTL {
		ttl = broker.maxTTL
	}
	expires := now.Add(ttl)
	attestationExpiry, _ := time.Parse(time.RFC3339Nano, current.Attestation.ExpiresAt)
	if expires.After(attestationExpiry) {
		expires = attestationExpiry
	}
	if !expires.After(now) {
		zero(token)
		err = brokerError(workercontract.Denied, "worker_attestation_expired")
		return broker.recordIssue(ctx, request, authority, "", nil, err, now, expires)
	}
	requestDigest, _ := workercontract.LeaseRequestDigest(request)
	record := LeaseRecord{LeaseID: leaseID, tokenDigest: sha256.Sum256(token), RequestDigest: requestDigest,
		Request: request, Authority: authority, IssuedAt: now, ExpiresAt: expires}
	created, err := broker.store.CreateLease(ctx, record)
	if err != nil {
		zero(token)
		return broker.recordIssue(ctx, request, authority, "", nil, normalizeStoreError(ctx, err), now, expires)
	}
	if created != LeaseNew {
		zero(token)
		reason := "lease_issuance_replay"
		if created == LeaseConflict {
			reason = "lease_idempotency_conflict"
		}
		err = brokerError(workercontract.Conflict, reason)
		return broker.recordIssue(ctx, request, authority, "", nil, err, now, expires)
	}
	handle := &Handle{LeaseID: leaseID, token: token}
	return broker.recordIssue(ctx, request, authority, leaseID, handle, nil, now, expires)
}

func validateLeaseAuthority(request workercontract.LeaseRequest, authority workercontract.LeaseAuthority, now time.Time) error {
	if err := workercontract.ValidateLeaseAuthority(authority, now); err != nil {
		return err
	}
	if !sameLeaseScope(request.Scope, authority.Scope) || request.WorkerID != authority.Worker.WorkerID ||
		request.Scope.OrganizationID != authority.Worker.Scope.OrganizationID ||
		request.Scope.TenantID != authority.Worker.Scope.TenantID {
		return brokerError(workercontract.Denied, "lease_authority_mismatch")
	}
	attestation := authority.Worker.Attestation
	if !slices.Contains(attestation.IsolationClasses, request.Scope.IsolationClass) ||
		tierValue(request.Scope.RequiredTier) > tierValue(attestation.MaximumActionTier) ||
		request.Scope.ToolRegistryDigest != attestation.ToolRegistryDigest {
		return brokerError(workercontract.Denied, "worker_isolation_mismatch")
	}
	if !slices.Contains(attestation.NetworkModes, request.Scope.NetworkMode) ||
		!withinCapacity(request.Scope.Resources, attestation.Resources) {
		return brokerError(workercontract.Denied, "worker_capacity_exceeded")
	}
	return nil
}

func (broker *Broker) recordIssue(ctx context.Context, request workercontract.LeaseRequest, authority workercontract.LeaseAuthority, leaseID string, handle *Handle, resultErr error, issuedAt, expiresAt time.Time) (*Handle, workercontract.Decision, error) {
	decision := leaseDecision(request, authority, leaseID, resultErr, issuedAt, expiresAt)
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := broker.audit.AppendRemoteWorkerDecision(auditCtx, decision); err != nil {
		if handle != nil {
			_, _ = broker.store.RevokeLease(context.WithoutCancel(ctx), handle.LeaseID, "audit_unavailable")
			handle.Destroy()
		}
		auditErr := brokerError(workercontract.Unavailable, "audit_unavailable")
		return nil, leaseDecision(request, authority, leaseID, auditErr, issuedAt, expiresAt), auditErr
	}
	if resultErr != nil {
		return nil, decision, resultErr
	}
	return handle, decision, nil
}

func leaseDecision(request workercontract.LeaseRequest, authority workercontract.LeaseAuthority, leaseID string, err error, issuedAt, expiresAt time.Time) workercontract.Decision {
	result, reason := outcome(err, "runner_lease_issued")
	scope := request.Scope
	decision := workercontract.Decision{Event: "runner_lease_issuance", Outcome: result, ReasonCode: reason,
		RequestID: request.RequestID, LeaseID: leaseID, OrganizationID: scope.OrganizationID, TenantID: scope.TenantID,
		CaseID: scope.CaseID, ActorID: scope.ActorID, ActorRevision: authority.ActorRevision, TaskID: scope.TaskID,
		ActionDigest: scope.ActionDigest, TargetScopeDigest: workercontract.TargetScopeDigest(scope.TargetDigests),
		ToolDigest: scope.ToolDigest, Operation: scope.Operation, RequiredTier: scope.RequiredTier,
		IsolationClass: scope.IsolationClass, WorkerID: request.WorkerID, WorkerRevision: authority.Worker.Revision,
		TransportIdentityDigest: authority.Worker.TransportIdentityDigest,
		CertificateFingerprint:  authority.Worker.CertificateFingerprint, CertificateRevision: authority.Worker.CertificateRevision,
		AttestationDigest: authority.Worker.AttestationDigest, AttestationKeyRevision: authority.Worker.AttestationKeyRevision,
		AttestationKeyDigest:        authority.Worker.AttestationKeyDigest,
		AuthorizationDecisionDigest: authority.AuthorizationDecisionDigest, PolicyDecisionDigest: authority.PolicyDecisionDigest,
		ApprovalDecisionDigest: authority.ApprovalDecisionDigest, IssuedAt: issuedAt, ExpiresAt: expiresAt, OccurredAt: issuedAt}
	if workercontract.Code(err) == workercontract.InvalidInput {
		decision.Operation, decision.WorkerID, decision.TransportIdentityDigest, decision.CertificateFingerprint = "", "", "", ""
	}
	return workercontract.FinalizeDecision(decision)
}

func newLeaseID(now time.Time, source io.Reader) (string, error) {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(source, bytes); err != nil {
		return "", err
	}
	milliseconds := uint64(now.UnixMilli())
	bytes[0], bytes[1], bytes[2] = byte(milliseconds>>40), byte(milliseconds>>32), byte(milliseconds>>24)
	bytes[3], bytes[4], bytes[5] = byte(milliseconds>>16), byte(milliseconds>>8), byte(milliseconds)
	bytes[6], bytes[8] = (bytes[6]&0x0f)|0x70, (bytes[8]&0x3f)|0x80
	encoded := hex.EncodeToString(bytes)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func withinCapacity(required, maximum workercontract.ResourceCapacity) bool {
	return required.WallTimeMilliseconds <= maximum.WallTimeMilliseconds && required.CPUMilliseconds <= maximum.CPUMilliseconds &&
		required.MemoryBytes <= maximum.MemoryBytes && required.OutputBytes <= maximum.OutputBytes &&
		required.EphemeralStorageBytes <= maximum.EphemeralStorageBytes && required.ProcessCount <= maximum.ProcessCount &&
		required.OpenFileCount <= maximum.OpenFileCount
}

func tierValue(value string) int {
	switch value {
	case "T0":
		return 0
	case "T1":
		return 1
	case "T2":
		return 2
	case "T3":
		return 3
	default:
		return 4
	}
}

func sameLeaseScope(left, right workercontract.LeaseScope) bool {
	return reflect.DeepEqual(left, right)
}

func sameWorker(left, right workercontract.WorkerRecord) bool {
	return reflect.DeepEqual(left, right)
}

func normalizeStoreError(ctx context.Context, err error) error {
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	switch workercontract.Code(err) {
	case workercontract.Denied, workercontract.NotFound, workercontract.Conflict:
		return err
	default:
		return brokerError(workercontract.Unavailable, "worker_store_unavailable")
	}
}
