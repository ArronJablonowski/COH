package credentiallease

import (
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"time"

	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

// Use atomically consumes one lease, revalidates every authority binding,
// resolves the current credential version, appends audit, and only then gives
// a temporary secret copy to the callback.
func (broker *Broker) Use(ctx context.Context, handle *Handle, request leasecontract.DispatchRequest, authority leasecontract.DispatchAuthority, consumer func([]byte) error) (leasecontract.Decision, error) {
	now := time.Time{}
	if broker != nil && broker.clock != nil {
		now = broker.clock.Now().UTC()
	}
	if broker == nil || broker.store == nil || broker.audit == nil || broker.resolver == nil || broker.clock == nil {
		err := brokerError(leasecontract.Unavailable, "broker_unavailable")
		return dispatchDecision(Record{}, request, authority, leaseID(handle), err, "", now), err
	}
	if err := contextError(ctx); err != nil {
		return broker.recordDispatch(ctx, Record{}, request, authority, leaseID(handle), err, "", now)
	}
	if handle == nil || consumer == nil {
		err := brokerError(leasecontract.InvalidInput, "dispatch_input_invalid")
		return broker.recordDispatch(ctx, Record{}, request, authority, leaseID(handle), err, "", now)
	}
	tokenDigest, err := handle.digest()
	if err != nil {
		return broker.recordDispatch(ctx, Record{}, request, authority, handle.LeaseID, err, "", now)
	}
	record, err := broker.store.Claim(ctx, handle.LeaseID, tokenDigest, now)
	if err != nil {
		if leasecontract.Code(err) != leasecontract.Unavailable && leasecontract.Code(err) != leasecontract.Canceled && leasecontract.Code(err) != leasecontract.Timeout {
			handle.Destroy()
		}
		resultErr := normalizeStoreError(ctx, err)
		return broker.recordDispatch(ctx, record, request, authority, handle.LeaseID, resultErr, "", now)
	}
	handle.Destroy()
	if err := validateDispatch(record, request, authority, now); err != nil {
		return broker.recordDispatch(ctx, record, request, authority, record.LeaseID, err, "", now)
	}
	resolutionRequest := secretref.ResolutionRequest{
		SchemaVersion: secretref.SchemaVersion, ContractVersion: secretref.ContractVersion,
		RequestID: record.Request.RequestID, IdempotencyKey: "lease-dispatch-" + record.LeaseID,
		Context: record.Request.Context, ActionDigest: record.Request.ActionDigest,
		CredentialClass: record.Request.CredentialClass, Reference: record.Request.Reference,
	}
	resolutionAuthority := secretref.AuthoritySnapshot{
		Context: authority.Context, Active: authority.Active, ActorRevision: authority.ActorRevision,
		AuthorizationDecisionDigest: authority.AuthorizationDecisionDigest,
	}
	secret, secretDecision, resolveErr := broker.resolver.Resolve(ctx, resolutionRequest, resolutionAuthority)
	if resolveErr != nil {
		return broker.recordDispatch(ctx, record, request, authority, record.LeaseID, mapResolutionError(resolveErr), secretDecision.DecisionDigest, now)
	}
	if secret == nil {
		err := brokerError(leasecontract.Unavailable, "credential_resolution_unavailable")
		return broker.recordDispatch(ctx, record, request, authority, record.LeaseID, err, secretDecision.DecisionDigest, now)
	}
	defer secret.Destroy()
	decision, err := broker.recordDispatch(ctx, record, request, authority, record.LeaseID, nil, secretDecision.DecisionDigest, now)
	if err != nil {
		return decision, err
	}
	if err := secret.Use(consumer); err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return decision, contextErr
		}
		return decision, brokerError(leasecontract.Unavailable, "dispatch_failed")
	}
	return decision, nil
}

func (handle *Handle) digest() ([32]byte, error) {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.dead || len(handle.token) != tokenBytes {
		return [32]byte{}, brokerError(leasecontract.Denied, "capability_destroyed")
	}
	return sha256.Sum256(handle.token), nil
}

func validateDispatch(record Record, request leasecontract.DispatchRequest, authority leasecontract.DispatchAuthority, now time.Time) error {
	if err := leasecontract.ValidateDispatchRequest(request); err != nil {
		return err
	}
	if err := leasecontract.ValidateDispatchAuthority(authority); err != nil {
		return err
	}
	bound := record.Request
	if request.Context != bound.Context || request.TaskID != bound.TaskID || request.ActionDigest != bound.ActionDigest ||
		request.Operation != bound.Operation || !slices.Equal(request.TargetDigests, bound.TargetDigests) {
		return brokerError(leasecontract.Denied, "lease_scope_mismatch")
	}
	if request.Audience.Kind != bound.Audience.Kind || request.Audience.ID != bound.Audience.ID {
		return brokerError(leasecontract.Denied, "audience_scope_mismatch")
	}
	if request.Audience.TransportIdentityDigest != bound.Audience.TransportIdentityDigest {
		return brokerError(leasecontract.Denied, "transport_identity_rotated")
	}
	if !authority.TaskActive {
		return brokerError(leasecontract.Denied, "task_canceled")
	}
	if authority.EmergencyStopActive {
		return brokerError(leasecontract.Denied, "emergency_stop_active")
	}
	if err := validateAuthority(bound, authority.IssuanceAuthority, now); err != nil {
		return err
	}
	if !sameAuthority(record.Authority, authority.IssuanceAuthority) {
		return brokerError(leasecontract.Denied, "authority_state_stale")
	}
	return nil
}

func sameAuthority(initial, current leasecontract.IssuanceAuthority) bool {
	return initial.Context == current.Context && initial.Active == current.Active &&
		initial.ActorRevision == current.ActorRevision && initial.AuthorizationAllowed == current.AuthorizationAllowed &&
		initial.AuthorizationDecisionDigest == current.AuthorizationDecisionDigest && initial.PolicyAllowed == current.PolicyAllowed &&
		initial.PolicyDecisionDigest == current.PolicyDecisionDigest && initial.ApprovalRequired == current.ApprovalRequired &&
		initial.ApprovalAllowed == current.ApprovalAllowed && initial.ApprovalDecisionDigest == current.ApprovalDecisionDigest &&
		initial.Audience.Audience == current.Audience.Audience && initial.Audience.Active == current.Audience.Active &&
		initial.Audience.Revision == current.Audience.Revision && initial.Audience.Remote == current.Audience.Remote &&
		initial.Audience.MutualTLS == current.Audience.MutualTLS
}

func (broker *Broker) recordDispatch(ctx context.Context, record Record, request leasecontract.DispatchRequest, authority leasecontract.DispatchAuthority, publicLeaseID string, resultErr error, secretDecisionDigest string, now time.Time) (leasecontract.Decision, error) {
	decision := dispatchDecision(record, request, authority, publicLeaseID, resultErr, secretDecisionDigest, now)
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := broker.audit.AppendCredentialLeaseDecision(auditCtx, decision); err != nil {
		auditErr := brokerError(leasecontract.Unavailable, "audit_unavailable")
		return dispatchDecision(record, request, authority, publicLeaseID, auditErr, secretDecisionDigest, now), auditErr
	}
	return decision, resultErr
}

func dispatchDecision(record Record, request leasecontract.DispatchRequest, authority leasecontract.DispatchAuthority, publicLeaseID string, err error, secretDecisionDigest string, now time.Time) leasecontract.Decision {
	bound := record.Request
	initialAuthority := authority.IssuanceAuthority
	referenceDigest := ""
	if record.LeaseID == "" {
		bound = leasecontract.IssuanceRequest{Context: request.Context, TaskID: request.TaskID, ActionDigest: request.ActionDigest,
			TargetDigests: request.TargetDigests, Operation: request.Operation, Audience: request.Audience}
	} else {
		initialAuthority = record.Authority
		referenceDigest, _ = secretref.ReferenceDigest(record.Request.Reference)
	}
	outcome, reasonCode := "allowed", "dispatch_authorized"
	if err != nil {
		outcome, reasonCode = "unavailable", reason(err)
		switch leasecontract.Code(err) {
		case leasecontract.InvalidInput:
			outcome = "invalid"
			bound.Operation = ""
			bound.Audience = leasecontract.Audience{}
			bound.CredentialClass = ""
		case leasecontract.Denied, leasecontract.Conflict:
			outcome = "denied"
		case leasecontract.Canceled:
			outcome = "canceled"
		case leasecontract.Timeout:
			outcome = "timeout"
		}
	}
	return leasecontract.NewDispatchDecision(bound, initialAuthority, publicLeaseID, outcome, reasonCode, referenceDigest, secretDecisionDigest, record.IssuedAt, record.ExpiresAt, now)
}

func normalizeStoreError(ctx context.Context, err error) error {
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	if leasecontract.Code(err) == leasecontract.Denied || leasecontract.Code(err) == leasecontract.Conflict {
		return err
	}
	return brokerError(leasecontract.Unavailable, "lease_store_unavailable")
}

func mapResolutionError(err error) error {
	code := leasecontract.Unavailable
	switch secretref.Code(err) {
	case secretref.InvalidInput:
		code = leasecontract.InvalidInput
	case secretref.Denied:
		code = leasecontract.Denied
	case secretref.Conflict:
		code = leasecontract.Conflict
	case secretref.Canceled:
		code = leasecontract.Canceled
	case secretref.Timeout:
		code = leasecontract.Timeout
	}
	return brokerError(code, "credential_"+secretReason(err))
}

func secretReason(err error) string {
	var secretErr *secretref.Error
	if errors.As(err, &secretErr) {
		return secretErr.Reason
	}
	return "resolution_unavailable"
}

func leaseID(handle *Handle) string {
	if handle == nil {
		return ""
	}
	return handle.LeaseID
}
