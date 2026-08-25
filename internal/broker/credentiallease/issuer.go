package credentiallease

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"time"

	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

type systemClock struct{}

const maximumAuthorityAge = 30 * time.Second

func (systemClock) Now() time.Time { return time.Now().UTC() }

func New(store Store, audit AuditSink, resolver SecretResolver) (*Broker, error) {
	return NewWithDependencies(store, audit, resolver, systemClock{}, rand.Reader, time.Duration(leasecontract.MaximumTTLSeconds)*time.Second)
}

func NewWithDependencies(store Store, audit AuditSink, resolver SecretResolver, clock Clock, random io.Reader, maximumTTL time.Duration) (*Broker, error) {
	if store == nil || audit == nil || resolver == nil || clock == nil || random == nil || maximumTTL <= 0 ||
		maximumTTL > time.Duration(leasecontract.MaximumTTLSeconds)*time.Second {
		return nil, brokerError(leasecontract.InvalidInput, "broker_configuration_invalid")
	}
	return &Broker{store: store, audit: audit, resolver: resolver, clock: clock, random: random, maxTTL: maximumTTL}, nil
}

func (broker *Broker) Issue(ctx context.Context, request leasecontract.IssuanceRequest, authority leasecontract.IssuanceAuthority) (*Handle, leasecontract.Decision, error) {
	if broker == nil || broker.store == nil || broker.audit == nil || broker.clock == nil || broker.random == nil {
		err := brokerError(leasecontract.Unavailable, "broker_unavailable")
		return nil, issuanceDecision(request, authority, "", err, "", time.Time{}, time.Time{}), err
	}
	now := broker.clock.Now().UTC()
	if err := contextError(ctx); err != nil {
		return broker.recordIssue(ctx, request, authority, "", nil, err, "", now, time.Time{})
	}
	if err := leasecontract.ValidateIssuanceRequest(request); err != nil {
		return broker.recordIssue(ctx, request, authority, "", nil, err, "", now, time.Time{})
	}
	if err := validateAuthority(request, authority, now); err != nil {
		return broker.recordIssue(ctx, request, authority, "", nil, err, "", now, time.Time{})
	}
	requestDigest, _ := leasecontract.RequestDigest(request)
	referenceDigest, _ := secretref.ReferenceDigest(request.Reference)
	ttl := time.Duration(request.RequestedTTLSeconds) * time.Second
	if ttl > broker.maxTTL {
		ttl = broker.maxTTL
	}
	token := make([]byte, tokenBytes)
	if _, err := io.ReadFull(broker.random, token); err != nil {
		zero(token)
		resultErr := brokerError(leasecontract.Unavailable, "entropy_unavailable")
		return broker.recordIssue(ctx, request, authority, "", nil, resultErr, referenceDigest, now, time.Time{})
	}
	leaseID, err := newLeaseID(now, broker.random)
	if err != nil {
		zero(token)
		resultErr := brokerError(leasecontract.Unavailable, "entropy_unavailable")
		return broker.recordIssue(ctx, request, authority, "", nil, resultErr, referenceDigest, now, time.Time{})
	}
	expires := now.Add(ttl)
	record := Record{LeaseID: leaseID, TokenDigest: sha256.Sum256(token), RequestDigest: requestDigest,
		Request: request, Authority: authority, IssuedAt: now, ExpiresAt: expires}
	created, err := broker.store.Create(ctx, record)
	if err != nil {
		zero(token)
		resultErr := brokerError(leasecontract.Unavailable, "lease_store_unavailable")
		if contextErr := contextError(ctx); contextErr != nil {
			resultErr = contextErr
		}
		return broker.recordIssue(ctx, request, authority, "", nil, resultErr, referenceDigest, now, expires)
	}
	if created != CreateNew {
		zero(token)
		reasonCode := "issuance_replay"
		if created == CreateConflict {
			reasonCode = "idempotency_conflict"
		}
		resultErr := brokerError(leasecontract.Conflict, reasonCode)
		return broker.recordIssue(ctx, request, authority, "", nil, resultErr, referenceDigest, now, expires)
	}
	handle := &Handle{LeaseID: leaseID, token: token}
	return broker.recordIssue(ctx, request, authority, leaseID, handle, nil, referenceDigest, now, expires)
}

func validateAuthority(request leasecontract.IssuanceRequest, authority leasecontract.IssuanceAuthority, now time.Time) error {
	if err := leasecontract.ValidateIssuanceAuthority(authority); err != nil {
		return err
	}
	if authority.Context != request.Context || authority.Audience.Audience != request.Audience {
		return brokerError(leasecontract.Denied, "authority_scope_mismatch")
	}
	if !authority.Active {
		return brokerError(leasecontract.Denied, "actor_revoked")
	}
	if !authority.AuthorizationAllowed {
		return brokerError(leasecontract.Denied, "authorization_denied")
	}
	if !authority.PolicyAllowed {
		return brokerError(leasecontract.Denied, "policy_denied")
	}
	if authority.ApprovalRequired && !authority.ApprovalAllowed {
		return brokerError(leasecontract.Denied, "approval_denied")
	}
	if !authority.Audience.Active {
		return brokerError(leasecontract.Denied, "audience_revoked")
	}
	observedAt := authority.Audience.ObservedAt.UTC()
	if observedAt.After(now) || now.Sub(observedAt) > maximumAuthorityAge {
		return brokerError(leasecontract.Denied, "audience_state_stale")
	}
	return nil
}

func (broker *Broker) recordIssue(ctx context.Context, request leasecontract.IssuanceRequest, authority leasecontract.IssuanceAuthority, leaseID string, handle *Handle, resultErr error, referenceDigest string, issuedAt, expiresAt time.Time) (*Handle, leasecontract.Decision, error) {
	decision := issuanceDecision(request, authority, leaseID, resultErr, referenceDigest, issuedAt, expiresAt)
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := broker.audit.AppendCredentialLeaseDecision(auditCtx, decision); err != nil {
		if handle != nil {
			_, _ = broker.store.Revoke(context.WithoutCancel(ctx), handle.LeaseID, "audit_unavailable")
			handle.Destroy()
		}
		auditErr := brokerError(leasecontract.Unavailable, "audit_unavailable")
		return nil, issuanceDecision(request, authority, leaseID, auditErr, referenceDigest, issuedAt, expiresAt), auditErr
	}
	if resultErr != nil {
		return nil, decision, resultErr
	}
	return handle, decision, nil
}

func issuanceDecision(request leasecontract.IssuanceRequest, authority leasecontract.IssuanceAuthority, leaseID string, err error, referenceDigest string, issuedAt, expiresAt time.Time) leasecontract.Decision {
	outcome, reasonCode := "allowed", "lease_issued"
	if err != nil {
		outcome, reasonCode = "unavailable", reason(err)
		switch leasecontract.Code(err) {
		case leasecontract.InvalidInput:
			outcome = "invalid"
		case leasecontract.Denied, leasecontract.Conflict:
			outcome = "denied"
		case leasecontract.Canceled:
			outcome = "canceled"
		case leasecontract.Timeout:
			outcome = "timeout"
		}
		if leasecontract.Code(err) == leasecontract.InvalidInput {
			request.Operation = ""
			request.Audience = leasecontract.Audience{}
			request.CredentialClass = ""
			referenceDigest = ""
		}
	}
	return leasecontract.NewIssuanceDecision(request, authority, leaseID, outcome, reasonCode, referenceDigest, issuedAt, expiresAt)
}

func newLeaseID(now time.Time, source io.Reader) (string, error) {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(source, bytes); err != nil {
		return "", err
	}
	milliseconds := uint64(now.UnixMilli())
	bytes[0], bytes[1], bytes[2] = byte(milliseconds>>40), byte(milliseconds>>32), byte(milliseconds>>24)
	bytes[3], bytes[4], bytes[5] = byte(milliseconds>>16), byte(milliseconds>>8), byte(milliseconds)
	bytes[6] = (bytes[6] & 0x0f) | 0x70
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(bytes)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}
