package credentiallease

import (
	"context"
	"time"

	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

// Revoke atomically disables a lease before recording the administrative
// decision. Audit failure is returned, but can never restore dispatch access.
func (broker *Broker) Revoke(ctx context.Context, request leasecontract.RevocationRequest) (leasecontract.Decision, error) {
	now := time.Time{}
	if broker != nil && broker.clock != nil {
		now = broker.clock.Now().UTC()
	}
	if broker == nil || broker.store == nil || broker.audit == nil || broker.clock == nil {
		err := brokerError(leasecontract.Unavailable, "broker_unavailable")
		return revocationDecision(Record{}, request.LeaseID, err, now), err
	}
	if err := contextError(ctx); err != nil {
		return broker.recordRevocation(ctx, Record{}, request.LeaseID, err, now)
	}
	if err := leasecontract.ValidateRevocationRequest(request); err != nil {
		return broker.recordRevocation(ctx, Record{}, request.LeaseID, err, now)
	}
	record, err := broker.store.Revoke(ctx, request.LeaseID, request.Reason)
	if err != nil {
		return broker.recordRevocation(ctx, record, request.LeaseID, normalizeStoreError(ctx, err), now)
	}
	return broker.recordRevocation(ctx, record, request.LeaseID, nil, now)
}

func (broker *Broker) recordRevocation(ctx context.Context, record Record, leaseID string, resultErr error, now time.Time) (leasecontract.Decision, error) {
	decision := revocationDecision(record, leaseID, resultErr, now)
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := broker.audit.AppendCredentialLeaseDecision(auditCtx, decision); err != nil {
		auditErr := brokerError(leasecontract.Unavailable, "audit_unavailable")
		return revocationDecision(record, leaseID, auditErr, now), auditErr
	}
	return decision, resultErr
}

func revocationDecision(record Record, leaseID string, err error, now time.Time) leasecontract.Decision {
	outcome, reasonCode := "allowed", record.RevokeReason
	if reasonCode == "" {
		reasonCode = "lease_revoked"
	}
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
	}
	referenceDigest := ""
	if record.LeaseID != "" {
		referenceDigest, _ = secretref.ReferenceDigest(record.Request.Reference)
	}
	return leasecontract.NewRevocationDecision(record.Request, record.Authority, leaseID, outcome, reasonCode,
		referenceDigest, record.IssuedAt, record.ExpiresAt, now)
}
