package remoteworker

import (
	"context"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

func (broker *Broker) Revoke(ctx context.Context, request workercontract.RevocationRequest) (workercontract.Decision, error) {
	now := time.Time{}
	if broker != nil && broker.clock != nil {
		now = broker.clock.Now().UTC()
	}
	if broker == nil || broker.store == nil || broker.audit == nil || broker.clock == nil {
		err := brokerError(workercontract.Unavailable, "broker_unavailable")
		return revocationDecision(request, workercontract.WorkerRecord{}, err, now), err
	}
	if err := contextError(ctx); err != nil {
		return broker.recordRevocation(ctx, request, workercontract.WorkerRecord{}, err, now)
	}
	if err := workercontract.ValidateRevocationRequest(request); err != nil {
		return broker.recordRevocation(ctx, request, workercontract.WorkerRecord{}, err, now)
	}
	var record workercontract.WorkerRecord
	var err error
	if request.Kind == "lease" {
		_, err = broker.store.RevokeLease(ctx, request.LeaseID, request.Reason)
	} else {
		record, err = broker.store.RevokeWorker(ctx, request.Scope, request.WorkerID, request.Reason, now)
		if err == nil {
			err = broker.store.RevokeWorkerLeases(ctx, request.Scope, request.WorkerID, request.Reason)
		}
	}
	if err != nil {
		err = normalizeStoreError(ctx, err)
	}
	return broker.recordRevocation(ctx, request, record, err, now)
}

func (broker *Broker) recordRevocation(ctx context.Context, request workercontract.RevocationRequest, record workercontract.WorkerRecord, resultErr error, now time.Time) (workercontract.Decision, error) {
	decision := revocationDecision(request, record, resultErr, now)
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := broker.audit.AppendRemoteWorkerDecision(auditCtx, decision); err != nil {
		auditErr := brokerError(workercontract.Unavailable, "audit_unavailable")
		return revocationDecision(request, record, auditErr, now), auditErr
	}
	return decision, resultErr
}

func revocationDecision(request workercontract.RevocationRequest, record workercontract.WorkerRecord, err error, now time.Time) workercontract.Decision {
	result, reason := outcome(err, "revocation_applied")
	decision := workercontract.Decision{Event: request.Kind + "_revocation", Outcome: result, ReasonCode: reason,
		LeaseID: request.LeaseID, OrganizationID: request.Scope.OrganizationID, TenantID: request.Scope.TenantID,
		WorkerID: request.WorkerID, WorkerRevision: record.Revision, TransportIdentityDigest: record.TransportIdentityDigest,
		CertificateFingerprint: record.CertificateFingerprint, CertificateRevision: record.CertificateRevision,
		AttestationDigest: record.AttestationDigest, AttestationKeyRevision: record.AttestationKeyRevision,
		AttestationKeyDigest: record.AttestationKeyDigest, OccurredAt: now}
	return workercontract.FinalizeDecision(decision)
}
