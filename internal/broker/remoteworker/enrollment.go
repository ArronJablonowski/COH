package remoteworker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func New(store Store, audit AuditSink) (*Broker, error) {
	return NewWithDependencies(store, audit, systemClock{}, rand.Reader,
		time.Duration(workercontract.MaximumLeaseTTLSeconds)*time.Second)
}

func NewWithDependencies(store Store, audit AuditSink, clock Clock, random io.Reader, maximumTTL time.Duration) (*Broker, error) {
	if store == nil || audit == nil || clock == nil || random == nil || maximumTTL <= 0 ||
		maximumTTL > time.Duration(workercontract.MaximumLeaseTTLSeconds)*time.Second {
		return nil, brokerError(workercontract.InvalidInput, "broker_configuration_invalid")
	}
	return &Broker{store: store, audit: audit, clock: clock, random: random, maxTTL: maximumTTL}, nil
}

func (broker *Broker) Enroll(ctx context.Context, request workercontract.EnrollmentRequest, authority workercontract.EnrollmentAuthority) (workercontract.WorkerRecord, workercontract.Decision, error) {
	now := time.Time{}
	if broker != nil && broker.clock != nil {
		now = broker.clock.Now().UTC()
	}
	if broker == nil || broker.store == nil || broker.audit == nil || broker.clock == nil {
		err := brokerError(workercontract.Unavailable, "broker_unavailable")
		return workercontract.WorkerRecord{}, enrollmentDecision(request, authority, workercontract.WorkerRecord{}, err, now), err
	}
	if err := contextError(ctx); err != nil {
		return broker.recordEnrollment(ctx, request, authority, workercontract.WorkerRecord{}, err, now)
	}
	if err := workercontract.ValidateEnrollmentRequest(request); err != nil {
		return broker.recordEnrollment(ctx, request, authority, workercontract.WorkerRecord{}, err, now)
	}
	if err := workercontract.ValidateEnrollmentAuthority(authority, now); err != nil {
		return broker.recordEnrollment(ctx, request, authority, workercontract.WorkerRecord{}, err, now)
	}
	if request.Scope != authority.Scope || request.WorkerID != authority.WorkerID ||
		request.EnrollmentNonce != authority.ExpectedEnrollmentNonce {
		err := brokerError(workercontract.Denied, "enrollment_authority_mismatch")
		return broker.recordEnrollment(ctx, request, authority, workercontract.WorkerRecord{}, err, now)
	}
	verified, err := workercontract.VerifyCapabilityAttestation(ctx, request.SignedAttestation, workercontract.AttestationAuthority{
		Scope: authority.Scope, WorkerID: authority.WorkerID, EnrollmentNonce: authority.ExpectedEnrollmentNonce,
		KeyID: authority.AttestationKeyID, KeyRevision: authority.AttestationKeyRevision, Active: authority.EnrollmentAllowed,
		PublicKey: authority.AttestationPublicKey, Transport: authority.Transport,
	}, now)
	if err != nil {
		return broker.recordEnrollment(ctx, request, authority, workercontract.WorkerRecord{}, err, now)
	}
	requestDigest, _ := workercontract.EnrollmentRequestDigest(request)
	record := workercontract.WorkerRecord{Scope: request.Scope, WorkerID: request.WorkerID, Active: true,
		TransportIdentityDigest: authority.Transport.IdentityDigest, CertificateFingerprint: authority.Transport.CertificateFingerprint,
		CertificateRevision: authority.Transport.CertificateRevision, AttestationDigest: verified.Digest,
		AttestationKeyID: verified.KeyID, AttestationKeyRevision: verified.KeyRevision,
		AttestationKeyDigest: digestBytes(authority.AttestationPublicKey),
		Attestation:          verified.Value(), EnrolledAt: now}
	created, result, err := broker.store.Enroll(ctx, record, requestDigest, request.IdempotencyKey, authority.ExpectedCurrentRevision)
	if err != nil {
		if workercontract.Code(err) == workercontract.Unavailable {
			err = brokerError(workercontract.Unavailable, "worker_store_unavailable")
		}
		return broker.recordEnrollment(ctx, request, authority, workercontract.WorkerRecord{}, err, now)
	}
	if result == EnrollmentConflict {
		err = brokerError(workercontract.Conflict, "enrollment_conflict")
		return broker.recordEnrollment(ctx, request, authority, workercontract.WorkerRecord{}, err, now)
	}
	return broker.recordEnrollment(ctx, request, authority, created, nil, now)
}

func (broker *Broker) recordEnrollment(ctx context.Context, request workercontract.EnrollmentRequest, authority workercontract.EnrollmentAuthority, record workercontract.WorkerRecord, resultErr error, now time.Time) (workercontract.WorkerRecord, workercontract.Decision, error) {
	decision := enrollmentDecision(request, authority, record, resultErr, now)
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := broker.audit.AppendRemoteWorkerDecision(auditCtx, decision); err != nil {
		if record.Revision > 0 {
			_, _ = broker.store.RevokeWorker(context.WithoutCancel(ctx), record.Scope, record.WorkerID, "audit_unavailable", now)
		}
		auditErr := brokerError(workercontract.Unavailable, "audit_unavailable")
		return workercontract.WorkerRecord{}, enrollmentDecision(request, authority, record, auditErr, now), auditErr
	}
	if resultErr != nil {
		return workercontract.WorkerRecord{}, decision, resultErr
	}
	return record, decision, nil
}

func enrollmentDecision(request workercontract.EnrollmentRequest, authority workercontract.EnrollmentAuthority, record workercontract.WorkerRecord, err error, now time.Time) workercontract.Decision {
	result, reason := outcome(err, "worker_enrolled")
	decision := workercontract.Decision{Event: "worker_enrollment", Outcome: result, ReasonCode: reason,
		RequestID: request.RequestID, OrganizationID: request.Scope.OrganizationID, TenantID: request.Scope.TenantID,
		WorkerID: request.WorkerID, WorkerRevision: record.Revision, TransportIdentityDigest: authority.Transport.IdentityDigest,
		CertificateFingerprint: authority.Transport.CertificateFingerprint, CertificateRevision: authority.Transport.CertificateRevision,
		AttestationDigest: record.AttestationDigest, AttestationKeyRevision: authority.AttestationKeyRevision,
		AttestationKeyDigest:        record.AttestationKeyDigest,
		AuthorizationDecisionDigest: authority.EnrollmentDecisionDigest, OccurredAt: now}
	if workercontract.Code(err) == workercontract.InvalidInput {
		decision.WorkerID, decision.TransportIdentityDigest, decision.CertificateFingerprint = "", "", ""
	}
	return workercontract.FinalizeDecision(decision)
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
