package remoteworker

import (
	"context"
	"crypto/subtle"
	"sync"
	"time"

	workercontract "github.com/ArronJablonowski/COH/internal/domain/remoteworker"
)

type enrollmentReplay struct {
	digest string
	record workercontract.WorkerRecord
}

type MemoryStore struct {
	mu          sync.Mutex
	workers     map[string]workercontract.WorkerRecord
	enrollments map[string]enrollmentReplay
	leases      map[string]LeaseRecord
	leaseKeys   map[string]string
	tokens      map[[32]byte]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{workers: make(map[string]workercontract.WorkerRecord), enrollments: make(map[string]enrollmentReplay),
		leases: make(map[string]LeaseRecord), leaseKeys: make(map[string]string), tokens: make(map[[32]byte]string)}
}

func (store *MemoryStore) Enroll(ctx context.Context, record workercontract.WorkerRecord, requestDigest, idempotencyKey string, expected uint64) (workercontract.WorkerRecord, EnrollmentResult, error) {
	if err := ctx.Err(); err != nil {
		return workercontract.WorkerRecord{}, "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	workerKey := workerKey(record.Scope, record.WorkerID)
	replayKey := workerKey + "\x00" + idempotencyKey
	if previous, exists := store.enrollments[replayKey]; exists {
		if previous.digest == requestDigest {
			current, currentExists := store.workers[workerKey]
			if !currentExists || !current.Active || current.Revision != previous.record.Revision {
				return workercontract.WorkerRecord{}, EnrollmentConflict, brokerError(workercontract.Denied, "worker_revoked_or_rotated")
			}
			return cloneWorker(current), EnrollmentReplay, nil
		}
		return workercontract.WorkerRecord{}, EnrollmentConflict, nil
	}
	current, exists := store.workers[workerKey]
	if (!exists && expected != 0) || (exists && current.Revision != expected) {
		return workercontract.WorkerRecord{}, EnrollmentConflict, nil
	}
	if exists {
		if !current.Active {
			return workercontract.WorkerRecord{}, EnrollmentConflict, brokerError(workercontract.Denied, "worker_revoked")
		}
		if err := validateRotation(current, record); err != nil {
			return workercontract.WorkerRecord{}, EnrollmentConflict, err
		}
	}
	record.Revision = expected + 1
	if exists {
		for leaseID, lease := range store.leases {
			if lease.Request.WorkerID == record.WorkerID && lease.Request.Scope.OrganizationID == record.Scope.OrganizationID &&
				lease.Request.Scope.TenantID == record.Scope.TenantID {
				lease.Revoked, lease.RevokeReason = true, "worker_rotated"
				store.leases[leaseID] = lease
			}
		}
	}
	store.workers[workerKey] = cloneWorker(record)
	store.enrollments[replayKey] = enrollmentReplay{digest: requestDigest, record: cloneWorker(record)}
	return cloneWorker(record), EnrollmentNew, nil
}

func validateRotation(current, next workercontract.WorkerRecord) error {
	if current.Scope != next.Scope || current.WorkerID != next.WorkerID ||
		next.CertificateRevision < current.CertificateRevision || next.AttestationKeyRevision < current.AttestationKeyRevision {
		return brokerError(workercontract.Denied, "worker_rotation_invalid")
	}
	if next.CertificateRevision == current.CertificateRevision &&
		(next.CertificateFingerprint != current.CertificateFingerprint || next.TransportIdentityDigest != current.TransportIdentityDigest) {
		return brokerError(workercontract.Denied, "certificate_continuity_invalid")
	}
	if next.CertificateRevision > current.CertificateRevision && next.CertificateFingerprint == current.CertificateFingerprint {
		return brokerError(workercontract.Denied, "certificate_rotation_invalid")
	}
	if next.AttestationKeyRevision == current.AttestationKeyRevision && next.AttestationKeyID != current.AttestationKeyID {
		return brokerError(workercontract.Denied, "attestation_key_continuity_invalid")
	}
	if next.AttestationKeyRevision == current.AttestationKeyRevision && next.AttestationKeyDigest != current.AttestationKeyDigest {
		return brokerError(workercontract.Denied, "attestation_key_continuity_invalid")
	}
	if next.AttestationKeyRevision > current.AttestationKeyRevision && next.AttestationKeyDigest == current.AttestationKeyDigest {
		return brokerError(workercontract.Denied, "attestation_key_rotation_invalid")
	}
	return nil
}

func (store *MemoryStore) CurrentWorker(ctx context.Context, scope workercontract.Scope, workerID string) (workercontract.WorkerRecord, error) {
	if err := ctx.Err(); err != nil {
		return workercontract.WorkerRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.workers[workerKey(scope, workerID)]
	if !exists {
		return workercontract.WorkerRecord{}, brokerError(workercontract.NotFound, "worker_not_found")
	}
	return cloneWorker(record), nil
}

func (store *MemoryStore) RevokeWorker(ctx context.Context, scope workercontract.Scope, workerID, reason string, at time.Time) (workercontract.WorkerRecord, error) {
	if err := ctx.Err(); err != nil {
		return workercontract.WorkerRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := workerKey(scope, workerID)
	record, exists := store.workers[key]
	if !exists {
		return workercontract.WorkerRecord{}, brokerError(workercontract.NotFound, "worker_not_found")
	}
	record.Active, record.RevokedAt, record.RevocationReason = false, at, reason
	store.workers[key] = record
	for leaseID, lease := range store.leases {
		if lease.Request.WorkerID == workerID && lease.Request.Scope.OrganizationID == scope.OrganizationID &&
			lease.Request.Scope.TenantID == scope.TenantID {
			lease.Revoked, lease.RevokeReason = true, reason
			store.leases[leaseID] = lease
		}
	}
	return cloneWorker(record), nil
}

func (store *MemoryStore) CreateLease(ctx context.Context, record LeaseRecord) (LeaseCreateResult, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, exists := store.workers[workerKey(record.Authority.Worker.Scope, record.Authority.Worker.WorkerID)]
	if !exists || !current.Active || !sameWorker(current, record.Authority.Worker) {
		return LeaseConflict, brokerError(workercontract.Denied, "worker_state_stale")
	}
	key := record.Request.Scope.OrganizationID + "\x00" + record.Request.Scope.ActorID + "\x00" + record.Request.IdempotencyKey
	if previous, exists := store.leaseKeys[key]; exists {
		if store.leases[previous].RequestDigest == record.RequestDigest {
			return LeaseReplay, nil
		}
		return LeaseConflict, nil
	}
	if _, exists := store.leases[record.LeaseID]; exists {
		return LeaseConflict, nil
	}
	if _, exists := store.tokens[record.tokenDigest]; exists {
		return LeaseConflict, nil
	}
	store.leases[record.LeaseID], store.leaseKeys[key], store.tokens[record.tokenDigest] = cloneLease(record), record.LeaseID, record.LeaseID
	return LeaseNew, nil
}

func (store *MemoryStore) ClaimLease(ctx context.Context, leaseID string, token [32]byte, now time.Time) (LeaseRecord, error) {
	if err := ctx.Err(); err != nil {
		return LeaseRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.leases[leaseID]
	if !exists {
		return LeaseRecord{}, brokerError(workercontract.NotFound, "lease_not_found")
	}
	if subtle.ConstantTimeCompare(record.tokenDigest[:], token[:]) != 1 {
		return LeaseRecord{}, brokerError(workercontract.Denied, "capability_invalid")
	}
	if record.Revoked {
		return cloneLease(record), brokerError(workercontract.Denied, "lease_revoked")
	}
	if !now.Before(record.ExpiresAt) {
		return cloneLease(record), brokerError(workercontract.Denied, "lease_expired")
	}
	if record.Consumed {
		return cloneLease(record), brokerError(workercontract.Conflict, "lease_replayed")
	}
	record.Consumed = true
	store.leases[leaseID] = record
	return cloneLease(record), nil
}

func (store *MemoryStore) RevokeLease(ctx context.Context, leaseID, reason string) (LeaseRecord, error) {
	if err := ctx.Err(); err != nil {
		return LeaseRecord{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.leases[leaseID]
	if !exists {
		return LeaseRecord{}, brokerError(workercontract.NotFound, "lease_not_found")
	}
	record.Revoked, record.RevokeReason = true, reason
	store.leases[leaseID] = record
	return cloneLease(record), nil
}

func (store *MemoryStore) RevokeWorkerLeases(ctx context.Context, scope workercontract.Scope, workerID, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for leaseID, lease := range store.leases {
		if lease.Request.WorkerID == workerID && lease.Request.Scope.OrganizationID == scope.OrganizationID &&
			lease.Request.Scope.TenantID == scope.TenantID {
			lease.Revoked, lease.RevokeReason = true, reason
			store.leases[leaseID] = lease
		}
	}
	return nil
}

func (store *MemoryStore) RevokeLeaseScope(ctx context.Context, organizationID, tenantID, caseID, reason string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	matched := 0
	for leaseID, lease := range store.leases {
		scope := lease.Request.Scope
		if scope.OrganizationID != organizationID || scope.TenantID != tenantID || (caseID != "" && scope.CaseID != caseID) {
			continue
		}
		matched++
		lease.Revoked, lease.RevokeReason = true, reason
		store.leases[leaseID] = lease
	}
	return matched, nil
}

func workerKey(scope workercontract.Scope, workerID string) string {
	return scope.OrganizationID + "\x00" + scope.TenantID + "\x00" + workerID
}

func cloneWorker(record workercontract.WorkerRecord) workercontract.WorkerRecord {
	record.Attestation.IsolationClasses = append([]string(nil), record.Attestation.IsolationClasses...)
	record.Attestation.NetworkModes = append([]string(nil), record.Attestation.NetworkModes...)
	return record
}

func cloneLease(record LeaseRecord) LeaseRecord {
	record.Request.Scope.TargetDigests = append([]string(nil), record.Request.Scope.TargetDigests...)
	record.Authority.Scope.TargetDigests = append([]string(nil), record.Authority.Scope.TargetDigests...)
	record.Authority.Worker = cloneWorker(record.Authority.Worker)
	return record
}
