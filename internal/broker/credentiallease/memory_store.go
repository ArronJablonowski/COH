package credentiallease

import (
	"context"
	"crypto/subtle"
	"sync"
	"time"

	leasecontract "github.com/ArronJablonowski/COH/internal/domain/credentiallease"
)

type MemoryStore struct {
	mu       sync.Mutex
	records  map[string]Record
	requests map[string]string
	tokens   map[[32]byte]string
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{records: make(map[string]Record), requests: make(map[string]string), tokens: make(map[[32]byte]string)}
}

func (store *MemoryStore) Create(ctx context.Context, record Record) (CreateResult, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.Request.Context.OrganizationID + "\x00" + record.Request.Context.ActorID + "\x00" + record.Request.IdempotencyKey
	if previous, exists := store.requests[key]; exists {
		if previous == record.RequestDigest {
			return CreateReplay, nil
		}
		return CreateConflict, nil
	}
	if _, exists := store.records[record.LeaseID]; exists {
		return CreateConflict, nil
	}
	if _, exists := store.tokens[record.tokenDigest]; exists {
		return CreateConflict, nil
	}
	store.records[record.LeaseID] = cloneRecord(record)
	store.requests[key] = record.RequestDigest
	store.tokens[record.tokenDigest] = record.LeaseID
	return CreateNew, nil
}

func (store *MemoryStore) Claim(ctx context.Context, leaseID string, tokenDigest [32]byte, now time.Time) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[leaseID]
	if !exists {
		return Record{}, brokerError(leasecontract.Denied, "lease_not_found")
	}
	if subtle.ConstantTimeCompare(record.tokenDigest[:], tokenDigest[:]) != 1 {
		return Record{}, brokerError(leasecontract.Denied, "capability_invalid")
	}
	if record.Revoked {
		return cloneRecord(record), brokerError(leasecontract.Denied, "lease_revoked")
	}
	if !now.Before(record.ExpiresAt) {
		return cloneRecord(record), brokerError(leasecontract.Denied, "lease_expired")
	}
	if record.Consumed {
		return cloneRecord(record), brokerError(leasecontract.Conflict, "lease_replayed")
	}
	record.Consumed = true
	store.records[leaseID] = record
	return cloneRecord(record), nil
}

func (store *MemoryStore) Revoke(ctx context.Context, leaseID, reason string) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[leaseID]
	if !exists {
		return Record{}, brokerError(leasecontract.Denied, "lease_not_found")
	}
	record.Revoked = true
	record.RevokeReason = reason
	store.records[leaseID] = record
	return cloneRecord(record), nil
}

func (store *MemoryStore) RevokeScope(ctx context.Context, organizationID, tenantID, caseID, reason string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	matched := 0
	for leaseID, record := range store.records {
		scope := record.Request.Context
		if scope.OrganizationID != organizationID || scope.TenantID != tenantID || (caseID != "" && scope.CaseID != caseID) {
			continue
		}
		matched++
		record.Revoked, record.RevokeReason = true, reason
		store.records[leaseID] = record
	}
	return matched, nil
}

func cloneRecord(record Record) Record {
	record.Request.TargetDigests = append([]string(nil), record.Request.TargetDigests...)
	return record
}
