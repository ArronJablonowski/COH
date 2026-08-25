package credentiallease

import (
	"context"
	"sync"

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
	if _, exists := store.tokens[record.TokenDigest]; exists {
		return CreateConflict, nil
	}
	store.records[record.LeaseID] = cloneRecord(record)
	store.requests[key] = record.RequestDigest
	store.tokens[record.TokenDigest] = record.LeaseID
	return CreateNew, nil
}

func (store *MemoryStore) Revoke(ctx context.Context, leaseID, reason string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[leaseID]
	if !exists {
		return brokerError(leasecontract.Denied, "lease_not_found")
	}
	record.Revoked = true
	record.RevokeReason = reason
	store.records[leaseID] = record
	return nil
}

func cloneRecord(record Record) Record {
	record.Request.TargetDigests = append([]string(nil), record.Request.TargetDigests...)
	return record
}
