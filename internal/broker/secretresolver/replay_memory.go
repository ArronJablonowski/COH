package secretresolver

import (
	"context"
	"strings"
	"sync"

	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

type MemoryReplayStore struct {
	mu      sync.Mutex
	records map[string]ReplayRecord
}

func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{records: make(map[string]ReplayRecord)}
}

func (store *MemoryReplayStore) CheckAndStore(ctx context.Context, record ReplayRecord) (ReplayResult, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if !validUUID(record.OrganizationID) || !validUUID(record.ActorID) || record.IdempotencyKey == "" ||
		len(record.IdempotencyKey) > 128 || strings.ContainsAny(record.IdempotencyKey, "\r\n\t") ||
		!validSHA256Digest(record.RequestDigest) {
		return "", resolverError(secretref.InvalidInput, "replay_record_invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	key := record.OrganizationID + "\x00" + record.ActorID + "\x00" + record.IdempotencyKey
	previous, exists := store.records[key]
	if !exists {
		store.records[key] = record
		return ReplayNew, nil
	}
	if previous.RequestDigest == record.RequestDigest {
		return ReplayExact, nil
	}
	return ReplayConflict, nil
}

func validSHA256Digest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

var _ ReplayStore = (*MemoryReplayStore)(nil)
