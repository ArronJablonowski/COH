package kustovalidator

import (
	"context"
	"sync"
)

type memoryReplayEntry struct {
	digest    string
	done      chan struct{}
	record    ReplayRecord
	completed bool
}

// MemoryReplayStore provides exact in-process coalescing. Durable deployments
// implement ReplayStore with the same atomic reserve/complete semantics.
type MemoryReplayStore struct {
	mu      sync.Mutex
	entries map[string]*memoryReplayEntry
}

func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{entries: make(map[string]*memoryReplayEntry)}
}

func (store *MemoryReplayStore) BeginKustoValidation(ctx context.Context, key, digest string) (ReplayRecord, bool, error) {
	if store == nil || ctx == nil {
		return ReplayRecord{}, false, context.Canceled
	}
	for {
		store.mu.Lock()
		entry := store.entries[key]
		if entry == nil {
			store.entries[key] = &memoryReplayEntry{digest: digest, done: make(chan struct{})}
			store.mu.Unlock()
			return ReplayRecord{}, false, nil
		}
		if entry.digest != digest {
			store.mu.Unlock()
			return ReplayRecord{}, false, ErrChangedReplay
		}
		if entry.completed {
			record := clone(entry.record)
			store.mu.Unlock()
			return record, true, nil
		}
		done := entry.done
		store.mu.Unlock()
		select {
		case <-ctx.Done():
			return ReplayRecord{}, false, ctx.Err()
		case <-done:
		}
	}
}

func (store *MemoryReplayStore) CompleteKustoValidation(_ context.Context, key string, record ReplayRecord) error {
	if store == nil {
		return context.Canceled
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry := store.entries[key]
	if entry == nil || entry.digest != record.RequestDigest || entry.completed {
		return ErrChangedReplay
	}
	entry.record, entry.completed = clone(record), true
	close(entry.done)
	return nil
}

func (store *MemoryReplayStore) AbandonKustoValidation(_ context.Context, key, digest string) {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry := store.entries[key]
	if entry != nil && entry.digest == digest && !entry.completed {
		delete(store.entries, key)
		close(entry.done)
	}
}
