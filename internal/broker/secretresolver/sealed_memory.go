package secretresolver

import (
	"context"
	"crypto/subtle"
	"sync"

	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

const sealedMemoryBackendName = "sealed-memory"

// SealedMemoryBackend is deterministic ephemeral state for tests and local
// development only. It is not an approved production secret store.
type SealedMemoryBackend struct {
	mu      sync.RWMutex
	entries map[string]Record
	closed  bool
}

func NewSealedMemoryBackend(entries []Record) (*SealedMemoryBackend, error) {
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.Backend != sealedMemoryBackendName || validateRecord(entry, entry.Value) != nil {
			return nil, resolverError(secretref.InvalidInput, "sealed_entry_invalid")
		}
		if seen[entry.EntryID] {
			return nil, resolverError(secretref.Conflict, "sealed_entry_conflict")
		}
		seen[entry.EntryID] = true
	}
	backend := &SealedMemoryBackend{entries: make(map[string]Record, len(entries))}
	for _, entry := range entries {
		backend.entries[entry.EntryID] = cloneRecord(entry)
		zero(entry.Value)
	}
	return backend, nil
}

func (*SealedMemoryBackend) Name() string { return sealedMemoryBackendName }

func (backend *SealedMemoryBackend) Fetch(ctx context.Context, reference secretref.Reference) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	backend.mu.RLock()
	defer backend.mu.RUnlock()
	if backend.closed {
		return Record{}, resolverError(secretref.Unavailable, "sealed_backend_closed")
	}
	if err := secretref.ValidateReference(reference); err != nil || reference.Backend != sealedMemoryBackendName {
		return Record{}, ErrNotFound
	}
	record, exists := backend.entries[reference.EntryID]
	if !exists {
		return Record{}, ErrNotFound
	}
	return cloneRecord(record), nil
}

// Replace atomically applies the exact next metadata revision. Keeping a value
// version requires identical bytes; rotating bytes requires version+1.
func (backend *SealedMemoryBackend) Replace(ctx context.Context, next Record) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if next.Backend != sealedMemoryBackendName || validateRecord(next, next.Value) != nil {
		return resolverError(secretref.InvalidInput, "sealed_entry_invalid")
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed {
		return resolverError(secretref.Unavailable, "sealed_backend_closed")
	}
	current, exists := backend.entries[next.EntryID]
	if !exists || next.Revision != current.Revision+1 || next.Version < current.Version || next.Version > current.Version+1 ||
		(next.Version == current.Version && subtle.ConstantTimeCompare(next.Value, current.Value) != 1) {
		return resolverError(secretref.Conflict, "sealed_revision_conflict")
	}
	backend.entries[next.EntryID] = cloneRecord(next)
	zero(current.Value)
	zero(next.Value)
	return nil
}

func (backend *SealedMemoryBackend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.closed {
		return nil
	}
	for key, record := range backend.entries {
		zero(record.Value)
		delete(backend.entries, key)
	}
	backend.closed = true
	return nil
}

var _ Backend = (*SealedMemoryBackend)(nil)
