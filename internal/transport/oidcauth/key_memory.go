package oidcauth

import (
	"context"
	"sync"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

type MemoryKeySource struct {
	mu      sync.RWMutex
	records map[string]KeyRecord
}

func NewMemoryKeySource(records []KeyRecord) (*MemoryKeySource, error) {
	source := &MemoryKeySource{records: make(map[string]KeyRecord, len(records))}
	for _, record := range records {
		if !validKeyRecord(record) {
			return nil, authError(localidentity.InvalidInput, "key_record_invalid")
		}
		key := keyRecordKey(record.Issuer, record.SourceReference, record.ID)
		if _, exists := source.records[key]; exists {
			return nil, authError(localidentity.Conflict, "key_record_conflict")
		}
		source.records[key] = record
	}
	return source, nil
}

func (source *MemoryKeySource) LookupKey(ctx context.Context, issuer, reference, id string) (KeyRecord, error) {
	if err := ctx.Err(); err != nil {
		return KeyRecord{}, err
	}
	source.mu.RLock()
	defer source.mu.RUnlock()
	record, exists := source.records[keyRecordKey(issuer, reference, id)]
	if !exists {
		return KeyRecord{}, ErrNotFound
	}
	return record, nil
}

func (source *MemoryKeySource) Replace(ctx context.Context, record KeyRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validKeyRecord(record) {
		return authError(localidentity.InvalidInput, "key_record_invalid")
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	key := keyRecordKey(record.Issuer, record.SourceReference, record.ID)
	current, exists := source.records[key]
	if !exists || record.Revision != current.Revision+1 {
		return authError(localidentity.Conflict, "key_revision_conflict")
	}
	source.records[key] = record
	return nil
}

func keyRecordKey(issuer, reference, id string) string {
	return issuer + "\x00" + reference + "\x00" + id
}

var _ KeySource = (*MemoryKeySource)(nil)
