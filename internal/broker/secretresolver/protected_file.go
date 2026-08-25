package secretresolver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"sync"

	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

const protectedFileBackendName = "protected-file"

type ProtectedFileBackend struct {
	mu      sync.RWMutex
	root    *os.Root
	entries map[string]protectedEntry
}

type protectedEntry struct {
	record      Record
	fingerprint [sha256.Size]byte
}

// NewProtectedFileBackend opens a descriptor-rooted secret directory. Each
// opaque entry ID maps to <entry-id>.secret; no path is accepted from a
// reference or workflow-controlled request.
func NewProtectedFileBackend(rootPath string, entries []Record) (*ProtectedFileBackend, error) {
	before, err := os.Lstat(rootPath)
	if err != nil || !secureDirectory(before) {
		return nil, resolverError(secretref.InvalidInput, "protected_root_invalid")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, resolverError(secretref.Unavailable, "protected_root_unavailable")
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) || !secureDirectory(opened) {
		_ = root.Close()
		return nil, resolverError(secretref.InvalidInput, "protected_root_invalid")
	}
	if len(entries) == 0 {
		_ = root.Close()
		return nil, resolverError(secretref.InvalidInput, "protected_entry_invalid")
	}
	registry := make(map[string]protectedEntry, len(entries))
	for _, entry := range entries {
		if entry.Backend != protectedFileBackendName || len(entry.Value) != 0 {
			_ = root.Close()
			return nil, resolverError(secretref.InvalidInput, "protected_entry_invalid")
		}
		if err := validateRecordMetadata(entry); err != nil {
			_ = root.Close()
			return nil, resolverError(secretref.InvalidInput, "protected_entry_invalid")
		}
		if _, exists := registry[entry.EntryID]; exists {
			_ = root.Close()
			return nil, resolverError(secretref.Conflict, "protected_entry_conflict")
		}
		value, readErr := readProtectedFile(context.Background(), root, entry.EntryID+".secret")
		if readErr != nil {
			_ = root.Close()
			return nil, resolverError(secretref.InvalidInput, "protected_entry_invalid")
		}
		fingerprint := sha256.Sum256(value)
		zero(value)
		registry[entry.EntryID] = protectedEntry{record: cloneRecord(entry), fingerprint: fingerprint}
	}
	return &ProtectedFileBackend{root: root, entries: registry}, nil
}

func (*ProtectedFileBackend) Name() string { return protectedFileBackendName }

func (backend *ProtectedFileBackend) Fetch(ctx context.Context, reference secretref.Reference) (Record, error) {
	if err := ctx.Err(); err != nil {
		return Record{}, err
	}
	backend.mu.RLock()
	defer backend.mu.RUnlock()
	if backend.root == nil {
		return Record{}, errors.New("protected backend is closed")
	}
	if err := secretref.ValidateReference(reference); err != nil || reference.Backend != protectedFileBackendName {
		return Record{}, ErrNotFound
	}
	entry, exists := backend.entries[reference.EntryID]
	if !exists {
		return Record{}, ErrNotFound
	}
	filename := reference.EntryID + ".secret"
	value, err := readProtectedFile(ctx, backend.root, filename)
	if err != nil {
		return Record{}, err
	}
	fingerprint := sha256.Sum256(value)
	if subtle.ConstantTimeCompare(fingerprint[:], entry.fingerprint[:]) != 1 {
		zero(value)
		return Record{}, errors.New("protected secret file fingerprint changed")
	}
	result := cloneRecord(entry.record)
	result.Value = value
	return result, nil
}

func readProtectedFile(ctx context.Context, root *os.Root, filename string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	before, err := root.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil || !secureSecretFile(before) {
		return nil, errors.New("protected secret file is invalid")
	}
	file, err := root.Open(filename)
	if err != nil {
		return nil, errors.New("protected secret file cannot be opened")
	}
	opened, statErr := file.Stat()
	value, readErr := io.ReadAll(io.LimitReader(file, maximumSecretBytes+1))
	closeErr := file.Close()
	after, finalErr := root.Lstat(filename)
	if statErr != nil || readErr != nil || closeErr != nil || finalErr != nil ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) ||
		before.Mode() != opened.Mode() || opened.Mode() != after.Mode() ||
		before.Size() != opened.Size() || opened.Size() != after.Size() ||
		!before.ModTime().Equal(opened.ModTime()) || !opened.ModTime().Equal(after.ModTime()) ||
		!secureSecretFile(after) || len(value) == 0 || len(value) > maximumSecretBytes || int64(len(value)) != after.Size() {
		zero(value)
		return nil, errors.New("protected secret file changed or is invalid")
	}
	if err := ctx.Err(); err != nil {
		zero(value)
		return nil, err
	}
	return value, nil
}

func (backend *ProtectedFileBackend) Close() error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.root == nil {
		return nil
	}
	err := backend.root.Close()
	backend.root = nil
	return err
}

func secureDirectory(info os.FileInfo) bool {
	permissions := info.Mode().Perm()
	return info.IsDir() && info.Mode()&os.ModeSymlink == 0 && permissions&0o500 == 0o500 && permissions&0o077 == 0
}

func secureSecretFile(info os.FileInfo) bool {
	permissions := info.Mode().Perm()
	return info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 &&
		permissions&0o400 != 0 && permissions&0o177 == 0 && info.Size() > 0 && info.Size() <= maximumSecretBytes
}

func cloneRecord(record Record) Record {
	cloned := record
	cloned.CaseIDs = append([]string(nil), record.CaseIDs...)
	cloned.Value = append([]byte(nil), record.Value...)
	return cloned
}

var _ Backend = (*ProtectedFileBackend)(nil)
