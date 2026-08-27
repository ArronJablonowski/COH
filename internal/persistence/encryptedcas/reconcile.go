package encryptedcas

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

func (store *Store) Staged(ctx context.Context, before time.Time,
	limit uint16) ([]evidenceingest.StagedCandidate, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if store == nil || store.ensureRoot() != nil || before.IsZero() || before.Location() != time.UTC ||
		limit == 0 || limit > 256 {
		return nil, newError(InvalidInput, "staged_reconciliation_invalid", nil)
	}
	directory := filepath.Join(store.root, "staging")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, newError(Unavailable, "staging_scan_failed", err)
	}
	result := make([]evidenceingest.StagedCandidate, 0, limit)
	for _, entry := range entries {
		if err = contextError(ctx); err != nil {
			return nil, err
		}
		name := entry.Name()
		if entry.IsDir() || !validStageFilename(name) {
			return nil, newError(Denied, "staging_entry_invalid", nil)
		}
		path := filepath.Join(directory, name)
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
			info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > 2<<30 {
			return nil, newError(Denied, "staging_entry_invalid", statErr)
		}
		modified := info.ModTime().UTC()
		if !modified.Before(before) {
			continue
		}
		result = append(result, evidenceingest.StagedCandidate{LocatorDigest: "sha256:" + name[:64],
			CiphertextLength: info.Size(), ModifiedAt: modified})
		if len(result) == int(limit) {
			break
		}
	}
	return result, nil
}

func validStageFilename(value string) bool {
	if len(value) != 70 || !strings.HasSuffix(value, ".stage") {
		return false
	}
	decoded, err := hex.DecodeString(value[:64])
	return err == nil && len(decoded) == 32
}
