package sqlite

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// BackupArtifact describes a consistent SQLite snapshot held outside the live
// database directory.
type BackupArtifact struct {
	Path      string
	Digest    string
	Length    int64
	CreatedAt time.Time
}

func (store *Store) Backup(ctx context.Context) (BackupArtifact, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "backup"); err != nil {
		return BackupArtifact{}, err
	}
	return store.backup(ctx, store.nextBackupPath("manual"))
}

func (store *Store) nextBackupPath(label string) string {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		random = []byte(fmt.Sprintf("%016x", store.clock().UnixNano()))
	}
	name := fmt.Sprintf("coh-%s-%d-%s.sqlite3", label, store.clock().UTC().UnixNano(), hex.EncodeToString(random))
	return filepath.Join(store.backupDir, name)
}

func (store *Store) backup(ctx context.Context, destination string) (BackupArtifact, error) {
	resolved, err := resolveFilePath(destination, false)
	if err != nil || filepath.Dir(resolved) != store.backupDir {
		return BackupArtifact{}, storageError("invalid_input", "backup", "path", "backup must be a new file in the configured directory")
	}
	if _, err := os.Lstat(resolved); !os.IsNotExist(err) {
		return BackupArtifact{}, storageError("conflict", "backup", "path", "backup path already exists")
	}
	if _, err := store.db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)"); err != nil {
		return BackupArtifact{}, normalizeError("backup", "checkpoint", err)
	}
	var quoted string
	if err := store.db.QueryRowContext(ctx, "SELECT quote(?)", resolved).Scan(&quoted); err != nil {
		return BackupArtifact{}, normalizeError("backup", "path", err)
	}
	if _, err := store.db.ExecContext(ctx, "VACUUM INTO "+quoted); err != nil {
		return BackupArtifact{}, normalizeError("backup", "snapshot", err)
	}
	artifact, err := inspectBackup(resolved, store.clock().UTC())
	if err != nil {
		return BackupArtifact{}, err
	}
	if _, err := store.db.ExecContext(ctx,
		"INSERT INTO coh_backups(digest, path, length, created_at) VALUES (?, ?, ?, ?)",
		artifact.Digest, artifact.Path, artifact.Length, formatTime(artifact.CreatedAt)); err != nil {
		return BackupArtifact{}, normalizeError("backup", "registry", err)
	}
	return artifact, nil
}

func inspectBackup(path string, createdAt time.Time) (BackupArtifact, error) {
	file, err := os.Open(path)
	if err != nil {
		return BackupArtifact{}, normalizeError("backup", "snapshot", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return BackupArtifact{}, storageError("unavailable", "backup", "snapshot", "backup artifact is invalid")
	}
	hash := sha256.New()
	length, err := io.Copy(hash, file)
	if err != nil || length != info.Size() {
		return BackupArtifact{}, normalizeError("backup", "digest", err)
	}
	return BackupArtifact{Path: path, Digest: "sha256:" + hex.EncodeToString(hash.Sum(nil)), Length: length, CreatedAt: createdAt}, nil
}
