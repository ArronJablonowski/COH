// Package sqlite implements the workstation storage driver.
package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow"
	modernsqlite "modernc.org/sqlite"
)

const defaultBusyTimeout = 5 * time.Second

type Config struct {
	Path            string
	BackupDirectory string
	BusyTimeout     time.Duration
	Clock           func() time.Time
}

type Store struct {
	mu         sync.Mutex
	db         *sql.DB
	path       string
	backupDir  string
	clock      func() time.Time
	migrations map[migrationKey]migration
}

func Open(ctx context.Context, config Config) (*Store, error) {
	if err := contextError(ctx, "open"); err != nil {
		return nil, err
	}
	path, err := resolveFilePath(config.Path, false)
	if err != nil {
		return nil, err
	}
	backupDir, err := resolveDirectory(config.BackupDirectory)
	if err != nil {
		return nil, err
	}
	if config.BusyTimeout == 0 {
		config.BusyTimeout = defaultBusyTimeout
	}
	if config.BusyTimeout < time.Millisecond || config.BusyTimeout > time.Minute {
		return nil, storageError(workflow.StorageInvalidInput, "open", "busy_timeout", "busy timeout is outside bounds")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}

	dsn := (&url.URL{Scheme: "file", Path: path}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, normalizeError("open", "database", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, path: path, backupDir: backupDir, clock: config.Clock, migrations: builtInMigrations()}
	if err := store.configure(ctx, config.BusyTimeout); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.bootstrap(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.ensureMetadataSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.ensureAuditSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.ensureProfileActivationSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if err := store.ensureExtensionLifecycleSchema(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.db == nil {
		return nil
	}
	err := store.db.Close()
	store.db = nil
	if err != nil {
		return normalizeError("close", "database", err)
	}
	return nil
}

func (store *Store) Path() string { return store.path }

func (store *Store) configure(ctx context.Context, busyTimeout time.Duration) error {
	statements := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=FULL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA trusted_schema=OFF",
		fmt.Sprintf("PRAGMA busy_timeout=%d", busyTimeout.Milliseconds()),
		"PRAGMA wal_autocheckpoint=1000",
	}
	for _, statement := range statements {
		if _, err := store.db.ExecContext(ctx, statement); err != nil {
			return normalizeError("open", "pragma", err)
		}
	}
	var journal string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil || journal != "wal" {
		return storageError(workflow.StorageDenied, "open", "journal_mode", "WAL mode was not established")
	}
	var synchronous int
	if err := store.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		return storageError(workflow.StorageDenied, "open", "synchronous", "FULL durability was not established")
	}
	return nil
}

func resolveFilePath(path string, mustExist bool) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", storageError(workflow.StorageInvalidInput, "open", "path", "absolute clean database path is required")
	}
	parent, err := resolveDirectory(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	resolved := filepath.Join(parent, filepath.Base(path))
	info, err := os.Lstat(resolved)
	if err == nil {
		if !info.Mode().IsRegular() {
			return "", storageError(workflow.StorageDenied, "open", "path", "database must be a regular non-symlink file")
		}
	} else if !os.IsNotExist(err) || mustExist {
		return "", storageError(workflow.StorageInvalidInput, "open", "path", "database path is unavailable")
	}
	return resolved, nil
}

func resolveDirectory(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", storageError(workflow.StorageInvalidInput, "open", "directory", "absolute clean directory is required")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", storageError(workflow.StorageInvalidInput, "open", "directory", "directory is unavailable")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", storageError(workflow.StorageInvalidInput, "open", "directory", "directory is unavailable")
	}
	return resolved, nil
}

var _ driver.Driver = (*modernsqlite.Driver)(nil)
var _ workflow.StorageDriver = (*Store)(nil)
