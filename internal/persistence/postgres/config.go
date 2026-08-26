// Package postgres implements the server PostgreSQL storage driver.
package postgres

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	defaultMaxConnections = int32(8)
	maximumConnections    = int32(128)
)

// BackupVerifier binds a migration to an externally created, immutable backup.
// Implementations belong to the deployment's artifact catalog; the store never
// accepts commands or launches backup tools.
type BackupVerifier interface {
	VerifyBackup(context.Context, string) error
}

type Config struct {
	URL                    string
	MaxConnections         int32
	MinConnections         int32
	MaxConnectionLifetime  time.Duration
	AllowInsecureLocalhost bool
	BootstrapBackupDigest  string
	BackupVerifier         BackupVerifier
	Clock                  func() time.Time
}

type Store struct {
	pool       *pgxpool.Pool
	clock      func() time.Time
	backups    BackupVerifier
	migrations map[migrationKey]migration
	closeOnce  sync.Once
	closed     atomic.Bool
}

func Open(ctx context.Context, config Config) (*Store, error) {
	if err := contextError(ctx, "open"); err != nil {
		return nil, err
	}
	if config.URL == "" || config.BackupVerifier == nil || config.BootstrapBackupDigest == "" {
		return nil, storageError(workflow.StorageInvalidInput, "open", "config", "URL, backup verifier, and bootstrap backup digest are required")
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = defaultMaxConnections
	}
	if config.MaxConnections < 1 || config.MaxConnections > maximumConnections || config.MinConnections < 0 || config.MinConnections > config.MaxConnections {
		return nil, storageError(workflow.StorageInvalidInput, "open", "connections", "connection bounds are invalid")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	poolConfig, err := pgxpool.ParseConfig(config.URL)
	if err != nil {
		return nil, storageError(workflow.StorageInvalidInput, "open", "url", "PostgreSQL URL is invalid")
	}
	if poolConfig.ConnConfig.TLSConfig == nil && (!config.AllowInsecureLocalhost || !loopbackHost(poolConfig.ConnConfig.Host)) {
		return nil, storageError(workflow.StorageDenied, "open", "tls", "TLS is required except for an explicitly enabled loopback test server")
	}
	poolConfig.MaxConns = config.MaxConnections
	poolConfig.MinConns = config.MinConnections
	if config.MaxConnectionLifetime > 0 {
		poolConfig.MaxConnLifetime = config.MaxConnectionLifetime
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, normalizeError("open", "pool", err)
	}
	store := &Store{pool: pool, clock: config.Clock, backups: config.BackupVerifier, migrations: builtInMigrations()}
	if err := store.configure(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := store.bootstrap(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := store.ensureMetadataSchema(ctx, config.BootstrapBackupDigest); err != nil {
		pool.Close()
		return nil, err
	}
	if err := store.ensureAuditSchema(ctx, config.BootstrapBackupDigest); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) Close() {
	store.closeOnce.Do(func() {
		store.closed.Store(true)
		store.pool.Close()
	})
}

func (store *Store) configure(ctx context.Context) error {
	if err := store.pool.Ping(ctx); err != nil {
		return normalizeError("open", "ping", err)
	}
	var superuser, bypassRLS bool
	if err := store.pool.QueryRow(ctx, `SELECT rolsuper, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user`).Scan(&superuser, &bypassRLS); err != nil {
		return normalizeError("open", "role", err)
	}
	if superuser || bypassRLS {
		return storageError(workflow.StorageDenied, "open", "role", "runtime role must not be superuser or bypass row security")
	}
	return nil
}

func (store *Store) ready(ctx context.Context, operation string) error {
	if err := contextError(ctx, operation); err != nil {
		return err
	}
	if store.pool == nil || store.closed.Load() {
		return storageError(workflow.StorageUnavailable, operation, "database", "store is unavailable")
	}
	return nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

var _ workflow.StorageDriver = (*Store)(nil)
