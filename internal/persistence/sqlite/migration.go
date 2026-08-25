package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"strings"

	"github.com/ArronJablonowski/COH/internal/workflow"
)

func (store *Store) MigrationStatus(ctx context.Context, component string) (workflow.MigrationResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "migration_status"); err != nil {
		return workflow.MigrationResult{}, err
	}
	return store.migrationStatus(ctx, component)
}

func (store *Store) migrationStatus(ctx context.Context, component string) (workflow.MigrationResult, error) {
	var result workflow.MigrationResult
	result.Component = component
	var version int64
	err := store.db.QueryRowContext(ctx,
		"SELECT version, checksum, state, resume_digest FROM coh_migration_state WHERE component = ?", component,
	).Scan(&version, &result.Checksum, &result.State, &result.ResumeDigest)
	if err == sql.ErrNoRows {
		result.State = workflow.MigrationPending
		return result, nil
	}
	if err != nil {
		return workflow.MigrationResult{}, normalizeError("migration_status", "state", err)
	}
	if version < 0 {
		return workflow.MigrationResult{}, storageError(workflow.StorageDenied, "migration_status", "version", "stored migration state is invalid")
	}
	result.Version = uint64(version)
	return result, nil
}

func (store *Store) Migrate(ctx context.Context, plan workflow.MigrationPlan) (workflow.MigrationResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "migrate"); err != nil {
		return workflow.MigrationResult{}, err
	}
	return store.migrate(ctx, plan)
}

func (store *Store) migrate(ctx context.Context, plan workflow.MigrationPlan) (workflow.MigrationResult, error) {
	spec, ok := store.migrations[migrationKey{component: plan.Component, version: plan.Version}]
	if !ok || spec.checksum != plan.Checksum {
		return workflow.MigrationResult{}, storageError(workflow.StorageDenied, "migrate", "plan", "migration is not registered by this adapter")
	}
	if err := store.verifyBackup(ctx, plan.BackupDigest); err != nil {
		return workflow.MigrationResult{}, err
	}
	current, err := store.migrationStatus(ctx, plan.Component)
	if err != nil {
		return workflow.MigrationResult{}, err
	}
	wantState := workflow.MigrationApplied
	statements := spec.up
	if plan.Direction == workflow.MigrationRollback {
		wantState = workflow.MigrationRolledBack
		statements = spec.down
	}
	if current.Version == plan.Version && current.Checksum == plan.Checksum && current.State == wantState {
		current.Replayed = true
		return current, nil
	}
	if current.Version != 0 && (current.Version != plan.Version || current.Checksum != plan.Checksum) {
		return workflow.MigrationResult{}, storageError(workflow.StorageDenied, "migrate", "state", "stored migration identity differs from plan")
	}
	if plan.Direction == workflow.MigrationRollback && current.State != workflow.MigrationApplied {
		return workflow.MigrationResult{}, storageError(workflow.StorageConflict, "migrate", "state", "only an applied migration can be rolled back")
	}
	if plan.Direction == workflow.MigrationApply && current.State == workflow.MigrationApplied {
		return workflow.MigrationResult{}, storageError(workflow.StorageConflict, "migrate", "state", "migration state conflicts with apply")
	}
	if plan.Direction == workflow.MigrationRollback && plan.Component == "metadata" {
		if err := store.requireEmptyMetadata(ctx); err != nil {
			return workflow.MigrationResult{}, err
		}
	}

	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return workflow.MigrationResult{}, normalizeError("migrate", "transaction", err)
	}
	defer transaction.Rollback()
	resume := migrationResumeDigest(plan, workflow.MigrationInProgress)
	if _, err := transaction.ExecContext(ctx, `INSERT INTO coh_migration_state
(component, version, checksum, state, backup_digest, resume_digest) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(component) DO UPDATE SET version=excluded.version, checksum=excluded.checksum,
state=excluded.state, backup_digest=excluded.backup_digest, resume_digest=excluded.resume_digest`,
		plan.Component, plan.Version, plan.Checksum, workflow.MigrationInProgress, plan.BackupDigest, resume); err != nil {
		return workflow.MigrationResult{}, normalizeError("migrate", "state", err)
	}
	for _, statement := range statements {
		if _, err := transaction.ExecContext(ctx, statement); err != nil {
			return workflow.MigrationResult{}, normalizeError("migrate", "registered_statement", err)
		}
	}
	resume = migrationResumeDigest(plan, wantState)
	if _, err := transaction.ExecContext(ctx,
		"UPDATE coh_migration_state SET state = ?, resume_digest = ? WHERE component = ?",
		wantState, resume, plan.Component); err != nil {
		return workflow.MigrationResult{}, normalizeError("migrate", "state", err)
	}
	if err := transaction.Commit(); err != nil {
		return workflow.MigrationResult{}, normalizeError("migrate", "commit", err)
	}
	return workflow.MigrationResult{Component: plan.Component, Version: plan.Version, Checksum: plan.Checksum, State: wantState, ResumeDigest: resume}, nil
}

func (store *Store) verifyBackup(ctx context.Context, digest string) error {
	var path string
	var length int64
	if err := store.db.QueryRowContext(ctx, "SELECT path, length FROM coh_backups WHERE digest = ?", digest).Scan(&path, &length); err != nil {
		if err == sql.ErrNoRows {
			return storageError(workflow.StorageDenied, "migrate", "backup_digest", "backup is not registered")
		}
		return normalizeError("migrate", "backup_digest", err)
	}
	artifact, err := inspectBackup(path, store.clock().UTC())
	if err != nil || artifact.Digest != digest || artifact.Length != length {
		return storageError(workflow.StorageDenied, "migrate", "backup_digest", "registered backup failed verification")
	}
	return nil
}

func (store *Store) requireEmptyMetadata(ctx context.Context) error {
	for _, table := range []string{"coh_records", "coh_idempotency", "coh_outbox"} {
		var count int64
		if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil {
			return normalizeError("migrate", "rollback", err)
		}
		if count != 0 {
			return storageError(workflow.StorageConflict, "migrate", "rollback", "metadata must be empty before rollback")
		}
	}
	return nil
}

func migrationResumeDigest(plan workflow.MigrationPlan, state workflow.MigrationState) string {
	material := strings.Join([]string{plan.Component, plan.Checksum, plan.BackupDigest, string(plan.Direction), string(state)}, "\n")
	sum := sha256.Sum256([]byte(material))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (store *Store) registerMigration(spec migration) {
	store.migrations[migrationKey{component: spec.component, version: spec.version}] = spec
}

func (store *Store) registerBackupForTest(ctx context.Context, path, digest string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	_, err = store.db.ExecContext(ctx, "INSERT INTO coh_backups(digest, path, length, created_at) VALUES (?, ?, ?, ?)", digest, path, info.Size(), formatTime(store.clock().UTC()))
	return err
}
