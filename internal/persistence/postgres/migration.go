package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/jackc/pgx/v5"
)

func (store *Store) MigrationStatus(ctx context.Context, component string) (workflow.MigrationResult, error) {
	if err := store.ready(ctx, "migration_status"); err != nil {
		return workflow.MigrationResult{}, err
	}
	return migrationStatus(ctx, store.pool, component)
}

type rowQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func migrationStatus(ctx context.Context, query rowQuerier, component string) (workflow.MigrationResult, error) {
	result := workflow.MigrationResult{Component: component}
	var version int64
	err := query.QueryRow(ctx, `SELECT version, checksum, state, resume_digest
FROM public.coh_migration_state WHERE component = $1`, component).Scan(&version, &result.Checksum, &result.State, &result.ResumeDigest)
	if err == pgx.ErrNoRows {
		result.State = workflow.MigrationPending
		return result, nil
	}
	if err != nil {
		return workflow.MigrationResult{}, normalizeError("migration_status", "state", err)
	}
	if version <= 0 {
		return workflow.MigrationResult{}, storageError(workflow.StorageDenied, "migration_status", "version", "stored migration state is invalid")
	}
	result.Version = uint64(version)
	return result, nil
}

func (store *Store) Migrate(ctx context.Context, plan workflow.MigrationPlan) (workflow.MigrationResult, error) {
	if err := store.ready(ctx, "migrate"); err != nil {
		return workflow.MigrationResult{}, err
	}
	if err := workflow.ValidateMigrationPlan(plan); err != nil {
		return workflow.MigrationResult{}, err
	}
	spec, ok := store.migrations[migrationKey{component: plan.Component, version: plan.Version}]
	if !ok || spec.checksum != plan.Checksum {
		return workflow.MigrationResult{}, storageError(workflow.StorageDenied, "migrate", "plan", "migration is not registered by this adapter")
	}
	if err := store.backups.VerifyBackup(ctx, plan.BackupDigest); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return workflow.MigrationResult{}, normalizeError("migrate", "backup_digest", contextErr)
		}
		return workflow.MigrationResult{}, storageError(workflow.StorageDenied, "migrate", "backup_digest", "backup verification failed")
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return workflow.MigrationResult{}, normalizeError("migrate", "transaction", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('coh:migration:' || $1))`, plan.Component); err != nil {
		return workflow.MigrationResult{}, normalizeError("migrate", "lock", err)
	}
	current, err := migrationStatus(ctx, tx, plan.Component)
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
	if len(statements) == 0 {
		return workflow.MigrationResult{}, storageError(workflow.StorageDenied, "migrate", "direction", "registered migration has no safe statements for this direction")
	}
	if plan.Direction == workflow.MigrationRollback && plan.Component == "metadata" {
		var sequence int64
		if err := tx.QueryRow(ctx, `SELECT commit_sequence FROM public.coh_store_sequence WHERE singleton=TRUE`).Scan(&sequence); err != nil {
			return workflow.MigrationResult{}, normalizeError("migrate", "rollback", err)
		}
		if sequence != 0 {
			return workflow.MigrationResult{}, storageError(workflow.StorageConflict, "migrate", "rollback", "metadata history must be empty before rollback")
		}
	}
	resume := migrationResumeDigest(plan, workflow.MigrationInProgress)
	if _, err := tx.Exec(ctx, `INSERT INTO public.coh_migration_state
(component, version, checksum, state, backup_digest, resume_digest) VALUES ($1,$2,$3,$4,$5,$6)
ON CONFLICT(component) DO UPDATE SET version=excluded.version, checksum=excluded.checksum,
state=excluded.state, backup_digest=excluded.backup_digest, resume_digest=excluded.resume_digest`,
		plan.Component, plan.Version, plan.Checksum, workflow.MigrationInProgress, plan.BackupDigest, resume); err != nil {
		return workflow.MigrationResult{}, normalizeError("migrate", "state", err)
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			return workflow.MigrationResult{}, normalizeError("migrate", "registered_statement", err)
		}
	}
	resume = migrationResumeDigest(plan, wantState)
	if _, err := tx.Exec(ctx, `UPDATE public.coh_migration_state SET state=$1, resume_digest=$2 WHERE component=$3`, wantState, resume, plan.Component); err != nil {
		return workflow.MigrationResult{}, normalizeError("migrate", "state", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return workflow.MigrationResult{}, normalizeError("migrate", "commit", err)
	}
	return workflow.MigrationResult{Component: plan.Component, Version: plan.Version, Checksum: plan.Checksum, State: wantState, ResumeDigest: resume}, nil
}

func migrationResumeDigest(plan workflow.MigrationPlan, state workflow.MigrationState) string {
	material := strings.Join([]string{plan.Component, plan.Checksum, plan.BackupDigest, string(plan.Direction), string(state)}, "\n")
	sum := sha256.Sum256([]byte(material))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (store *Store) registerMigration(spec migration) {
	store.migrations[migrationKey{component: spec.component, version: spec.version}] = spec
}
