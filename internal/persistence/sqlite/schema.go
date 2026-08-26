package sqlite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/ArronJablonowski/COH/internal/workflow"
)

const controlSchema = `
CREATE TABLE IF NOT EXISTS coh_migration_state (
  component TEXT PRIMARY KEY,
  version INTEGER NOT NULL,
  checksum TEXT NOT NULL,
  state TEXT NOT NULL,
  backup_digest TEXT NOT NULL,
  resume_digest TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS coh_backups (
  digest TEXT PRIMARY KEY,
  path TEXT NOT NULL UNIQUE,
  length INTEGER NOT NULL CHECK (length >= 0),
  created_at TEXT NOT NULL
) STRICT;`

var metadataUp = []string{
	`CREATE TABLE coh_records (
  organization_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  record_id TEXT NOT NULL,
  schema_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision > 0),
  canonical BLOB NOT NULL,
  digest TEXT NOT NULL,
  PRIMARY KEY (organization_id, tenant_id, case_id, kind, record_id)
) STRICT`,
	`CREATE TABLE coh_idempotency (
  idempotency_key TEXT PRIMARY KEY,
  request_digest TEXT NOT NULL,
  commit_sequence INTEGER NOT NULL CHECK (commit_sequence > 0),
  result_json BLOB NOT NULL
) STRICT`,
	`CREATE TABLE coh_outbox (
  message_id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  topic TEXT NOT NULL,
  payload_ref TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  lease_id TEXT NOT NULL DEFAULT '',
  lease_until TEXT NOT NULL DEFAULT '',
  settlement_outcome TEXT NOT NULL DEFAULT '',
  evidence_digest TEXT NOT NULL DEFAULT ''
) STRICT`,
	`CREATE INDEX coh_outbox_claim ON coh_outbox
  (organization_id, tenant_id, settlement_outcome, lease_until, message_id)`,
	`CREATE TABLE coh_store_sequence (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  commit_sequence INTEGER NOT NULL CHECK (commit_sequence >= 0)
) STRICT`,
	`INSERT INTO coh_store_sequence(singleton, commit_sequence) VALUES (1, 0)`,
}

var metadataDown = []string{
	"DROP TABLE coh_store_sequence",
	"DROP INDEX coh_outbox_claim",
	"DROP TABLE coh_outbox",
	"DROP TABLE coh_idempotency",
	"DROP TABLE coh_records",
}

var auditUp = []string{
	`CREATE TABLE coh_audit_heads (
  organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK (sequence >= 0), chain_hash TEXT NOT NULL,
  last_record_at TEXT NOT NULL, last_checkpoint_sequence INTEGER NOT NULL CHECK (last_checkpoint_sequence >= 0),
  last_checkpoint_at TEXT NOT NULL, PRIMARY KEY (organization_id, tenant_id)
) STRICT`,
	`CREATE TABLE coh_audit_records (
  organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK (sequence > 0),
  event_id TEXT NOT NULL, event_digest TEXT NOT NULL, previous_chain_hash TEXT NOT NULL, chain_hash TEXT NOT NULL,
  appended_at TEXT NOT NULL, canonical BLOB NOT NULL,
  PRIMARY KEY (organization_id, tenant_id, sequence), UNIQUE (organization_id, tenant_id, event_id)
) STRICT`,
	`CREATE TABLE coh_audit_checkpoints (
  organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK (sequence > 0),
  checkpoint_id TEXT NOT NULL, chain_hash TEXT NOT NULL, created_at TEXT NOT NULL, canonical BLOB NOT NULL,
  PRIMARY KEY (organization_id, tenant_id, sequence), UNIQUE (organization_id, tenant_id, checkpoint_id)
) STRICT`,
	`CREATE TABLE coh_audit_idempotency (
  organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL, sequence INTEGER NOT NULL CHECK (sequence > 0), chain_hash TEXT NOT NULL,
  checkpoint_id TEXT NOT NULL, PRIMARY KEY (organization_id, tenant_id, idempotency_key)
) STRICT`,
	`CREATE TRIGGER coh_audit_records_no_update BEFORE UPDATE ON coh_audit_records BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END`,
	`CREATE TRIGGER coh_audit_records_no_delete BEFORE DELETE ON coh_audit_records BEGIN SELECT RAISE(ABORT, 'audit records are append-only'); END`,
	`CREATE TRIGGER coh_audit_checkpoints_no_update BEFORE UPDATE ON coh_audit_checkpoints BEGIN SELECT RAISE(ABORT, 'audit checkpoints are append-only'); END`,
	`CREATE TRIGGER coh_audit_checkpoints_no_delete BEFORE DELETE ON coh_audit_checkpoints BEGIN SELECT RAISE(ABORT, 'audit checkpoints are append-only'); END`,
}

var auditDown = []string{
	"DROP TRIGGER coh_audit_checkpoints_no_delete",
	"DROP TRIGGER coh_audit_checkpoints_no_update",
	"DROP TRIGGER coh_audit_records_no_delete",
	"DROP TRIGGER coh_audit_records_no_update",
	"DROP TABLE coh_audit_idempotency",
	"DROP TABLE coh_audit_checkpoints",
	"DROP TABLE coh_audit_records",
	"DROP TABLE coh_audit_heads",
}

type migration struct {
	component string
	version   uint64
	checksum  string
	up        []string
	down      []string
}

type migrationKey struct {
	component string
	version   uint64
}

func builtInMigrations() map[migrationKey]migration {
	metadata := migration{component: "metadata", version: 1, up: metadataUp, down: metadataDown}
	metadata.checksum = migrationChecksum(metadata)
	audit := migration{component: "audit", version: 1, up: auditUp, down: auditDown}
	audit.checksum = migrationChecksum(audit)
	return map[migrationKey]migration{
		{component: metadata.component, version: metadata.version}: metadata,
		{component: audit.component, version: audit.version}:       audit,
	}
}

func migrationChecksum(value migration) string {
	material := value.component + "\n" + strings.Join(value.up, "\n-- next --\n") + "\n-- down --\n" + strings.Join(value.down, "\n-- next --\n")
	sum := sha256.Sum256([]byte(material))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (store *Store) bootstrap(ctx context.Context) error {
	if _, err := store.db.ExecContext(ctx, controlSchema); err != nil {
		return normalizeError("bootstrap", "control_schema", err)
	}
	return nil
}

func (store *Store) ensureMetadataSchema(ctx context.Context) error {
	result, err := store.migrationStatus(ctx, "metadata")
	if err != nil {
		return err
	}
	if result.State == workflow.MigrationApplied {
		return nil
	}
	backup, err := store.backup(ctx, store.nextBackupPath("metadata-v1"))
	if err != nil {
		return err
	}
	spec := store.migrations[migrationKey{component: "metadata", version: 1}]
	_, err = store.migrate(ctx, workflow.MigrationPlan{
		ContractVersion: workflow.StorageContractVersion,
		Component:       spec.component, Version: spec.version, Checksum: spec.checksum,
		BackupDigest: backup.Digest, Direction: workflow.MigrationApply,
	})
	return err
}

func (store *Store) ensureAuditSchema(ctx context.Context) error {
	result, err := store.migrationStatus(ctx, "audit")
	if err != nil || result.State == workflow.MigrationApplied {
		return err
	}
	backup, err := store.backup(ctx, store.nextBackupPath("audit-v1"))
	if err != nil {
		return err
	}
	spec := store.migrations[migrationKey{component: "audit", version: 1}]
	_, err = store.migrate(ctx, workflow.MigrationPlan{ContractVersion: workflow.StorageContractVersion,
		Component: spec.component, Version: spec.version, Checksum: spec.checksum,
		BackupDigest: backup.Digest, Direction: workflow.MigrationApply})
	return err
}
