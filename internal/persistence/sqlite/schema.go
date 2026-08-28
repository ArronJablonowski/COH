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

var profileActivationUp = []string{
	`CREATE TABLE coh_profile_activation_transitions (
  transition_id TEXT PRIMARY KEY,
  profile_id TEXT NOT NULL,
  deployment_kind TEXT NOT NULL,
  connectivity_mode TEXT NOT NULL,
  platform TEXT NOT NULL,
  surface TEXT NOT NULL,
  phase TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  intent_digest TEXT NOT NULL,
  transition_digest TEXT NOT NULL,
  canonical BLOB NOT NULL
) STRICT`,
	`CREATE INDEX coh_profile_activation_transition_target ON coh_profile_activation_transitions
  (profile_id, deployment_kind, connectivity_mode, platform, surface, phase)`,
	`CREATE TABLE coh_active_profiles (
  profile_id TEXT NOT NULL,
  deployment_kind TEXT NOT NULL,
  connectivity_mode TEXT NOT NULL,
  platform TEXT NOT NULL,
  surface TEXT NOT NULL,
  profile_revision INTEGER NOT NULL CHECK (profile_revision > 0),
  composition_digest TEXT NOT NULL,
  transition_id TEXT NOT NULL,
  active_digest TEXT NOT NULL,
  canonical BLOB NOT NULL,
  PRIMARY KEY (profile_id, deployment_kind, connectivity_mode, platform, surface),
  FOREIGN KEY (transition_id) REFERENCES coh_profile_activation_transitions(transition_id)
) STRICT`,
}

var profileActivationDown = []string{
	"DROP TABLE coh_active_profiles",
	"DROP INDEX coh_profile_activation_transition_target",
	"DROP TABLE coh_profile_activation_transitions",
}

var extensionLifecycleUp = []string{
	`CREATE TABLE coh_extension_manifests (
  manifest_digest TEXT PRIMARY KEY,
  extension_id TEXT NOT NULL,
  canonical BLOB NOT NULL
) STRICT`,
	`CREATE TABLE coh_extension_lifecycle_transitions (
  transition_id TEXT PRIMARY KEY,
  extension_id TEXT NOT NULL,
  organization_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  direction TEXT NOT NULL,
  phase TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  intent_digest TEXT NOT NULL,
  transition_digest TEXT NOT NULL,
  canonical BLOB NOT NULL
) STRICT`,
	`CREATE INDEX coh_extension_lifecycle_scope ON coh_extension_lifecycle_transitions
  (extension_id, organization_id, tenant_id, phase)`,
	`CREATE TABLE coh_extension_registration_receipts (
  receipt_digest TEXT PRIMARY KEY,
  receipt_id TEXT NOT NULL UNIQUE,
  extension_id TEXT NOT NULL,
  organization_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  registration_ordinal INTEGER NOT NULL CHECK (registration_ordinal >= 0),
  state TEXT NOT NULL,
  handle_digest TEXT NOT NULL,
  canonical BLOB NOT NULL
) STRICT`,
	`CREATE TABLE coh_active_extensions (
  extension_id TEXT NOT NULL,
  organization_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  manifest_digest TEXT NOT NULL,
  lifecycle_revision INTEGER NOT NULL CHECK (lifecycle_revision > 0),
  transition_id TEXT NOT NULL,
  active_digest TEXT NOT NULL,
  canonical BLOB NOT NULL,
  PRIMARY KEY (extension_id, organization_id, tenant_id),
  FOREIGN KEY (transition_id) REFERENCES coh_extension_lifecycle_transitions(transition_id),
  FOREIGN KEY (manifest_digest) REFERENCES coh_extension_manifests(manifest_digest)
) STRICT`,
}

var extensionLifecycleDown = []string{
	"DROP TABLE coh_active_extensions",
	"DROP TABLE coh_extension_registration_receipts",
	"DROP INDEX coh_extension_lifecycle_scope",
	"DROP TABLE coh_extension_lifecycle_transitions",
	"DROP TABLE coh_extension_manifests",
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
	profileActivation := migration{component: "profile_activation", version: 1,
		up: profileActivationUp, down: profileActivationDown}
	profileActivation.checksum = migrationChecksum(profileActivation)
	extensionLifecycle := migration{component: "extension_lifecycle", version: 1,
		up: extensionLifecycleUp, down: extensionLifecycleDown}
	extensionLifecycle.checksum = migrationChecksum(extensionLifecycle)
	return map[migrationKey]migration{
		{component: metadata.component, version: metadata.version}:                     metadata,
		{component: audit.component, version: audit.version}:                           audit,
		{component: profileActivation.component, version: profileActivation.version}:   profileActivation,
		{component: extensionLifecycle.component, version: extensionLifecycle.version}: extensionLifecycle,
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

func (store *Store) ensureProfileActivationSchema(ctx context.Context) error {
	result, err := store.migrationStatus(ctx, "profile_activation")
	if err != nil || result.State == workflow.MigrationApplied {
		return err
	}
	backup, err := store.backup(ctx, store.nextBackupPath("profile-activation-v1"))
	if err != nil {
		return err
	}
	spec := store.migrations[migrationKey{component: "profile_activation", version: 1}]
	_, err = store.migrate(ctx, workflow.MigrationPlan{ContractVersion: workflow.StorageContractVersion,
		Component: spec.component, Version: spec.version, Checksum: spec.checksum,
		BackupDigest: backup.Digest, Direction: workflow.MigrationApply})
	return err
}

func (store *Store) ensureExtensionLifecycleSchema(ctx context.Context) error {
	result, err := store.migrationStatus(ctx, "extension_lifecycle")
	if err != nil || result.State == workflow.MigrationApplied {
		return err
	}
	backup, err := store.backup(ctx, store.nextBackupPath("extension-lifecycle-v1"))
	if err != nil {
		return err
	}
	spec := store.migrations[migrationKey{component: "extension_lifecycle", version: 1}]
	_, err = store.migrate(ctx, workflow.MigrationPlan{ContractVersion: workflow.StorageContractVersion,
		Component: spec.component, Version: spec.version, Checksum: spec.checksum,
		BackupDigest: backup.Digest, Direction: workflow.MigrationApply})
	return err
}
