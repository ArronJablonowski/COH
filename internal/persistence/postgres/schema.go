package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/ArronJablonowski/COH/internal/workflow"
)

const controlSchema = `
CREATE TABLE IF NOT EXISTS public.coh_migration_state (
  component TEXT PRIMARY KEY,
  version BIGINT NOT NULL CHECK (version > 0),
  checksum TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('in_progress','applied','rolled_back')),
  backup_digest TEXT NOT NULL,
  resume_digest TEXT NOT NULL
);`

var metadataUp = []string{
	`CREATE TABLE public.coh_records (
  organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL, case_id TEXT NOT NULL,
  kind TEXT NOT NULL, record_id TEXT NOT NULL, schema_id TEXT NOT NULL,
  revision BIGINT NOT NULL CHECK (revision > 0), canonical BYTEA NOT NULL, digest TEXT NOT NULL,
  PRIMARY KEY (organization_id, tenant_id, case_id, kind, record_id)
)`,
	`CREATE TABLE public.coh_idempotency (
  organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL, commit_sequence BIGINT NOT NULL CHECK (commit_sequence > 0), result_json BYTEA NOT NULL,
  PRIMARY KEY (organization_id, tenant_id, idempotency_key)
)`,
	`CREATE TABLE public.coh_outbox (
  organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL, message_id TEXT NOT NULL,
  case_id TEXT NOT NULL, topic TEXT NOT NULL, payload_ref TEXT NOT NULL, payload_digest TEXT NOT NULL,
  lease_id TEXT NOT NULL DEFAULT '', lease_worker TEXT NOT NULL DEFAULT '', lease_until TIMESTAMPTZ,
  settlement_outcome TEXT NOT NULL DEFAULT '' CHECK (settlement_outcome IN ('','retry','delivered','dead_letter')),
  evidence_digest TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (organization_id, tenant_id, message_id)
)`,
	`CREATE INDEX coh_outbox_claim ON public.coh_outbox
  (organization_id, tenant_id, settlement_outcome, lease_until, message_id)`,
	`CREATE TABLE public.coh_store_sequence (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton), commit_sequence BIGINT NOT NULL CHECK (commit_sequence >= 0)
)`,
	`INSERT INTO public.coh_store_sequence(singleton, commit_sequence) VALUES (TRUE, 0)`,
	`ALTER TABLE public.coh_records ENABLE ROW LEVEL SECURITY`,
	`ALTER TABLE public.coh_records FORCE ROW LEVEL SECURITY`,
	`CREATE POLICY coh_records_tenant ON public.coh_records USING (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND
  tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
) WITH CHECK (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND
  tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
)`,
	`ALTER TABLE public.coh_idempotency ENABLE ROW LEVEL SECURITY`,
	`ALTER TABLE public.coh_idempotency FORCE ROW LEVEL SECURITY`,
	`CREATE POLICY coh_idempotency_tenant ON public.coh_idempotency USING (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND
  tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
) WITH CHECK (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND
  tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
)`,
	`ALTER TABLE public.coh_outbox ENABLE ROW LEVEL SECURITY`,
	`ALTER TABLE public.coh_outbox FORCE ROW LEVEL SECURITY`,
	`CREATE POLICY coh_outbox_tenant ON public.coh_outbox USING (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND
  tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
) WITH CHECK (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND
  tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
)`,
}

var metadataDown = []string{
	"DROP TABLE public.coh_store_sequence",
	"DROP TABLE public.coh_outbox",
	"DROP TABLE public.coh_idempotency",
	"DROP TABLE public.coh_records",
}

var auditUp = []string{
	`CREATE TABLE public.coh_audit_heads (
  organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL,
  sequence BIGINT NOT NULL CHECK (sequence >= 0), chain_hash TEXT NOT NULL,
  last_record_at TEXT NOT NULL, last_checkpoint_sequence BIGINT NOT NULL CHECK (last_checkpoint_sequence >= 0),
  last_checkpoint_at TEXT NOT NULL, PRIMARY KEY (organization_id, tenant_id)
)`,
	`CREATE TABLE public.coh_audit_records (
  organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL, sequence BIGINT NOT NULL CHECK (sequence > 0),
  event_id TEXT NOT NULL, event_digest TEXT NOT NULL, previous_chain_hash TEXT NOT NULL, chain_hash TEXT NOT NULL,
  appended_at TEXT NOT NULL, canonical BYTEA NOT NULL,
  PRIMARY KEY (organization_id, tenant_id, sequence), UNIQUE (organization_id, tenant_id, event_id)
)`,
	`CREATE TABLE public.coh_audit_checkpoints (
  organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL, sequence BIGINT NOT NULL CHECK (sequence > 0),
  checkpoint_id TEXT NOT NULL, chain_hash TEXT NOT NULL, created_at TEXT NOT NULL, canonical BYTEA NOT NULL,
  PRIMARY KEY (organization_id, tenant_id, sequence), UNIQUE (organization_id, tenant_id, checkpoint_id)
)`,
	`CREATE TABLE public.coh_audit_idempotency (
  organization_id TEXT NOT NULL, tenant_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL, sequence BIGINT NOT NULL CHECK (sequence > 0), chain_hash TEXT NOT NULL,
  checkpoint_id TEXT NOT NULL, PRIMARY KEY (organization_id, tenant_id, idempotency_key)
)`,
	`ALTER TABLE public.coh_audit_heads ENABLE ROW LEVEL SECURITY`,
	`ALTER TABLE public.coh_audit_heads FORCE ROW LEVEL SECURITY`,
	`CREATE POLICY coh_audit_heads_tenant ON public.coh_audit_heads USING (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
) WITH CHECK (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
)`,
	`ALTER TABLE public.coh_audit_records ENABLE ROW LEVEL SECURITY`,
	`ALTER TABLE public.coh_audit_records FORCE ROW LEVEL SECURITY`,
	`CREATE POLICY coh_audit_records_select ON public.coh_audit_records FOR SELECT USING (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
)`,
	`CREATE POLICY coh_audit_records_insert ON public.coh_audit_records FOR INSERT WITH CHECK (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
)`,
	`ALTER TABLE public.coh_audit_checkpoints ENABLE ROW LEVEL SECURITY`,
	`ALTER TABLE public.coh_audit_checkpoints FORCE ROW LEVEL SECURITY`,
	`CREATE POLICY coh_audit_checkpoints_select ON public.coh_audit_checkpoints FOR SELECT USING (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
)`,
	`CREATE POLICY coh_audit_checkpoints_insert ON public.coh_audit_checkpoints FOR INSERT WITH CHECK (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
)`,
	`ALTER TABLE public.coh_audit_idempotency ENABLE ROW LEVEL SECURITY`,
	`ALTER TABLE public.coh_audit_idempotency FORCE ROW LEVEL SECURITY`,
	`CREATE POLICY coh_audit_idempotency_select ON public.coh_audit_idempotency FOR SELECT USING (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
)`,
	`CREATE POLICY coh_audit_idempotency_insert ON public.coh_audit_idempotency FOR INSERT WITH CHECK (
  organization_id = COALESCE(pg_catalog.current_setting('coh.organization_id', true), '') AND tenant_id = COALESCE(pg_catalog.current_setting('coh.tenant_id', true), '')
)`,
}

var auditDown = []string{
	"DROP TABLE public.coh_audit_idempotency",
	"DROP TABLE public.coh_audit_checkpoints",
	"DROP TABLE public.coh_audit_records",
	"DROP TABLE public.coh_audit_heads",
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
	if _, err := store.pool.Exec(ctx, controlSchema); err != nil {
		return normalizeError("bootstrap", "control_schema", err)
	}
	return nil
}

func (store *Store) ensureMetadataSchema(ctx context.Context, backupDigest string) error {
	status, err := store.MigrationStatus(ctx, "metadata")
	if err != nil {
		return err
	}
	if status.State == workflow.MigrationApplied {
		return nil
	}
	spec := store.migrations[migrationKey{component: "metadata", version: 1}]
	_, err = store.Migrate(ctx, workflow.MigrationPlan{
		ContractVersion: workflow.StorageContractVersion, Component: spec.component,
		Version: spec.version, Checksum: spec.checksum, BackupDigest: backupDigest,
		Direction: workflow.MigrationApply,
	})
	return err
}

func (store *Store) ensureAuditSchema(ctx context.Context, backupDigest string) error {
	status, err := store.MigrationStatus(ctx, "audit")
	if err != nil || status.State == workflow.MigrationApplied {
		return err
	}
	spec := store.migrations[migrationKey{component: "audit", version: 1}]
	_, err = store.Migrate(ctx, workflow.MigrationPlan{ContractVersion: workflow.StorageContractVersion,
		Component: spec.component, Version: spec.version, Checksum: spec.checksum,
		BackupDigest: backupDigest, Direction: workflow.MigrationApply})
	return err
}
