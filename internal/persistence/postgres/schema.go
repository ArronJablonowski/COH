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
	return map[migrationKey]migration{{component: metadata.component, version: metadata.version}: metadata}
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
