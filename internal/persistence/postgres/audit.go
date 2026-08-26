package postgres

import (
	"context"
	"errors"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/auditlog"
	"github.com/jackc/pgx/v5"
)

func (store *Store) LoadHead(ctx context.Context, organizationID, tenantID string) (tamperaudit.Head, error) {
	if err := store.ready(ctx, "load_audit_head"); err != nil {
		return tamperaudit.Head{}, err
	}
	tx, err := store.beginScoped(ctx, organizationID, tenantID)
	if err != nil {
		return tamperaudit.Head{}, normalizeError("load_audit_head", "transaction", err)
	}
	defer tx.Rollback(ctx)
	head, err := loadAuditHead(ctx, tx, organizationID, tenantID, false)
	if err != nil {
		return tamperaudit.Head{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return tamperaudit.Head{}, normalizeError("load_audit_head", "commit", err)
	}
	return head, nil
}

func loadAuditHead(ctx context.Context, query rowQuerier, organizationID, tenantID string, lock bool) (tamperaudit.Head, error) {
	statement := `SELECT organization_id,tenant_id,sequence,chain_hash,last_record_at,last_checkpoint_sequence,last_checkpoint_at
FROM public.coh_audit_heads WHERE organization_id=$1 AND tenant_id=$2`
	if lock {
		statement += " FOR UPDATE"
	}
	var head tamperaudit.Head
	var sequence, checkpointSequence int64
	err := query.QueryRow(ctx, statement, organizationID, tenantID).Scan(&head.OrganizationID, &head.TenantID,
		&sequence, &head.ChainHash, &head.LastRecordAt, &checkpointSequence, &head.LastCheckpointAt)
	if err == pgx.ErrNoRows {
		return tamperaudit.Head{}, nil
	}
	if err != nil {
		return tamperaudit.Head{}, normalizeError("load_audit_head", "head", err)
	}
	if sequence < 0 || checkpointSequence < 0 {
		return tamperaudit.Head{}, storageError(workflow.StorageDenied, "load_audit_head", "head", "stored audit head is invalid")
	}
	head.Sequence, head.LastCheckpointSequence = uint64(sequence), uint64(checkpointSequence)
	return head, nil
}

func (store *Store) CommitAudit(ctx context.Context, commit auditlog.Commit) (auditlog.AppendResult, error) {
	if err := store.ready(ctx, "commit_audit"); err != nil {
		return auditlog.AppendResult{}, err
	}
	if err := auditlog.ValidateCommit(commit); err != nil {
		return auditlog.AppendResult{}, postgresAuditValidationError(err)
	}
	tx, err := store.beginScoped(ctx, commit.Record.OrganizationID, commit.Record.TenantID)
	if err != nil {
		return auditlog.AppendResult{}, normalizeError("commit_audit", "transaction", err)
	}
	defer tx.Rollback(ctx)
	lockKey := "coh:audit:" + commit.Record.OrganizationID + "/" + commit.Record.TenantID
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))`, lockKey); err != nil {
		return auditlog.AppendResult{}, normalizeError("commit_audit", "lock", err)
	}
	if result, found, err := postgresAuditReplay(ctx, tx, commit); err != nil || found {
		return result, err
	}
	actual, err := loadAuditHead(ctx, tx, commit.Record.OrganizationID, commit.Record.TenantID, true)
	if err != nil {
		return auditlog.AppendResult{}, err
	}
	if !samePostgresAuditHead(actual, commit.ExpectedHead) {
		return auditlog.AppendResult{}, storageError(workflow.StorageConflict, "commit_audit", "head", "audit head changed")
	}
	recordBytes, _ := tamperaudit.CanonicalRecord(commit.Record)
	if _, err := tx.Exec(ctx, `INSERT INTO public.coh_audit_records
(organization_id,tenant_id,sequence,event_id,event_digest,previous_chain_hash,chain_hash,appended_at,canonical)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, commit.Record.OrganizationID, commit.Record.TenantID,
		commit.Record.Sequence, commit.Record.Event.EventID, commit.Record.EventDigest, commit.Record.PreviousChainHash,
		commit.Record.ChainHash, commit.Record.AppendedAt, recordBytes); err != nil {
		return auditlog.AppendResult{}, normalizeError("commit_audit", "record", err)
	}
	result := auditlog.AppendResult{Sequence: commit.Record.Sequence, ChainHash: commit.Record.ChainHash}
	checkpointSequence, checkpointAt := commit.ExpectedHead.LastCheckpointSequence, commit.ExpectedHead.LastCheckpointAt
	if commit.Checkpoint != nil {
		checkpointBytes, _ := tamperaudit.CanonicalCheckpoint(*commit.Checkpoint)
		if _, err := tx.Exec(ctx, `INSERT INTO public.coh_audit_checkpoints
(organization_id,tenant_id,sequence,checkpoint_id,chain_hash,created_at,canonical) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			commit.Checkpoint.OrganizationID, commit.Checkpoint.TenantID, commit.Checkpoint.Sequence,
			commit.Checkpoint.CheckpointID, commit.Checkpoint.ChainHash, commit.Checkpoint.CreatedAt, checkpointBytes); err != nil {
			return auditlog.AppendResult{}, normalizeError("commit_audit", "checkpoint", err)
		}
		result.CheckpointID, checkpointSequence, checkpointAt = commit.Checkpoint.CheckpointID, commit.Checkpoint.Sequence, commit.Checkpoint.CreatedAt
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.coh_audit_heads
(organization_id,tenant_id,sequence,chain_hash,last_record_at,last_checkpoint_sequence,last_checkpoint_at)
VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(organization_id,tenant_id) DO UPDATE SET
sequence=excluded.sequence,chain_hash=excluded.chain_hash,last_record_at=excluded.last_record_at,
last_checkpoint_sequence=excluded.last_checkpoint_sequence,last_checkpoint_at=excluded.last_checkpoint_at`,
		commit.Record.OrganizationID, commit.Record.TenantID, commit.Record.Sequence, commit.Record.ChainHash,
		commit.Record.AppendedAt, checkpointSequence, checkpointAt); err != nil {
		return auditlog.AppendResult{}, normalizeError("commit_audit", "head", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.coh_audit_idempotency
(organization_id,tenant_id,idempotency_key,request_digest,sequence,chain_hash,checkpoint_id) VALUES($1,$2,$3,$4,$5,$6,$7)`,
		commit.Record.OrganizationID, commit.Record.TenantID, commit.IdempotencyKey, commit.RequestDigest,
		result.Sequence, result.ChainHash, result.CheckpointID); err != nil {
		return auditlog.AppendResult{}, normalizeError("commit_audit", "idempotency", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return auditlog.AppendResult{}, normalizeError("commit_audit", "commit", err)
	}
	return result, nil
}

func postgresAuditReplay(ctx context.Context, tx pgx.Tx, commit auditlog.Commit) (auditlog.AppendResult, bool, error) {
	var digest string
	var sequence int64
	var result auditlog.AppendResult
	err := tx.QueryRow(ctx, `SELECT request_digest,sequence,chain_hash,checkpoint_id FROM public.coh_audit_idempotency
WHERE organization_id=$1 AND tenant_id=$2 AND idempotency_key=$3`, commit.Record.OrganizationID,
		commit.Record.TenantID, commit.IdempotencyKey).Scan(&digest, &sequence, &result.ChainHash, &result.CheckpointID)
	if err == pgx.ErrNoRows {
		return auditlog.AppendResult{}, false, nil
	}
	if err != nil || sequence <= 0 {
		return auditlog.AppendResult{}, false, normalizeError("commit_audit", "idempotency", err)
	}
	if digest != commit.RequestDigest {
		return auditlog.AppendResult{}, true, storageError(workflow.StorageConflict, "commit_audit", "idempotency", "idempotency key changed")
	}
	result.Sequence, result.Replayed = uint64(sequence), true
	return result, true, nil
}

func (store *Store) ReadAuditRecords(ctx context.Context, organizationID, tenantID string, after uint64, limit uint16) ([]tamperaudit.Record, error) {
	if err := store.ready(ctx, "read_audit_records"); err != nil {
		return nil, err
	}
	if limit == 0 || limit > 1000 {
		return nil, storageError(workflow.StorageInvalidInput, "read_audit_records", "limit", "limit is outside bounds")
	}
	tx, err := store.beginScoped(ctx, organizationID, tenantID)
	if err != nil {
		return nil, normalizeError("read_audit_records", "transaction", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT sequence,event_id,event_digest,previous_chain_hash,chain_hash,appended_at,canonical
FROM public.coh_audit_records WHERE organization_id=$1 AND tenant_id=$2 AND sequence>$3 ORDER BY sequence LIMIT $4`, organizationID, tenantID, after, limit)
	if err != nil {
		return nil, normalizeError("read_audit_records", "query", err)
	}
	defer rows.Close()
	var records []tamperaudit.Record
	for rows.Next() {
		var sequence int64
		var eventID, eventDigest, previousHash, chainHash string
		var appendedAt string
		var canonicalBytes []byte
		if err := rows.Scan(&sequence, &eventID, &eventDigest, &previousHash, &chainHash, &appendedAt, &canonicalBytes); err != nil {
			return nil, normalizeError("read_audit_records", "row", err)
		}
		if sequence <= 0 {
			return nil, storageError(workflow.StorageDenied, "read_audit_records", "sequence", "stored audit sequence is invalid")
		}
		record, err := tamperaudit.DecodeRecord(canonicalBytes)
		if err != nil || record.Sequence != uint64(sequence) || record.Event.EventID != eventID || record.EventDigest != eventDigest ||
			record.PreviousChainHash != previousHash || record.ChainHash != chainHash || record.AppendedAt != appendedAt {
			return nil, storageError(workflow.StorageDenied, "read_audit_records", "integrity", "audit record columns differ from canonical bytes")
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, normalizeError("read_audit_records", "rows", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, normalizeError("read_audit_records", "commit", err)
	}
	return records, nil
}

func (store *Store) ReadAuditCheckpoints(ctx context.Context, organizationID, tenantID string) ([]tamperaudit.Checkpoint, error) {
	if err := store.ready(ctx, "read_audit_checkpoints"); err != nil {
		return nil, err
	}
	tx, err := store.beginScoped(ctx, organizationID, tenantID)
	if err != nil {
		return nil, normalizeError("read_audit_checkpoints", "transaction", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT sequence,checkpoint_id,chain_hash,created_at,canonical FROM public.coh_audit_checkpoints
WHERE organization_id=$1 AND tenant_id=$2 ORDER BY sequence`, organizationID, tenantID)
	if err != nil {
		return nil, normalizeError("read_audit_checkpoints", "query", err)
	}
	defer rows.Close()
	var checkpoints []tamperaudit.Checkpoint
	for rows.Next() {
		var sequence int64
		var checkpointID, chainHash string
		var createdAt string
		var canonicalBytes []byte
		if err := rows.Scan(&sequence, &checkpointID, &chainHash, &createdAt, &canonicalBytes); err != nil {
			return nil, normalizeError("read_audit_checkpoints", "row", err)
		}
		if sequence <= 0 {
			return nil, storageError(workflow.StorageDenied, "read_audit_checkpoints", "sequence", "stored checkpoint sequence is invalid")
		}
		checkpoint, err := tamperaudit.DecodeCheckpoint(canonicalBytes)
		if err != nil || checkpoint.Sequence != uint64(sequence) || checkpoint.CheckpointID != checkpointID ||
			checkpoint.ChainHash != chainHash || checkpoint.CreatedAt != createdAt {
			return nil, storageError(workflow.StorageDenied, "read_audit_checkpoints", "integrity", "audit checkpoint columns differ from canonical bytes")
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	if err := rows.Err(); err != nil {
		return nil, normalizeError("read_audit_checkpoints", "rows", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, normalizeError("read_audit_checkpoints", "commit", err)
	}
	return checkpoints, nil
}

func samePostgresAuditHead(left, right tamperaudit.Head) bool {
	if left.Sequence == 0 && left.ChainHash == "" {
		left.ChainHash = tamperaudit.GenesisHash
	}
	if right.Sequence == 0 && right.ChainHash == "" {
		right.ChainHash = tamperaudit.GenesisHash
	}
	return left == right
}

func postgresAuditValidationError(err error) error {
	if errors.Is(err, auditlog.ErrInvalidInput) {
		return storageError(workflow.StorageInvalidInput, "commit_audit", "commit", "audit commit is invalid")
	}
	return storageError(workflow.StorageDenied, "commit_audit", "integrity", "audit commit failed integrity validation")
}
