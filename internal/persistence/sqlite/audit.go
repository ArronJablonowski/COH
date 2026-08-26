package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/auditlog"
)

func (store *Store) LoadHead(ctx context.Context, organizationID, tenantID string) (tamperaudit.Head, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "load_audit_head"); err != nil {
		return tamperaudit.Head{}, err
	}
	return loadAuditHead(ctx, store.db, organizationID, tenantID)
}

type sqliteRowQuery interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func loadAuditHead(ctx context.Context, query sqliteRowQuery, organizationID, tenantID string) (tamperaudit.Head, error) {
	var head tamperaudit.Head
	err := query.QueryRowContext(ctx, `SELECT organization_id, tenant_id, sequence, chain_hash,
last_record_at, last_checkpoint_sequence, last_checkpoint_at FROM coh_audit_heads
WHERE organization_id=? AND tenant_id=?`, organizationID, tenantID).Scan(&head.OrganizationID, &head.TenantID,
		&head.Sequence, &head.ChainHash, &head.LastRecordAt, &head.LastCheckpointSequence, &head.LastCheckpointAt)
	if err == sql.ErrNoRows {
		return tamperaudit.Head{}, nil
	}
	if err != nil {
		return tamperaudit.Head{}, normalizeError("load_audit_head", "head", err)
	}
	return head, nil
}

func (store *Store) CommitAudit(ctx context.Context, commit auditlog.Commit) (auditlog.AppendResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "commit_audit"); err != nil {
		return auditlog.AppendResult{}, err
	}
	if err := auditlog.ValidateCommit(commit); err != nil {
		return auditlog.AppendResult{}, auditValidationError(err)
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return auditlog.AppendResult{}, normalizeError("commit_audit", "transaction", err)
	}
	defer tx.Rollback()
	if result, found, err := sqliteAuditReplay(ctx, tx, commit); err != nil || found {
		return result, err
	}
	actual, err := loadAuditHead(ctx, tx, commit.Record.OrganizationID, commit.Record.TenantID)
	if err != nil {
		return auditlog.AppendResult{}, err
	}
	if !sameAuditHead(actual, commit.ExpectedHead) {
		return auditlog.AppendResult{}, storageError(workflow.StorageConflict, "commit_audit", "head", "audit head changed")
	}
	recordBytes, _ := tamperaudit.CanonicalRecord(commit.Record)
	if _, err := tx.ExecContext(ctx, `INSERT INTO coh_audit_records
(organization_id,tenant_id,sequence,event_id,event_digest,previous_chain_hash,chain_hash,appended_at,canonical)
VALUES (?,?,?,?,?,?,?,?,?)`, commit.Record.OrganizationID, commit.Record.TenantID, commit.Record.Sequence,
		commit.Record.Event.EventID, commit.Record.EventDigest, commit.Record.PreviousChainHash,
		commit.Record.ChainHash, commit.Record.AppendedAt, recordBytes); err != nil {
		return auditlog.AppendResult{}, normalizeError("commit_audit", "record", err)
	}
	result := auditlog.AppendResult{Sequence: commit.Record.Sequence, ChainHash: commit.Record.ChainHash}
	checkpointSequence, checkpointAt := commit.ExpectedHead.LastCheckpointSequence, commit.ExpectedHead.LastCheckpointAt
	if commit.Checkpoint != nil {
		checkpointBytes, _ := tamperaudit.CanonicalCheckpoint(*commit.Checkpoint)
		if _, err := tx.ExecContext(ctx, `INSERT INTO coh_audit_checkpoints
(organization_id,tenant_id,sequence,checkpoint_id,chain_hash,created_at,canonical) VALUES (?,?,?,?,?,?,?)`,
			commit.Checkpoint.OrganizationID, commit.Checkpoint.TenantID, commit.Checkpoint.Sequence,
			commit.Checkpoint.CheckpointID, commit.Checkpoint.ChainHash, commit.Checkpoint.CreatedAt, checkpointBytes); err != nil {
			return auditlog.AppendResult{}, normalizeError("commit_audit", "checkpoint", err)
		}
		result.CheckpointID, checkpointSequence, checkpointAt = commit.Checkpoint.CheckpointID, commit.Checkpoint.Sequence, commit.Checkpoint.CreatedAt
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO coh_audit_heads
(organization_id,tenant_id,sequence,chain_hash,last_record_at,last_checkpoint_sequence,last_checkpoint_at)
VALUES (?,?,?,?,?,?,?) ON CONFLICT(organization_id,tenant_id) DO UPDATE SET
sequence=excluded.sequence,chain_hash=excluded.chain_hash,last_record_at=excluded.last_record_at,
last_checkpoint_sequence=excluded.last_checkpoint_sequence,last_checkpoint_at=excluded.last_checkpoint_at`,
		commit.Record.OrganizationID, commit.Record.TenantID, commit.Record.Sequence, commit.Record.ChainHash,
		commit.Record.AppendedAt, checkpointSequence, checkpointAt); err != nil {
		return auditlog.AppendResult{}, normalizeError("commit_audit", "head", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO coh_audit_idempotency
(organization_id,tenant_id,idempotency_key,request_digest,sequence,chain_hash,checkpoint_id) VALUES (?,?,?,?,?,?,?)`,
		commit.Record.OrganizationID, commit.Record.TenantID, commit.IdempotencyKey, commit.RequestDigest,
		result.Sequence, result.ChainHash, result.CheckpointID); err != nil {
		return auditlog.AppendResult{}, normalizeError("commit_audit", "idempotency", err)
	}
	if err := tx.Commit(); err != nil {
		return auditlog.AppendResult{}, normalizeError("commit_audit", "commit", err)
	}
	return result, nil
}

func sqliteAuditReplay(ctx context.Context, tx *sql.Tx, commit auditlog.Commit) (auditlog.AppendResult, bool, error) {
	var digest string
	var result auditlog.AppendResult
	err := tx.QueryRowContext(ctx, `SELECT request_digest,sequence,chain_hash,checkpoint_id FROM coh_audit_idempotency
WHERE organization_id=? AND tenant_id=? AND idempotency_key=?`, commit.Record.OrganizationID,
		commit.Record.TenantID, commit.IdempotencyKey).Scan(&digest, &result.Sequence, &result.ChainHash, &result.CheckpointID)
	if err == sql.ErrNoRows {
		return auditlog.AppendResult{}, false, nil
	}
	if err != nil {
		return auditlog.AppendResult{}, false, normalizeError("commit_audit", "idempotency", err)
	}
	if digest != commit.RequestDigest {
		return auditlog.AppendResult{}, true, storageError(workflow.StorageConflict, "commit_audit", "idempotency", "idempotency key changed")
	}
	result.Replayed = true
	return result, true, nil
}

func (store *Store) ReadAuditRecords(ctx context.Context, organizationID, tenantID string, after uint64, limit uint16) ([]tamperaudit.Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "read_audit_records"); err != nil {
		return nil, err
	}
	if limit == 0 || limit > 1000 {
		return nil, storageError(workflow.StorageInvalidInput, "read_audit_records", "limit", "limit is outside bounds")
	}
	rows, err := store.db.QueryContext(ctx, `SELECT sequence,event_id,event_digest,previous_chain_hash,chain_hash,appended_at,canonical
FROM coh_audit_records WHERE organization_id=? AND tenant_id=? AND sequence>? ORDER BY sequence LIMIT ?`, organizationID, tenantID, after, limit)
	if err != nil {
		return nil, normalizeError("read_audit_records", "query", err)
	}
	defer rows.Close()
	var records []tamperaudit.Record
	for rows.Next() {
		var sequence uint64
		var eventID, eventDigest, previousHash, chainHash, appendedAt string
		var canonicalBytes []byte
		if err := rows.Scan(&sequence, &eventID, &eventDigest, &previousHash, &chainHash, &appendedAt, &canonicalBytes); err != nil {
			return nil, normalizeError("read_audit_records", "row", err)
		}
		record, err := tamperaudit.DecodeRecord(canonicalBytes)
		if err != nil || record.Sequence != sequence || record.Event.EventID != eventID || record.EventDigest != eventDigest ||
			record.PreviousChainHash != previousHash || record.ChainHash != chainHash || record.AppendedAt != appendedAt {
			return nil, storageError(workflow.StorageDenied, "read_audit_records", "integrity", "audit record columns differ from canonical bytes")
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, normalizeError("read_audit_records", "rows", err)
	}
	return records, nil
}

func (store *Store) ReadAuditCheckpoints(ctx context.Context, organizationID, tenantID string) ([]tamperaudit.Checkpoint, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "read_audit_checkpoints"); err != nil {
		return nil, err
	}
	rows, err := store.db.QueryContext(ctx, `SELECT sequence,checkpoint_id,chain_hash,created_at,canonical
FROM coh_audit_checkpoints WHERE organization_id=? AND tenant_id=? ORDER BY sequence`, organizationID, tenantID)
	if err != nil {
		return nil, normalizeError("read_audit_checkpoints", "query", err)
	}
	defer rows.Close()
	var checkpoints []tamperaudit.Checkpoint
	for rows.Next() {
		var sequence uint64
		var checkpointID, chainHash, createdAt string
		var canonicalBytes []byte
		if err := rows.Scan(&sequence, &checkpointID, &chainHash, &createdAt, &canonicalBytes); err != nil {
			return nil, normalizeError("read_audit_checkpoints", "row", err)
		}
		checkpoint, err := tamperaudit.DecodeCheckpoint(canonicalBytes)
		if err != nil || checkpoint.Sequence != sequence || checkpoint.CheckpointID != checkpointID ||
			checkpoint.ChainHash != chainHash || checkpoint.CreatedAt != createdAt {
			return nil, storageError(workflow.StorageDenied, "read_audit_checkpoints", "integrity", "audit checkpoint columns differ from canonical bytes")
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	if err := rows.Err(); err != nil {
		return nil, normalizeError("read_audit_checkpoints", "rows", err)
	}
	return checkpoints, nil
}

func sameAuditHead(left, right tamperaudit.Head) bool {
	if left.Sequence == 0 && left.ChainHash == "" {
		left.ChainHash = tamperaudit.GenesisHash
	}
	if right.Sequence == 0 && right.ChainHash == "" {
		right.ChainHash = tamperaudit.GenesisHash
	}
	return left == right
}

func auditValidationError(err error) error {
	if errors.Is(err, auditlog.ErrInvalidInput) {
		return storageError(workflow.StorageInvalidInput, "commit_audit", "commit", "audit commit is invalid")
	}
	return storageError(workflow.StorageDenied, "commit_audit", "integrity", "audit commit failed integrity validation")
}
