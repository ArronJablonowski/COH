package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

func (store *Store) Get(ctx context.Context, key workflow.RecordKey) (workflow.MetadataRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "get"); err != nil {
		return workflow.MetadataRecord{}, err
	}
	var record workflow.MetadataRecord
	record.Key = key
	var revision int64
	err := store.db.QueryRowContext(ctx, `SELECT schema_id, revision, canonical, digest FROM coh_records
WHERE organization_id=? AND tenant_id=? AND case_id=? AND kind=? AND record_id=?`, key.Case.OrganizationID, key.Case.TenantID, key.Case.CaseID, key.Kind, key.ID).
		Scan(&record.Schema, &revision, &record.Canonical, &record.Digest)
	if err != nil {
		return workflow.MetadataRecord{}, normalizeError("get", "record", err)
	}
	if revision <= 0 {
		return workflow.MetadataRecord{}, storageError(workflow.StorageDenied, "get", "revision", "stored revision is invalid")
	}
	record.Revision = uint64(revision)
	return record, nil
}

func (store *Store) Transact(ctx context.Context, request workflow.Transaction) (workflow.CommitResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "transact"); err != nil {
		return workflow.CommitResult{}, err
	}
	fingerprint, err := transactionDigest(request)
	if err != nil {
		return workflow.CommitResult{}, storageError(workflow.StorageInvalidInput, "transact", "transaction", "transaction cannot be encoded")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return workflow.CommitResult{}, normalizeError("transact", "transaction", err)
	}
	defer tx.Rollback()
	var existingDigest string
	var existingJSON []byte
	err = tx.QueryRowContext(ctx, "SELECT request_digest, result_json FROM coh_idempotency WHERE idempotency_key=?", request.IdempotencyKey).Scan(&existingDigest, &existingJSON)
	if err == nil {
		if existingDigest != fingerprint {
			return workflow.CommitResult{}, storageError(workflow.StorageConflict, "transact", "idempotency_key", "idempotency key was used for different inputs")
		}
		var result workflow.CommitResult
		if json.Unmarshal(existingJSON, &result) != nil {
			return workflow.CommitResult{}, storageError(workflow.StorageDenied, "transact", "idempotency_key", "stored replay result is invalid")
		}
		result.Replayed = true
		return result, nil
	}
	if err != sql.ErrNoRows {
		return workflow.CommitResult{}, normalizeError("transact", "idempotency_key", err)
	}

	var sequence int64
	if err := tx.QueryRowContext(ctx, "UPDATE coh_store_sequence SET commit_sequence=commit_sequence+1 WHERE singleton=1 RETURNING commit_sequence").Scan(&sequence); err != nil {
		return workflow.CommitResult{}, normalizeError("transact", "sequence", err)
	}
	result := workflow.CommitResult{IdempotencyKey: request.IdempotencyKey, CommitSequence: uint64(sequence), RecordVersions: make(map[string]uint64, len(request.Mutations)), OutboxIDs: make([]string, 0, len(request.Outbox))}
	for _, mutation := range request.Mutations {
		actual, exists, err := recordRevision(ctx, tx, mutation.Key)
		if err != nil {
			return workflow.CommitResult{}, err
		}
		if !exists && mutation.ExpectedRevision != 0 || exists && actual != mutation.ExpectedRevision {
			return workflow.CommitResult{}, storageError(workflow.StorageConflict, "transact", "revision", "optimistic revision check failed")
		}
		key := recordKey(mutation.Key)
		switch mutation.Kind {
		case workflow.MutationPut:
			record := mutation.Record
			if _, err := tx.ExecContext(ctx, `INSERT INTO coh_records
(organization_id,tenant_id,case_id,kind,record_id,schema_id,revision,canonical,digest)
VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(organization_id,tenant_id,case_id,kind,record_id)
DO UPDATE SET schema_id=excluded.schema_id,revision=excluded.revision,canonical=excluded.canonical,digest=excluded.digest`,
				mutation.Key.Case.OrganizationID, mutation.Key.Case.TenantID, mutation.Key.Case.CaseID, mutation.Key.Kind, mutation.Key.ID,
				record.Schema, record.Revision, record.Canonical, record.Digest); err != nil {
				return workflow.CommitResult{}, normalizeError("transact", "record", err)
			}
			result.RecordVersions[key] = record.Revision
		case workflow.MutationDelete:
			changed, err := tx.ExecContext(ctx, `DELETE FROM coh_records WHERE organization_id=? AND tenant_id=? AND case_id=? AND kind=? AND record_id=?`,
				mutation.Key.Case.OrganizationID, mutation.Key.Case.TenantID, mutation.Key.Case.CaseID, mutation.Key.Kind, mutation.Key.ID)
			if err != nil {
				return workflow.CommitResult{}, normalizeError("transact", "record", err)
			}
			count, _ := changed.RowsAffected()
			if count != 1 {
				return workflow.CommitResult{}, storageError(workflow.StorageConflict, "transact", "revision", "delete target changed")
			}
			result.RecordVersions[key] = 0
		default:
			return workflow.CommitResult{}, storageError(workflow.StorageInvalidInput, "transact", "mutation", "unsupported mutation")
		}
	}
	for _, message := range request.Outbox {
		var exists int
		err := tx.QueryRowContext(ctx, "SELECT 1 FROM coh_outbox WHERE message_id=?", message.ID).Scan(&exists)
		if err == nil {
			return workflow.CommitResult{}, storageError(workflow.StorageConflict, "transact", "outbox", "outbox identity already exists")
		}
		if err != sql.ErrNoRows {
			return workflow.CommitResult{}, normalizeError("transact", "outbox", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO coh_outbox
(message_id,organization_id,tenant_id,case_id,topic,payload_ref,payload_digest) VALUES(?,?,?,?,?,?,?)`,
			message.ID, message.Case.OrganizationID, message.Case.TenantID, message.Case.CaseID, message.Topic, message.PayloadRef, message.PayloadDigest); err != nil {
			return workflow.CommitResult{}, normalizeError("transact", "outbox", err)
		}
		result.OutboxIDs = append(result.OutboxIDs, message.ID)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return workflow.CommitResult{}, normalizeError("transact", "result", err)
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO coh_idempotency(idempotency_key,request_digest,commit_sequence,result_json) VALUES(?,?,?,?)", request.IdempotencyKey, fingerprint, sequence, encoded); err != nil {
		return workflow.CommitResult{}, normalizeError("transact", "idempotency_key", err)
	}
	if err := tx.Commit(); err != nil {
		return workflow.CommitResult{}, normalizeError("transact", "commit", err)
	}
	return result, nil
}

func recordRevision(ctx context.Context, tx *sql.Tx, key workflow.RecordKey) (uint64, bool, error) {
	var revision int64
	err := tx.QueryRowContext(ctx, `SELECT revision FROM coh_records WHERE organization_id=? AND tenant_id=? AND case_id=? AND kind=? AND record_id=?`,
		key.Case.OrganizationID, key.Case.TenantID, key.Case.CaseID, key.Kind, key.ID).Scan(&revision)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, normalizeError("transact", "revision", err)
	}
	return uint64(revision), true, nil
}

func transactionDigest(value workflow.Transaction) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func recordKey(key workflow.RecordKey) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s", key.Case.OrganizationID, key.Case.TenantID, key.Case.CaseID, key.Kind, key.ID)
}

func scanOutbox(scanner interface{ Scan(...any) error }) (workflow.OutboxMessage, error) {
	var message workflow.OutboxMessage
	var organizationID, tenantID, caseID string
	err := scanner.Scan(&message.ID, &organizationID, &tenantID, &caseID, &message.Topic, &message.PayloadRef, &message.PayloadDigest)
	message.Case = domain.CaseRef{OrganizationID: organizationID, TenantID: tenantID, CaseID: caseID}
	return message, err
}
