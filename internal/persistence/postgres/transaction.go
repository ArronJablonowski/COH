package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/jackc/pgx/v5"
)

func (store *Store) Get(ctx context.Context, key workflow.RecordKey) (workflow.MetadataRecord, error) {
	if err := store.ready(ctx, "get"); err != nil {
		return workflow.MetadataRecord{}, err
	}
	tx, err := store.beginScoped(ctx, key.Case.OrganizationID, key.Case.TenantID)
	if err != nil {
		return workflow.MetadataRecord{}, normalizeError("get", "transaction", err)
	}
	defer tx.Rollback(ctx)
	record := workflow.MetadataRecord{Key: key}
	var revision int64
	err = tx.QueryRow(ctx, `SELECT schema_id, revision, canonical, digest FROM public.coh_records
WHERE organization_id=$1 AND tenant_id=$2 AND case_id=$3 AND kind=$4 AND record_id=$5`,
		key.Case.OrganizationID, key.Case.TenantID, key.Case.CaseID, key.Kind, key.ID).
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
	if err := store.ready(ctx, "transact"); err != nil {
		return workflow.CommitResult{}, err
	}
	if err := workflow.ValidateTransaction(request); err != nil {
		return workflow.CommitResult{}, err
	}
	scope := request.Mutations[0].Key.Case
	fingerprint, err := transactionDigest(request)
	if err != nil {
		return workflow.CommitResult{}, storageError(workflow.StorageInvalidInput, "transact", "transaction", "transaction cannot be encoded")
	}
	tx, err := store.beginScoped(ctx, scope.OrganizationID, scope.TenantID)
	if err != nil {
		return workflow.CommitResult{}, normalizeError("transact", "transaction", err)
	}
	defer tx.Rollback(ctx)
	lockKey := scope.OrganizationID + "/" + scope.TenantID + "/" + request.IdempotencyKey
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1, 0))`, lockKey); err != nil {
		return workflow.CommitResult{}, normalizeError("transact", "idempotency_lock", err)
	}
	if replay, found, err := replayResult(ctx, tx, scope.OrganizationID, scope.TenantID, request.IdempotencyKey, fingerprint); err != nil {
		return workflow.CommitResult{}, err
	} else if found {
		return replay, nil
	}
	var sequence int64
	if err := tx.QueryRow(ctx, `UPDATE public.coh_store_sequence SET commit_sequence=commit_sequence+1
WHERE singleton=TRUE RETURNING commit_sequence`).Scan(&sequence); err != nil {
		return workflow.CommitResult{}, normalizeError("transact", "sequence", err)
	}
	result := workflow.CommitResult{IdempotencyKey: request.IdempotencyKey, CommitSequence: uint64(sequence), RecordVersions: make(map[string]uint64, len(request.Mutations)), OutboxIDs: make([]string, 0, len(request.Outbox))}
	for _, mutation := range request.Mutations {
		if err := applyMutation(ctx, tx, mutation, result.RecordVersions); err != nil {
			return workflow.CommitResult{}, err
		}
	}
	for _, message := range request.Outbox {
		if _, err := tx.Exec(ctx, `INSERT INTO public.coh_outbox
(organization_id,tenant_id,message_id,case_id,topic,payload_ref,payload_digest) VALUES($1,$2,$3,$4,$5,$6,$7)`,
			message.Case.OrganizationID, message.Case.TenantID, message.ID, message.Case.CaseID, message.Topic, message.PayloadRef, message.PayloadDigest); err != nil {
			return workflow.CommitResult{}, normalizeError("transact", "outbox", err)
		}
		result.OutboxIDs = append(result.OutboxIDs, message.ID)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return workflow.CommitResult{}, normalizeError("transact", "result", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.coh_idempotency
(organization_id,tenant_id,idempotency_key,request_digest,commit_sequence,result_json) VALUES($1,$2,$3,$4,$5,$6)`,
		scope.OrganizationID, scope.TenantID, request.IdempotencyKey, fingerprint, sequence, encoded); err != nil {
		return workflow.CommitResult{}, normalizeError("transact", "idempotency_key", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return workflow.CommitResult{}, normalizeError("transact", "commit", err)
	}
	return result, nil
}

func replayResult(ctx context.Context, tx pgx.Tx, organizationID, tenantID, key, fingerprint string) (workflow.CommitResult, bool, error) {
	var existingDigest string
	var existingJSON []byte
	err := tx.QueryRow(ctx, `SELECT request_digest,result_json FROM public.coh_idempotency
WHERE organization_id=$1 AND tenant_id=$2 AND idempotency_key=$3`, organizationID, tenantID, key).Scan(&existingDigest, &existingJSON)
	if err == pgx.ErrNoRows {
		return workflow.CommitResult{}, false, nil
	}
	if err != nil {
		return workflow.CommitResult{}, false, normalizeError("transact", "idempotency_key", err)
	}
	if existingDigest != fingerprint {
		return workflow.CommitResult{}, false, storageError(workflow.StorageConflict, "transact", "idempotency_key", "idempotency key was used for different inputs")
	}
	var result workflow.CommitResult
	if json.Unmarshal(existingJSON, &result) != nil {
		return workflow.CommitResult{}, false, storageError(workflow.StorageDenied, "transact", "idempotency_key", "stored replay result is invalid")
	}
	result.Replayed = true
	return result, true, nil
}

func applyMutation(ctx context.Context, tx pgx.Tx, mutation workflow.Mutation, versions map[string]uint64) error {
	actual, exists, err := recordRevision(ctx, tx, mutation.Key)
	if err != nil {
		return err
	}
	if (!exists && mutation.ExpectedRevision != 0) || (exists && actual != mutation.ExpectedRevision) {
		return storageError(workflow.StorageConflict, "transact", "revision", "optimistic revision check failed")
	}
	key := recordKey(mutation.Key)
	switch mutation.Kind {
	case workflow.MutationPut:
		record := mutation.Record
		_, err := tx.Exec(ctx, `INSERT INTO public.coh_records
(organization_id,tenant_id,case_id,kind,record_id,schema_id,revision,canonical,digest)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(organization_id,tenant_id,case_id,kind,record_id)
DO UPDATE SET schema_id=excluded.schema_id,revision=excluded.revision,canonical=excluded.canonical,digest=excluded.digest`,
			mutation.Key.Case.OrganizationID, mutation.Key.Case.TenantID, mutation.Key.Case.CaseID, mutation.Key.Kind, mutation.Key.ID,
			record.Schema, record.Revision, record.Canonical, record.Digest)
		if err != nil {
			return normalizeError("transact", "record", err)
		}
		versions[key] = record.Revision
	case workflow.MutationDelete:
		tag, err := tx.Exec(ctx, `DELETE FROM public.coh_records WHERE organization_id=$1 AND tenant_id=$2 AND case_id=$3 AND kind=$4 AND record_id=$5`,
			mutation.Key.Case.OrganizationID, mutation.Key.Case.TenantID, mutation.Key.Case.CaseID, mutation.Key.Kind, mutation.Key.ID)
		if err != nil {
			return normalizeError("transact", "record", err)
		}
		if tag.RowsAffected() != 1 {
			return storageError(workflow.StorageConflict, "transact", "revision", "delete target changed")
		}
		versions[key] = 0
	default:
		return storageError(workflow.StorageInvalidInput, "transact", "mutation", "unsupported mutation")
	}
	return nil
}

func recordRevision(ctx context.Context, tx pgx.Tx, key workflow.RecordKey) (uint64, bool, error) {
	var revision int64
	err := tx.QueryRow(ctx, `SELECT revision FROM public.coh_records
WHERE organization_id=$1 AND tenant_id=$2 AND case_id=$3 AND kind=$4 AND record_id=$5 FOR UPDATE`,
		key.Case.OrganizationID, key.Case.TenantID, key.Case.CaseID, key.Kind, key.ID).Scan(&revision)
	if err == pgx.ErrNoRows {
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
