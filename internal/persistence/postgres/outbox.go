package postgres

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow"
)

func (store *Store) ClaimOutbox(ctx context.Context, claim workflow.OutboxClaim) ([]workflow.OutboxDelivery, error) {
	if err := store.ready(ctx, "claim_outbox"); err != nil {
		return nil, err
	}
	now := store.clock().UTC()
	if !claim.LeaseUntil.After(now) {
		return nil, storageError(workflow.StorageInvalidInput, "claim_outbox", "lease_until", "lease deadline must be in the future")
	}
	tx, err := store.beginScoped(ctx, claim.OrganizationID, claim.TenantID)
	if err != nil {
		return nil, normalizeError("claim_outbox", "transaction", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT message_id,organization_id,tenant_id,case_id,topic,payload_ref,payload_digest
FROM public.coh_outbox
WHERE organization_id=$1 AND tenant_id=$2 AND settlement_outcome IN ('','retry')
AND (lease_until IS NULL OR lease_until <= $3)
ORDER BY message_id FOR UPDATE SKIP LOCKED LIMIT $4`, claim.OrganizationID, claim.TenantID, now, claim.Limit)
	if err != nil {
		return nil, normalizeError("claim_outbox", "query", err)
	}
	messages := make([]workflow.OutboxMessage, 0, claim.Limit)
	for rows.Next() {
		message, scanErr := scanOutbox(rows)
		if scanErr != nil {
			rows.Close()
			return nil, normalizeError("claim_outbox", "result", scanErr)
		}
		messages = append(messages, message)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, normalizeError("claim_outbox", "result", err)
	}
	rows.Close()
	deliveries := make([]workflow.OutboxDelivery, 0, len(messages))
	for _, message := range messages {
		leaseID, err := newUUIDv7(now)
		if err != nil {
			return nil, storageError(workflow.StorageUnavailable, "claim_outbox", "lease_id", "lease identity generation failed")
		}
		tag, err := tx.Exec(ctx, `UPDATE public.coh_outbox SET lease_id=$1,lease_worker=$2,lease_until=$3,settlement_outcome='',evidence_digest=''
WHERE organization_id=$4 AND tenant_id=$5 AND message_id=$6 AND settlement_outcome IN ('','retry')
AND (lease_until IS NULL OR lease_until <= $7)`, leaseID, claim.WorkerID, claim.LeaseUntil,
			claim.OrganizationID, claim.TenantID, message.ID, now)
		if err != nil {
			return nil, normalizeError("claim_outbox", "lease", err)
		}
		if tag.RowsAffected() != 1 {
			return nil, storageError(workflow.StorageConflict, "claim_outbox", "lease", "outbox lease changed")
		}
		deliveries = append(deliveries, workflow.OutboxDelivery{Message: message, LeaseID: leaseID})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, normalizeError("claim_outbox", "commit", err)
	}
	return deliveries, nil
}

func (store *Store) SettleOutbox(ctx context.Context, settlement workflow.OutboxSettlement) error {
	if err := store.ready(ctx, "settle_outbox"); err != nil {
		return err
	}
	tx, err := store.beginScoped(ctx, settlement.OrganizationID, settlement.TenantID)
	if err != nil {
		return normalizeError("settle_outbox", "transaction", err)
	}
	defer tx.Rollback(ctx)
	var leaseID, outcome, evidence string
	err = tx.QueryRow(ctx, `SELECT lease_id,settlement_outcome,evidence_digest FROM public.coh_outbox
WHERE organization_id=$1 AND tenant_id=$2 AND message_id=$3 FOR UPDATE`,
		settlement.OrganizationID, settlement.TenantID, settlement.MessageID).Scan(&leaseID, &outcome, &evidence)
	if err != nil {
		return normalizeError("settle_outbox", "message_id", err)
	}
	if outcome != "" {
		if leaseID == settlement.LeaseID && outcome == string(settlement.Outcome) && evidence == settlement.EvidenceDigest {
			return nil
		}
		return storageError(workflow.StorageConflict, "settle_outbox", "settlement", "message was already settled differently")
	}
	if leaseID != settlement.LeaseID {
		return storageError(workflow.StorageConflict, "settle_outbox", "lease_id", "lease does not own message")
	}
	var leaseUntil any = store.clock().UTC()
	if settlement.Outcome == workflow.OutboxRetry {
		leaseUntil = nil
	}
	tag, err := tx.Exec(ctx, `UPDATE public.coh_outbox SET settlement_outcome=$1,evidence_digest=$2,lease_until=$3
WHERE organization_id=$4 AND tenant_id=$5 AND message_id=$6 AND lease_id=$7
AND settlement_outcome IN ('','retry')`, settlement.Outcome, settlement.EvidenceDigest, leaseUntil,
		settlement.OrganizationID, settlement.TenantID, settlement.MessageID, settlement.LeaseID)
	if err != nil {
		return normalizeError("settle_outbox", "settlement", err)
	}
	if tag.RowsAffected() != 1 {
		return storageError(workflow.StorageConflict, "settle_outbox", "settlement", "message lease changed before settlement")
	}
	if err := tx.Commit(ctx); err != nil {
		return normalizeError("settle_outbox", "commit", err)
	}
	return nil
}

func newUUIDv7(now time.Time) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	milliseconds := uint64(now.UnixMilli())
	value[0], value[1], value[2] = byte(milliseconds>>40), byte(milliseconds>>32), byte(milliseconds>>24)
	value[3], value[4], value[5] = byte(milliseconds>>16), byte(milliseconds>>8), byte(milliseconds)
	value[6] = (value[6] & 0x0f) | 0x70
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
