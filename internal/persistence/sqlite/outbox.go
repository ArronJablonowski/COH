package sqlite

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func (store *Store) ClaimOutbox(ctx context.Context, claim workflow.OutboxClaim) ([]workflow.OutboxDelivery, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "claim_outbox"); err != nil {
		return nil, err
	}
	now := store.clock().UTC()
	if !claim.LeaseUntil.After(now) {
		return nil, storageError(workflow.StorageInvalidInput, "claim_outbox", "lease_until", "lease deadline must be in the future")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, normalizeError("claim_outbox", "transaction", err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT message_id,organization_id,tenant_id,case_id,topic,payload_ref,payload_digest
FROM coh_outbox WHERE organization_id=? AND tenant_id=? AND settlement_outcome IN ('','retry') AND (lease_until='' OR lease_until<=?)
ORDER BY message_id LIMIT ?`, claim.OrganizationID, claim.TenantID, formatTime(now), claim.Limit)
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
	if err := rows.Close(); err != nil {
		return nil, normalizeError("claim_outbox", "result", err)
	}
	deliveries := make([]workflow.OutboxDelivery, 0, len(messages))
	for _, message := range messages {
		leaseID, err := newUUIDv7(now)
		if err != nil {
			return nil, storageError(workflow.StorageUnavailable, "claim_outbox", "lease_id", "lease identity generation failed")
		}
		changed, err := tx.ExecContext(ctx, `UPDATE coh_outbox SET lease_id=?,lease_until=?,settlement_outcome='',evidence_digest=''
WHERE message_id=? AND settlement_outcome IN ('','retry') AND (lease_until='' OR lease_until<=?)`, leaseID, formatTime(claim.LeaseUntil), message.ID, formatTime(now))
		if err != nil {
			return nil, normalizeError("claim_outbox", "lease", err)
		}
		count, _ := changed.RowsAffected()
		if count != 1 {
			return nil, storageError(workflow.StorageConflict, "claim_outbox", "lease", "outbox lease changed")
		}
		deliveries = append(deliveries, workflow.OutboxDelivery{Message: message, LeaseID: leaseID})
	}
	if err := tx.Commit(); err != nil {
		return nil, normalizeError("claim_outbox", "commit", err)
	}
	return deliveries, nil
}

func (store *Store) SettleOutbox(ctx context.Context, settlement workflow.OutboxSettlement) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "settle_outbox"); err != nil {
		return err
	}
	var leaseID, outcome, evidence string
	err := store.db.QueryRowContext(ctx, "SELECT lease_id,settlement_outcome,evidence_digest FROM coh_outbox WHERE message_id=?", settlement.MessageID).Scan(&leaseID, &outcome, &evidence)
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
	leaseUntil := ""
	if settlement.Outcome != workflow.OutboxRetry {
		if err := store.db.QueryRowContext(ctx, "SELECT lease_until FROM coh_outbox WHERE message_id=?", settlement.MessageID).Scan(&leaseUntil); err != nil {
			return normalizeError("settle_outbox", "lease", err)
		}
	}
	result, err := store.db.ExecContext(ctx, `UPDATE coh_outbox SET settlement_outcome=?,evidence_digest=?,lease_until=?
WHERE message_id=? AND lease_id=? AND settlement_outcome=''`, settlement.Outcome, settlement.EvidenceDigest, leaseUntil, settlement.MessageID, settlement.LeaseID)
	if err != nil {
		return normalizeError("settle_outbox", "settlement", err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return storageError(workflow.StorageConflict, "settle_outbox", "settlement", "message lease changed before settlement")
	}
	return nil
}

func (store *Store) ready(ctx context.Context, operation string) error {
	if err := contextError(ctx, operation); err != nil {
		return err
	}
	if store.db == nil {
		return storageError(workflow.StorageUnavailable, operation, "database", "store is closed")
	}
	return nil
}

func formatTime(value time.Time) string { return value.UTC().Format(timestampLayout) }

func newUUIDv7(now time.Time) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	milliseconds := uint64(now.UnixMilli())
	value[0] = byte(milliseconds >> 40)
	value[1] = byte(milliseconds >> 32)
	value[2] = byte(milliseconds >> 24)
	value[3] = byte(milliseconds >> 16)
	value[4] = byte(milliseconds >> 8)
	value[5] = byte(milliseconds)
	value[6] = (value[6] & 0x0f) | 0x70
	value[8] = (value[8] & 0x3f) | 0x80
	_ = binary.BigEndian.Uint64(value[8:])
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
