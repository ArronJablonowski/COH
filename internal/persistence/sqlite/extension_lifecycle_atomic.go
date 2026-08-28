package sqlite

import (
	"context"
	"database/sql"

	"github.com/ArronJablonowski/COH/internal/domain/extensionlifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

func (store *Store) CommitReceipt(ctx context.Context, current extensionlifecycle.Transition, receipt extensionlifecycle.RegistrationReceipt, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "extension_receipt_commit"); err != nil {
		return extensionlifecycle.Transition{}, err
	}
	canonical, digest, err := extensionlifecycle.CanonicalReceipt(ctx, receipt)
	if err != nil || receipt.ReceiptDigest != digest {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageInvalidInput, "extension_receipt_commit", "receipt", "receipt is invalid")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_receipt_commit", "transaction", err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO coh_extension_registration_receipts
(receipt_digest,receipt_id,extension_id,organization_id,tenant_id,registration_ordinal,state,handle_digest,canonical)
VALUES(?,?,?,?,?,?,?,?,?)`, digest, receipt.ReceiptID, receipt.ExtensionID, receipt.OrganizationID, receipt.TenantID,
		receipt.RegistrationOrdinal, receipt.State, receipt.RevocationHandle.HandleDigest, canonical); err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_receipt_commit", "receipt", err)
	}
	result, err := store.advanceExtensionTransition(ctx, tx, current, next)
	if err != nil {
		return extensionlifecycle.Transition{}, err
	}
	if err := tx.Commit(); err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_receipt_commit", "commit", err)
	}
	return result, nil
}

func (store *Store) CommitRevocation(ctx context.Context, current extensionlifecycle.Transition, registered, revoked extensionlifecycle.RegistrationReceipt, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "extension_revocation_commit"); err != nil {
		return extensionlifecycle.Transition{}, err
	}
	canonical, digest, err := extensionlifecycle.CanonicalReceipt(ctx, revoked)
	if err != nil || revoked.ReceiptDigest != digest || registered.ReceiptID != revoked.ReceiptID || registered.State != "registered" || revoked.State != "revoked" {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageInvalidInput, "extension_revocation_commit", "receipt", "revocation receipt is invalid")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_revocation_commit", "transaction", err)
	}
	defer tx.Rollback()
	stored, found, err := store.loadExtensionReceipt(ctx, tx, registered.ReceiptDigest)
	if err != nil || !found || stored.ReceiptID != registered.ReceiptID {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageConflict, "extension_revocation_commit", "receipt", "registered receipt changed")
	}
	result, err := tx.ExecContext(ctx, `UPDATE coh_extension_registration_receipts SET receipt_digest=?,state=?,handle_digest=?,canonical=? WHERE receipt_digest=? AND receipt_id=? AND state='registered'`, digest, revoked.State, revoked.RevocationHandle.HandleDigest, canonical, registered.ReceiptDigest, registered.ReceiptID)
	if err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_revocation_commit", "receipt", err)
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageConflict, "extension_revocation_commit", "receipt", "registered receipt changed")
	}
	transition, err := store.advanceExtensionTransition(ctx, tx, current, next)
	if err != nil {
		return extensionlifecycle.Transition{}, err
	}
	if err := tx.Commit(); err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_revocation_commit", "commit", err)
	}
	return transition, nil
}

func (store *Store) PublishActive(ctx context.Context, current extensionlifecycle.Transition, active extensionlifecycle.ActiveExtension, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "extension_active_publish"); err != nil {
		return extensionlifecycle.Transition{}, err
	}
	canonical, digest, err := extensionlifecycle.CanonicalActive(ctx, active)
	if err != nil || active.ActiveDigest != digest || active.TransitionID != current.TransitionID || next.Phase != extensionlifecycle.ActivePhase {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageInvalidInput, "extension_active_publish", "active", "active extension is invalid")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_active_publish", "transaction", err)
	}
	defer tx.Rollback()
	if _, found, loadErr := store.loadActiveExtension(ctx, tx, active.ExtensionID, active.OrganizationID, active.TenantID); loadErr != nil || found {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageConflict, "extension_active_publish", "active", "active extension changed")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO coh_active_extensions(extension_id,organization_id,tenant_id,manifest_digest,lifecycle_revision,transition_id,active_digest,canonical) VALUES(?,?,?,?,?,?,?,?)`, active.ExtensionID, active.OrganizationID, active.TenantID, active.ManifestDigest, active.LifecycleRevision, active.TransitionID, digest, canonical); err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_active_publish", "active", err)
	}
	transition, err := store.advanceExtensionTransition(ctx, tx, current, next)
	if err != nil {
		return extensionlifecycle.Transition{}, err
	}
	if err := tx.Commit(); err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_active_publish", "commit", err)
	}
	return transition, nil
}

func (store *Store) RemoveActive(ctx context.Context, current extensionlifecycle.Transition, active extensionlifecycle.ActiveExtension, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "extension_active_remove"); err != nil {
		return extensionlifecycle.Transition{}, err
	}
	if next.Phase != extensionlifecycle.InactivePhase || next.TerminalAuditDigest == "" {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageInvalidInput, "extension_active_remove", "transition", "terminal audit is required")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_active_remove", "transaction", err)
	}
	defer tx.Rollback()
	stored, found, err := store.loadActiveExtension(ctx, tx, active.ExtensionID, active.OrganizationID, active.TenantID)
	if err != nil || !found || stored.ActiveDigest != active.ActiveDigest {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageConflict, "extension_active_remove", "active", "active extension changed")
	}
	transition, err := store.advanceExtensionTransition(ctx, tx, current, next)
	if err != nil {
		return extensionlifecycle.Transition{}, err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM coh_active_extensions WHERE extension_id=? AND organization_id=? AND tenant_id=? AND active_digest=?`, active.ExtensionID, active.OrganizationID, active.TenantID, active.ActiveDigest)
	if err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_active_remove", "delete", err)
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageConflict, "extension_active_remove", "active", "active extension changed")
	}
	if err := tx.Commit(); err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_active_remove", "commit", err)
	}
	return transition, nil
}

func (store *Store) advanceExtensionTransition(ctx context.Context, tx *sql.Tx, current, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	stored, found, err := store.loadExtensionTransition(ctx, tx, current.TransitionID)
	if err != nil || !found || stored.Sequence != current.Sequence || stored.TransitionDigest != current.TransitionDigest ||
		next.TransitionID != current.TransitionID || next.IntentDigest != current.IntentDigest || next.Sequence != current.Sequence+1 {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageConflict, "extension_transition_advance", "state", "transition state changed")
	}
	canonical, digest, err := extensionlifecycle.CanonicalTransition(ctx, next)
	if err != nil || next.TransitionDigest != digest {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageDenied, "extension_transition_advance", "transition", "next transition is invalid")
	}
	result, err := tx.ExecContext(ctx, `UPDATE coh_extension_lifecycle_transitions SET phase=?,sequence=?,transition_digest=?,canonical=? WHERE transition_id=? AND sequence=? AND transition_digest=?`, next.Phase, next.Sequence, digest, canonical, current.TransitionID, current.Sequence, current.TransitionDigest)
	if err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_transition_advance", "update", err)
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageConflict, "extension_transition_advance", "state", "transition state changed")
	}
	return extensionlifecycle.DecodeTransition(ctx, canonical)
}
