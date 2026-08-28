package sqlite

import (
	"bytes"
	"context"
	"database/sql"

	"github.com/ArronJablonowski/COH/internal/domain/extensionlifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

func (store *Store) PutManifest(ctx context.Context, extensionID, digest string, canonical []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "extension_manifest_put"); err != nil {
		return err
	}
	validated, err := extensionlifecycle.DecodeEnvelope(ctx, canonical)
	if err != nil || validated.ManifestDigest() != digest || validated.Value().Manifest.ExtensionID != extensionID {
		return storageError(workflow.StorageDenied, "extension_manifest_put", "manifest", "manifest binding is invalid")
	}
	result, err := store.db.ExecContext(ctx, `INSERT OR IGNORE INTO coh_extension_manifests(manifest_digest,extension_id,canonical) VALUES(?,?,?)`, digest, extensionID, validated.CanonicalBytes())
	if err != nil {
		return normalizeError("extension_manifest_put", "insert", err)
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		var storedExtension string
		var stored []byte
		if err := store.db.QueryRowContext(ctx, `SELECT extension_id,canonical FROM coh_extension_manifests WHERE manifest_digest=?`, digest).Scan(&storedExtension, &stored); err != nil || storedExtension != extensionID || !bytes.Equal(stored, validated.CanonicalBytes()) {
			return storageError(workflow.StorageConflict, "extension_manifest_put", "manifest", "manifest digest was reused")
		}
	}
	return nil
}

func (store *Store) LoadManifest(ctx context.Context, digest string) ([]byte, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "extension_manifest_load"); err != nil {
		return nil, false, err
	}
	var extensionID string
	var canonical []byte
	err := store.db.QueryRowContext(ctx, `SELECT extension_id,canonical FROM coh_extension_manifests WHERE manifest_digest=?`, digest).Scan(&extensionID, &canonical)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, normalizeError("extension_manifest_load", "query", err)
	}
	validated, err := extensionlifecycle.DecodeEnvelope(ctx, canonical)
	if err != nil || validated.ManifestDigest() != digest || validated.Value().Manifest.ExtensionID != extensionID {
		return nil, false, storageError(workflow.StorageDenied, "extension_manifest_load", "integrity", "stored manifest failed verification")
	}
	return validated.CanonicalBytes(), true, nil
}

func (store *Store) loadLifecycleTransition(ctx context.Context, id string) (extensionlifecycle.Transition, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "extension_transition_load"); err != nil {
		return extensionlifecycle.Transition{}, false, err
	}
	return store.loadExtensionTransition(ctx, store.db, id)
}

func (store *Store) LoadReceipt(ctx context.Context, digest string) (extensionlifecycle.RegistrationReceipt, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "extension_receipt_load"); err != nil {
		return extensionlifecycle.RegistrationReceipt{}, false, err
	}
	return store.loadExtensionReceipt(ctx, store.db, digest)
}

func (store *Store) loadLifecycleActive(ctx context.Context, extensionID, organizationID, tenantID string) (extensionlifecycle.ActiveExtension, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "extension_active_load"); err != nil {
		return extensionlifecycle.ActiveExtension{}, false, err
	}
	return store.loadActiveExtension(ctx, store.db, extensionID, organizationID, tenantID)
}

func (store *Store) createLifecycleTransition(ctx context.Context, value extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "extension_transition_create"); err != nil {
		return extensionlifecycle.Transition{}, err
	}
	canonical, digest, err := extensionlifecycle.CanonicalTransition(ctx, value)
	if err != nil || value.TransitionDigest != digest {
		return extensionlifecycle.Transition{}, storageError(workflow.StorageInvalidInput, "extension_transition_create", "transition", "transition is invalid")
	}
	result, err := store.db.ExecContext(ctx, `INSERT OR IGNORE INTO coh_extension_lifecycle_transitions
(transition_id,extension_id,organization_id,tenant_id,direction,phase,sequence,intent_digest,transition_digest,canonical)
VALUES(?,?,?,?,?,?,?,?,?,?)`, value.TransitionID, value.ExtensionID, value.OrganizationID, value.TenantID, value.Direction, value.Phase, value.Sequence, value.IntentDigest, digest, canonical)
	if err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_transition_create", "insert", err)
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		existing, found, loadErr := store.loadExtensionTransition(ctx, store.db, value.TransitionID)
		if loadErr != nil || !found || existing.IntentDigest != value.IntentDigest {
			return extensionlifecycle.Transition{}, storageError(workflow.StorageConflict, "extension_transition_create", "replay", "transition identity was reused")
		}
		return existing, nil
	}
	return extensionlifecycle.DecodeTransition(ctx, canonical)
}

func (store *Store) advanceLifecycleTransition(ctx context.Context, current, next extensionlifecycle.Transition) (extensionlifecycle.Transition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.ready(ctx, "extension_transition_advance"); err != nil {
		return extensionlifecycle.Transition{}, err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_transition_advance", "transaction", err)
	}
	defer tx.Rollback()
	result, err := store.advanceExtensionTransition(ctx, tx, current, next)
	if err != nil {
		return extensionlifecycle.Transition{}, err
	}
	if err := tx.Commit(); err != nil {
		return extensionlifecycle.Transition{}, normalizeError("extension_transition_advance", "commit", err)
	}
	return result, nil
}

type extensionQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func (store *Store) loadExtensionTransition(ctx context.Context, query extensionQuerier, id string) (extensionlifecycle.Transition, bool, error) {
	var extension, organization, tenant, direction, phase, intent, digest string
	var sequence int64
	var canonical []byte
	err := query.QueryRowContext(ctx, `SELECT extension_id,organization_id,tenant_id,direction,phase,sequence,intent_digest,transition_digest,canonical FROM coh_extension_lifecycle_transitions WHERE transition_id=?`, id).Scan(&extension, &organization, &tenant, &direction, &phase, &sequence, &intent, &digest, &canonical)
	if err == sql.ErrNoRows {
		return extensionlifecycle.Transition{}, false, nil
	}
	if err != nil {
		return extensionlifecycle.Transition{}, false, normalizeError("extension_transition_load", "query", err)
	}
	value, err := extensionlifecycle.DecodeTransition(ctx, canonical)
	if err != nil || sequence <= 0 || value.TransitionID != id || value.ExtensionID != extension || value.OrganizationID != organization || value.TenantID != tenant || string(value.Direction) != direction || string(value.Phase) != phase || value.Sequence != uint64(sequence) || value.IntentDigest != intent || value.TransitionDigest != digest {
		return extensionlifecycle.Transition{}, false, storageError(workflow.StorageDenied, "extension_transition_load", "integrity", "stored transition failed verification")
	}
	return value, true, nil
}

func (store *Store) loadExtensionReceipt(ctx context.Context, query extensionQuerier, digest string) (extensionlifecycle.RegistrationReceipt, bool, error) {
	var receiptID, extension, organization, tenant, state, handle string
	var ordinal int64
	var canonical []byte
	err := query.QueryRowContext(ctx, `SELECT receipt_id,extension_id,organization_id,tenant_id,registration_ordinal,state,handle_digest,canonical FROM coh_extension_registration_receipts WHERE receipt_digest=?`, digest).Scan(&receiptID, &extension, &organization, &tenant, &ordinal, &state, &handle, &canonical)
	if err == sql.ErrNoRows {
		return extensionlifecycle.RegistrationReceipt{}, false, nil
	}
	if err != nil {
		return extensionlifecycle.RegistrationReceipt{}, false, normalizeError("extension_receipt_load", "query", err)
	}
	value, err := extensionlifecycle.DecodeReceipt(ctx, canonical)
	if err != nil || ordinal < 0 || value.ReceiptDigest != digest || value.ReceiptID != receiptID || value.ExtensionID != extension || value.OrganizationID != organization || value.TenantID != tenant || value.RegistrationOrdinal != uint64(ordinal) || value.State != state || value.RevocationHandle.HandleDigest != handle {
		return extensionlifecycle.RegistrationReceipt{}, false, storageError(workflow.StorageDenied, "extension_receipt_load", "integrity", "stored receipt failed verification")
	}
	return value, true, nil
}

func (store *Store) loadActiveExtension(ctx context.Context, query extensionQuerier, extension, organization, tenant string) (extensionlifecycle.ActiveExtension, bool, error) {
	var manifest, transition, digest string
	var revision int64
	var canonical []byte
	err := query.QueryRowContext(ctx, `SELECT manifest_digest,lifecycle_revision,transition_id,active_digest,canonical FROM coh_active_extensions WHERE extension_id=? AND organization_id=? AND tenant_id=?`, extension, organization, tenant).Scan(&manifest, &revision, &transition, &digest, &canonical)
	if err == sql.ErrNoRows {
		return extensionlifecycle.ActiveExtension{}, false, nil
	}
	if err != nil {
		return extensionlifecycle.ActiveExtension{}, false, normalizeError("extension_active_load", "query", err)
	}
	value, err := extensionlifecycle.DecodeActive(ctx, canonical)
	if err != nil || revision <= 0 || value.ExtensionID != extension || value.OrganizationID != organization || value.TenantID != tenant || value.ManifestDigest != manifest || value.LifecycleRevision != uint64(revision) || value.TransitionID != transition || value.ActiveDigest != digest {
		return extensionlifecycle.ActiveExtension{}, false, storageError(workflow.StorageDenied, "extension_active_load", "integrity", "stored active extension failed verification")
	}
	return value, true, nil
}
