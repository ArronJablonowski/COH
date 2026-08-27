package encryptedcas

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

// DisposePublished removes only the exact verified published object described
// by the caller's durable disposition plan. It never accepts a filesystem path
// and never removes ingestion metadata or manifests.
func (store *Store) DisposePublished(ctx context.Context, reference evidenceingest.PublishedObject,
	objectDigest string, keyRevision uint64) (bool, error) {
	if err := contextError(ctx); err != nil {
		return false, err
	}
	if store == nil || store.ensureRoot() != nil || keyRevision == 0 {
		return false, newError(InvalidInput, "disposition_request_invalid", nil)
	}
	if _, err := evidenceingest.PublishedObjectBindingDigest(reference); err != nil {
		return false, newError(InvalidInput, "disposition_reference_invalid", err)
	}
	path, locator, err := store.finalPath(reference.Case, reference.PlaintextDigest)
	if err != nil || locator != reference.LocatorDigest {
		return false, newError(Denied, "disposition_locator_invalid", err)
	}
	if _, err = os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, newError(Unavailable, "disposition_inspect_failed", err)
	}
	object, err := store.Resolve(ctx, reference)
	if err != nil {
		return false, err
	}
	want, err := evidenceingest.EncryptedObjectBindingDigest(object)
	if err != nil || want != objectDigest || object.KeyRevision != keyRevision {
		return false, newError(Denied, "disposition_object_mismatch", err)
	}
	if err = store.files.remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, newError(Unavailable, "disposition_remove_failed", err)
	}
	if err = store.files.syncDirectory(filepath.Dir(path)); err != nil {
		return false, newError(Unavailable, "disposition_sync_failed", err)
	}
	if _, err = os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return false, newError(Unavailable, "disposition_confirmation_failed", err)
	}
	return true, nil
}
