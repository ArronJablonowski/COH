package encryptedcas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

func (store *Store) Verify(ctx context.Context, object evidenceingest.EncryptedObject) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if store == nil || store.ensureRoot() != nil {
		return newError(Denied, "verify_store_invalid", nil)
	}
	if _, err := evidenceingest.EncryptedObjectBindingDigest(object); err != nil {
		return newError(InvalidInput, "verify_object_invalid", err)
	}
	path, err := store.objectPath(object)
	if err != nil {
		return err
	}
	file, info, err := store.files.openRegular(path)
	if err != nil {
		return err
	}
	defer file.Close()
	cipherHash := sha256.New()
	source := io.TeeReader(file, cipherHash)
	header, headerBytes, err := readHeader(source)
	if err != nil || !headerMatchesObject(header, object) {
		return newError(Denied, "object_header_invalid", err)
	}
	noncePrefix, err := decodeBinary(header.NoncePrefix, 8)
	if err != nil {
		return err
	}
	wrapped, err := decodeBoundedBinary(header.WrappedKey, 32, 16*1024)
	if err != nil || rawDigest(wrapped) != header.WrappedKeyDigest {
		return newError(Denied, "wrapped_key_invalid", err)
	}
	keyContext := KeyContext{Case: object.Case, KeyProfile: header.KeyProfile,
		KeyProfileDigest: header.KeyProfileDigest, EncryptionContextDigest: header.EncryptionContextDigest}
	plaintextKey, err := store.keys.UnwrapDataKey(ctx, WrappedDataKey{Context: keyContext,
		KeyReference: header.KeyReference, KeyRevision: header.KeyRevision,
		KeyAlgorithm: header.KeyAlgorithm, Wrapped: wrapped})
	if err != nil {
		zero(plaintextKey)
		return normalize("data_key_unwrap_failed", err)
	}
	aead, err := dataAEAD(plaintextKey)
	zero(plaintextKey)
	if err != nil {
		return err
	}
	headerSum := sha256.Sum256(headerBytes)
	plainHash := sha256.New()
	remaining := object.PlaintextLength
	for counter := uint32(0); uint64(counter) < object.ChunkCount; counter++ {
		if err = contextError(ctx); err != nil {
			return err
		}
		frameType, ciphertext, readErr := readFrame(source)
		if readErr != nil || frameType != frameData {
			return newError(Denied, "data_frame_invalid", readErr)
		}
		plaintext, openErr := aead.Open(nil, frameNonce(noncePrefix, counter), ciphertext,
			frameAAD(headerSum[:], frameData, counter))
		wanted := int64(object.ChunkSize)
		if remaining < wanted {
			wanted = remaining
		}
		if openErr != nil || int64(len(plaintext)) != wanted {
			zero(plaintext)
			return newError(Denied, "data_frame_authentication_failed", openErr)
		}
		plainHash.Write(plaintext)
		zero(plaintext)
		remaining -= wanted
	}
	if remaining != 0 {
		return newError(Denied, "plaintext_length_invalid", nil)
	}
	footerType, footerCiphertext, err := readFrame(source)
	if err != nil || footerType != frameFooter {
		return newError(Denied, "footer_frame_invalid", err)
	}
	footerPlaintext, err := aead.Open(nil, frameNonce(noncePrefix, uint32(object.ChunkCount)), footerCiphertext,
		frameAAD(headerSum[:], frameFooter, uint32(object.ChunkCount)))
	if err != nil {
		return newError(Denied, "footer_authentication_failed", err)
	}
	footer, err := decodeFooter(footerPlaintext)
	zero(footerPlaintext)
	if err != nil || footer.PlaintextDigest != object.PlaintextDigest ||
		footer.PlaintextLength != object.PlaintextLength || footer.ChunkCount != object.ChunkCount {
		return newError(Denied, "footer_invalid", err)
	}
	if err = ensureEOF(source); err != nil {
		return err
	}
	if info.Size() != object.CiphertextLength ||
		"sha256:"+hex.EncodeToString(cipherHash.Sum(nil)) != object.CiphertextDigest ||
		"sha256:"+hex.EncodeToString(plainHash.Sum(nil)) != object.PlaintextDigest {
		return newError(Denied, "object_digest_invalid", nil)
	}
	return nil
}

func decodeFooter(value []byte) (fileFooter, error) {
	var footer fileFooter
	decoder := json.NewDecoder(bytesReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&footer); err != nil {
		return fileFooter{}, err
	}
	canonical, err := canonicalJSON(footer)
	if err != nil || string(canonical) != string(value) {
		return fileFooter{}, newError(Denied, "footer_noncanonical", err)
	}
	return footer, nil
}

func (store *Store) Prepare(ctx context.Context,
	staged evidenceingest.EncryptedObject) (evidenceingest.PublishedObject, bool, error) {
	if staged.Status != evidenceingest.Staged && staged.Status != evidenceingest.Verified {
		return evidenceingest.PublishedObject{}, false, newError(InvalidInput, "prepare_status_invalid", nil)
	}
	if err := store.Verify(ctx, staged); err != nil {
		return evidenceingest.PublishedObject{}, false, err
	}
	finalPath, locator, err := store.finalPath(staged.Case, staged.PlaintextDigest)
	if err != nil {
		return evidenceingest.PublishedObject{}, false, err
	}
	if _, statErr := os.Lstat(finalPath); statErr == nil {
		existing, inspectErr := store.inspectPublished(finalPath, staged.Case, locator)
		if inspectErr != nil || !samePlainObject(existing, staged) {
			return evidenceingest.PublishedObject{}, false, newError(Conflict, "published_object_conflict", inspectErr)
		}
		if verifyErr := store.Verify(ctx, existing); verifyErr != nil {
			return evidenceingest.PublishedObject{}, false, verifyErr
		}
		return referenceFromObject(existing), true, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return evidenceingest.PublishedObject{}, false, newError(Unavailable, "published_object_inspect_failed", statErr)
	}
	planned := staged
	planned.Status = evidenceingest.Published
	planned.LocatorDigest = locator
	return referenceFromObject(planned), false, nil
}

func (store *Store) Publish(ctx context.Context, staged evidenceingest.EncryptedObject) (evidenceingest.EncryptedObject, bool, error) {
	if staged.Status != evidenceingest.Staged && staged.Status != evidenceingest.Verified {
		return evidenceingest.EncryptedObject{}, false, newError(InvalidInput, "publish_status_invalid", nil)
	}
	if err := store.Verify(ctx, staged); err != nil {
		return evidenceingest.EncryptedObject{}, false, err
	}
	stagePath, err := store.objectPath(staged)
	if err != nil {
		return evidenceingest.EncryptedObject{}, false, err
	}
	finalPath, locator, err := store.finalPath(staged.Case, staged.PlaintextDigest)
	if err != nil {
		return evidenceingest.EncryptedObject{}, false, err
	}
	if err = ensurePrivateDirectory(filepath.Dir(finalPath)); err != nil {
		return evidenceingest.EncryptedObject{}, false, err
	}
	if err = store.files.link(stagePath, finalPath); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return evidenceingest.EncryptedObject{}, false, newError(Unavailable, "publish_link_failed", err)
		}
		existing, resolveErr := store.inspectPublished(finalPath, staged.Case, locator)
		if resolveErr != nil || !samePlainObject(existing, staged) {
			return evidenceingest.EncryptedObject{}, false, newError(Conflict, "published_object_conflict", resolveErr)
		}
		if verifyErr := store.Verify(ctx, existing); verifyErr != nil {
			return evidenceingest.EncryptedObject{}, false, verifyErr
		}
		if removeErr := store.files.remove(stagePath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return evidenceingest.EncryptedObject{}, false, newError(Unavailable, "stage_cleanup_failed", removeErr)
		}
		return existing, true, nil
	}
	if err = store.files.syncDirectory(filepath.Dir(finalPath)); err != nil {
		return evidenceingest.EncryptedObject{}, false, err
	}
	if err = store.files.remove(stagePath); err != nil {
		return evidenceingest.EncryptedObject{}, false, newError(Unavailable, "stage_unlink_failed", err)
	}
	published := staged
	published.Status = evidenceingest.Published
	published.LocatorDigest = locator
	if err = store.Verify(ctx, published); err != nil {
		return evidenceingest.EncryptedObject{}, false, err
	}
	return published, false, nil
}

func (store *Store) Resolve(ctx context.Context, reference evidenceingest.PublishedObject) (evidenceingest.EncryptedObject, error) {
	if err := contextError(ctx); err != nil {
		return evidenceingest.EncryptedObject{}, err
	}
	if _, err := evidenceingest.PublishedObjectBindingDigest(reference); err != nil {
		return evidenceingest.EncryptedObject{}, newError(InvalidInput, "resolve_reference_invalid", err)
	}
	path, locator, err := store.finalPath(reference.Case, reference.PlaintextDigest)
	if err != nil || locator != reference.LocatorDigest {
		return evidenceingest.EncryptedObject{}, newError(Denied, "resolve_locator_invalid", err)
	}
	object, err := store.inspectPublished(path, reference.Case, locator)
	if err != nil || object.PlaintextLength != reference.PlaintextLength ||
		object.CiphertextDigest != reference.CiphertextDigest || object.CiphertextLength != reference.CiphertextLength ||
		object.EncryptionFormat != reference.EncryptionFormat ||
		object.EncryptionContextDigest != reference.EncryptionContextDigest {
		return evidenceingest.EncryptedObject{}, newError(Denied, "resolved_object_invalid", err)
	}
	if err = store.Verify(ctx, object); err != nil {
		return evidenceingest.EncryptedObject{}, err
	}
	return object, nil
}

func (store *Store) Find(ctx context.Context,
	pending evidenceingest.PendingObject) (evidenceingest.EncryptedObject, bool, error) {
	if err := contextError(ctx); err != nil {
		return evidenceingest.EncryptedObject{}, false, err
	}
	if evidenceingest.ValidatePendingObject(pending) != nil {
		return evidenceingest.EncryptedObject{}, false, newError(InvalidInput, "pending_object_invalid", nil)
	}
	path, locator, err := store.finalPath(pending.Case, pending.PlaintextDigest)
	if err != nil || locator != pending.LocatorDigest {
		return evidenceingest.EncryptedObject{}, false, newError(Denied, "pending_locator_invalid", err)
	}
	if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
		return evidenceingest.EncryptedObject{}, false, nil
	} else if statErr != nil {
		return evidenceingest.EncryptedObject{}, false, newError(Unavailable, "pending_object_inspect_failed", statErr)
	}
	object, err := store.inspectPublished(path, pending.Case, locator)
	if err != nil || object.PlaintextLength != pending.PlaintextLength || object.MediaType != pending.MediaType ||
		object.Classification != pending.Classification ||
		object.EncryptionContextDigest != pending.EncryptionContextDigest {
		return evidenceingest.EncryptedObject{}, false, newError(Denied, "pending_object_mismatch", err)
	}
	if err = store.Verify(ctx, object); err != nil {
		return evidenceingest.EncryptedObject{}, false, err
	}
	return object, true, nil
}

func (store *Store) Abandon(_ context.Context, object evidenceingest.EncryptedObject) error {
	if object.Status != evidenceingest.Staged && object.Status != evidenceingest.Verified {
		return newError(Denied, "abandon_published_denied", nil)
	}
	path, err := store.objectPath(object)
	if err != nil {
		return err
	}
	if err = store.files.remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return newError(Unavailable, "stage_abandon_failed", err)
	}
	return nil
}

func (store *Store) inspectPublished(path string, scope domain.CaseRef, locator string) (evidenceingest.EncryptedObject, error) {
	file, info, err := store.files.openRegular(path)
	if err != nil {
		return evidenceingest.EncryptedObject{}, err
	}
	defer file.Close()
	hash := sha256.New()
	source := io.TeeReader(file, hash)
	header, _, err := readHeader(source)
	if err != nil {
		return evidenceingest.EncryptedObject{}, err
	}
	if header.SchemaVersion != headerSchemaVersion || header.ScopeDigest != scopeDigest(scope) ||
		header.PlaintextLength <= 0 || header.PlaintextLength > 1<<30 ||
		header.ChunkSize < 4096 || header.ChunkSize > 1<<20 {
		return evidenceingest.EncryptedObject{}, newError(Denied, "object_header_invalid", nil)
	}
	if _, err = io.Copy(io.Discard, source); err != nil {
		return evidenceingest.EncryptedObject{}, newError(Denied, "object_read_failed", err)
	}
	wrapped, err := decodeBoundedBinary(header.WrappedKey, 32, 16*1024)
	createdAt, timeErr := time.Parse("2006-01-02T15:04:05.000000000Z", header.CreatedAt)
	if err != nil || timeErr != nil {
		return evidenceingest.EncryptedObject{}, newError(Denied, "object_header_invalid", errors.Join(err, timeErr))
	}
	chunks := uint64((header.PlaintextLength + int64(header.ChunkSize) - 1) / int64(header.ChunkSize))
	return evidenceingest.EncryptedObject{SchemaVersion: evidenceingest.EncryptedObjectSchemaVersion,
		ContractVersion: evidenceingest.ContractVersion, Status: evidenceingest.Published, Case: scope,
		PlaintextDigest: header.PlaintextDigest, PlaintextLength: header.PlaintextLength,
		CiphertextDigest: "sha256:" + hex.EncodeToString(hash.Sum(nil)), CiphertextLength: info.Size(),
		MediaType: header.MediaType, Classification: header.Classification,
		EncryptionFormat: header.EncryptionFormat, ChunkSize: header.ChunkSize, ChunkCount: chunks,
		KeyReference: header.KeyReference, KeyRevision: header.KeyRevision, KeyAlgorithm: header.KeyAlgorithm,
		WrappedKeyDigest: rawDigest(wrapped), EncryptionContextDigest: header.EncryptionContextDigest,
		LocatorDigest: locator, CreatedAt: createdAt.UTC()}, nil
}

func headerMatchesObject(header fileHeader, object evidenceingest.EncryptedObject) bool {
	return header.SchemaVersion == headerSchemaVersion && header.ScopeDigest == scopeDigest(object.Case) &&
		header.PlaintextDigest == object.PlaintextDigest && header.PlaintextLength == object.PlaintextLength &&
		header.MediaType == object.MediaType && header.Classification == object.Classification &&
		header.EncryptionFormat == object.EncryptionFormat && header.ChunkSize == object.ChunkSize &&
		header.KeyReference == object.KeyReference && header.KeyRevision == object.KeyRevision &&
		header.KeyAlgorithm == object.KeyAlgorithm && header.WrappedKeyDigest == object.WrappedKeyDigest &&
		header.EncryptionContextDigest == object.EncryptionContextDigest && header.CreatedAt == formatTime(object.CreatedAt)
}

func samePlainObject(left, right evidenceingest.EncryptedObject) bool {
	return left.Case == right.Case && left.PlaintextDigest == right.PlaintextDigest &&
		left.PlaintextLength == right.PlaintextLength && left.MediaType == right.MediaType &&
		left.Classification == right.Classification && left.EncryptionContextDigest == right.EncryptionContextDigest
}

func referenceFromObject(value evidenceingest.EncryptedObject) evidenceingest.PublishedObject {
	return evidenceingest.PublishedObject{Case: value.Case, PlaintextDigest: value.PlaintextDigest,
		PlaintextLength: value.PlaintextLength, CiphertextDigest: value.CiphertextDigest,
		CiphertextLength: value.CiphertextLength, EncryptionFormat: value.EncryptionFormat,
		EncryptionContextDigest: value.EncryptionContextDigest, LocatorDigest: value.LocatorDigest}
}

func (store *Store) objectPath(object evidenceingest.EncryptedObject) (string, error) {
	switch object.Status {
	case evidenceingest.Staged, evidenceingest.Verified:
		if len(object.LocatorDigest) != 71 || object.LocatorDigest[:7] != "sha256:" {
			return "", newError(InvalidInput, "stage_locator_invalid", nil)
		}
		return filepath.Join(store.root, "staging", object.LocatorDigest[7:]+".stage"), nil
	case evidenceingest.Published:
		path, locator, err := store.finalPath(object.Case, object.PlaintextDigest)
		if err != nil || locator != object.LocatorDigest {
			return "", newError(Denied, "published_locator_invalid", err)
		}
		return path, nil
	default:
		return "", newError(InvalidInput, "object_status_invalid", nil)
	}
}

func (store *Store) finalPath(scope domain.CaseRef, digestValue string) (string, string, error) {
	if !uuidPattern.MatchString(scope.OrganizationID) || !uuidPattern.MatchString(scope.TenantID) ||
		!uuidPattern.MatchString(scope.CaseID) || len(digestValue) != 71 || digestValue[:7] != "sha256:" {
		return "", "", newError(InvalidInput, "object_identity_invalid", nil)
	}
	scopeValue := scopeDigest(scope)[7:]
	digestHex := digestValue[7:]
	relative := filepath.Join("objects", scopeValue, digestHex[:2], digestHex+".cohcas")
	locator := rawDigest([]byte("COH-ENCRYPTED-CAS-LOCATOR-V1\x00" + relative))
	return filepath.Join(store.root, relative), locator, nil
}

func realOpenRegular(path string) (*os.File, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o600 {
		return nil, nil, newError(Denied, "object_file_invalid", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, newError(Unavailable, "object_open_failed", err)
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) {
		file.Close()
		return nil, nil, newError(Denied, "object_file_changed", err)
	}
	return file, after, nil
}

func realSyncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return newError(Unavailable, "directory_open_failed", err)
	}
	err = directory.Sync()
	closeErr := directory.Close()
	if err != nil || closeErr != nil {
		return newError(Unavailable, "directory_sync_failed", errors.Join(err, closeErr))
	}
	return nil
}
