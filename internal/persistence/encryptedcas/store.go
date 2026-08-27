package encryptedcas

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

const (
	headerSchemaVersion = "coh.encrypted-cas-header/v1"
	defaultChunkSize    = uint32(64 * 1024)
)

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type Config struct {
	Root           string
	Keys           KeyManager
	Random         io.Reader
	Clock          func() time.Time
	ChunkSize      uint32
	RedactionRules RedactionRuleResolver
}

type Store struct {
	root           string
	keys           KeyManager
	random         io.Reader
	clock          func() time.Time
	chunkSize      uint32
	files          fileOperations
	redactionRules RedactionRuleResolver
}

func Open(config Config) (*Store, error) {
	if !filepath.IsAbs(config.Root) || filepath.Clean(config.Root) != config.Root || config.Keys == nil {
		return nil, newError(InvalidInput, "store_configuration_invalid", nil)
	}
	if config.Random == nil {
		config.Random = cryptorand.Reader
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.ChunkSize == 0 {
		config.ChunkSize = defaultChunkSize
	}
	if config.ChunkSize < 4096 || config.ChunkSize > 1<<20 {
		return nil, newError(InvalidInput, "chunk_size_invalid", nil)
	}
	store := &Store{root: config.Root, keys: config.Keys, random: config.Random,
		clock: config.Clock, chunkSize: config.ChunkSize, files: defaultFileOperations(), redactionRules: config.RedactionRules}
	if err := store.ensureRoot(); err != nil {
		return nil, err
	}
	for _, name := range []string{"staging", "objects", "quarantine"} {
		if err := ensurePrivateDirectory(filepath.Join(store.root, name)); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (store *Store) Stage(ctx context.Context, request evidenceingest.StageRequest,
	source evidenceingest.Source) (evidenceingest.EncryptedObject, error) {
	if err := contextError(ctx); err != nil {
		return evidenceingest.EncryptedObject{}, err
	}
	if store == nil || source == nil || store.ensureRoot() != nil {
		return evidenceingest.EncryptedObject{}, newError(Denied, "stage_dependencies_invalid", nil)
	}
	contextDigest, err := evidenceingest.EncryptionContextBindingDigest(request)
	if err != nil || contextDigest != request.EncryptionContextDigest {
		return evidenceingest.EncryptedObject{}, newError(InvalidInput, "stage_request_invalid", err)
	}
	now := store.clock().UTC()
	if now.IsZero() || !request.Deadline.After(now) {
		return evidenceingest.EncryptedObject{}, newError(Timeout, "stage_deadline_elapsed", nil)
	}
	opCtx, cancel := context.WithTimeout(ctx, request.Deadline.Sub(now))
	defer cancel()
	locator, path, err := store.newStagePath()
	if err != nil {
		return evidenceingest.EncryptedObject{}, err
	}
	file, err := store.files.create(path)
	if err != nil {
		return evidenceingest.EncryptedObject{}, newError(Unavailable, "stage_create_failed", err)
	}
	cleanup := func() { _ = store.files.close(file); _ = store.files.remove(path) }
	keyContext := KeyContext{Case: request.Case, KeyProfile: request.KeyProfile,
		KeyProfileDigest: request.KeyProfileDigest, EncryptionContextDigest: contextDigest}
	dataKey, err := store.keys.GenerateDataKey(opCtx, keyContext)
	if err != nil || !validDataKey(dataKey) {
		cleanup()
		zero(dataKey.Plaintext)
		return evidenceingest.EncryptedObject{}, normalize("data_key_unavailable", err)
	}
	aead, err := dataAEAD(dataKey.Plaintext)
	zero(dataKey.Plaintext)
	if err != nil {
		cleanup()
		return evidenceingest.EncryptedObject{}, err
	}
	noncePrefix := make([]byte, 8)
	if _, err = io.ReadFull(store.random, noncePrefix); err != nil {
		cleanup()
		return evidenceingest.EncryptedObject{}, newError(Unavailable, "nonce_generation_failed", err)
	}
	header := fileHeader{SchemaVersion: headerSchemaVersion, ScopeDigest: scopeDigest(request.Case),
		PlaintextDigest: request.ExpectedDigest, PlaintextLength: request.ExpectedLength,
		MediaType: request.MediaType, Classification: request.Classification,
		EncryptionFormat: evidenceingest.EncryptionFormatVersion, ChunkSize: store.chunkSize,
		KeyProfile: request.KeyProfile, KeyProfileDigest: request.KeyProfileDigest,
		KeyReference: dataKey.KeyReference, KeyRevision: dataKey.KeyRevision, KeyAlgorithm: dataKey.KeyAlgorithm,
		WrappedKey: encodeBinary(dataKey.Wrapped), WrappedKeyDigest: rawDigest(dataKey.Wrapped),
		EncryptionContextDigest: contextDigest, NoncePrefix: encodeBinary(noncePrefix),
		CreatedAt: formatTime(now)}
	cipherHash := sha256.New()
	destination := io.MultiWriter(store.files.writer(file), cipherHash)
	headerBytes, err := writeHeader(destination, header)
	if err != nil {
		cleanup()
		return evidenceingest.EncryptedObject{}, newError(Unavailable, "header_write_failed", err)
	}
	headerSum := sha256.Sum256(headerBytes)
	plainHash := sha256.New()
	remaining, counter := request.ExpectedLength, uint32(0)
	buffer := make([]byte, store.chunkSize)
	defer zero(buffer)
	for remaining > 0 {
		if err = contextError(opCtx); err != nil {
			cleanup()
			return evidenceingest.EncryptedObject{}, err
		}
		wanted := int64(len(buffer))
		if remaining < wanted {
			wanted = remaining
		}
		if err = readExact(opCtx, source, buffer[:wanted]); err != nil {
			cleanup()
			return evidenceingest.EncryptedObject{}, err
		}
		plainHash.Write(buffer[:wanted])
		sealed := aead.Seal(nil, frameNonce(noncePrefix, counter), buffer[:wanted],
			frameAAD(headerSum[:], frameData, counter))
		if err = writeFrame(destination, frameData, sealed); err != nil {
			cleanup()
			return evidenceingest.EncryptedObject{}, newError(Unavailable, "frame_write_failed", err)
		}
		remaining -= wanted
		counter++
	}
	if err = sourceEOF(opCtx, source); err != nil {
		cleanup()
		return evidenceingest.EncryptedObject{}, err
	}
	plainDigest := "sha256:" + hex.EncodeToString(plainHash.Sum(nil))
	if plainDigest != request.ExpectedDigest {
		cleanup()
		return evidenceingest.EncryptedObject{}, newError(Denied, "plaintext_digest_mismatch", nil)
	}
	footerBytes, err := canonicalJSON(fileFooter{PlaintextDigest: plainDigest,
		PlaintextLength: request.ExpectedLength, ChunkCount: uint64(counter)})
	if err != nil {
		cleanup()
		return evidenceingest.EncryptedObject{}, err
	}
	footer := aead.Seal(nil, frameNonce(noncePrefix, counter), footerBytes,
		frameAAD(headerSum[:], frameFooter, counter))
	if err = writeFrame(destination, frameFooter, footer); err != nil {
		cleanup()
		return evidenceingest.EncryptedObject{}, newError(Unavailable, "footer_write_failed", err)
	}
	if err = store.files.sync(file); err != nil {
		cleanup()
		return evidenceingest.EncryptedObject{}, newError(Unavailable, "stage_sync_failed", err)
	}
	info, statErr := store.files.stat(file)
	closeErr := store.files.close(file)
	if statErr != nil || closeErr != nil {
		_ = store.files.remove(path)
		return evidenceingest.EncryptedObject{}, newError(Unavailable, "stage_close_failed", errors.Join(statErr, closeErr))
	}
	object := evidenceingest.EncryptedObject{SchemaVersion: evidenceingest.EncryptedObjectSchemaVersion,
		ContractVersion: evidenceingest.ContractVersion, Status: evidenceingest.Staged, Case: request.Case,
		PlaintextDigest: plainDigest, PlaintextLength: request.ExpectedLength,
		CiphertextDigest: "sha256:" + hex.EncodeToString(cipherHash.Sum(nil)), CiphertextLength: info.Size(),
		MediaType: request.MediaType, Classification: request.Classification,
		EncryptionFormat: evidenceingest.EncryptionFormatVersion, ChunkSize: store.chunkSize,
		ChunkCount: uint64(counter), KeyReference: dataKey.KeyReference, KeyRevision: dataKey.KeyRevision,
		KeyAlgorithm: dataKey.KeyAlgorithm, WrappedKeyDigest: rawDigest(dataKey.Wrapped),
		EncryptionContextDigest: contextDigest, LocatorDigest: locator, CreatedAt: now}
	return object, nil
}

func validDataKey(value DataKey) bool {
	return keyTokenPattern.MatchString(value.KeyReference) && value.KeyRevision > 0 &&
		value.KeyAlgorithm == "aes-256-gcm" && len(value.Plaintext) == DataKeyBytes && len(value.Wrapped) > DataKeyBytes
}

func dataAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, newError(Denied, "data_key_invalid", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, newError(Unavailable, "data_cipher_unavailable", err)
	}
	return aead, nil
}

func readExact(ctx context.Context, source evidenceingest.Source, destination []byte) error {
	offset := 0
	for offset < len(destination) {
		if err := contextError(ctx); err != nil {
			return err
		}
		count, err := source.ReadContext(ctx, destination[offset:])
		if contextErr := contextError(ctx); contextErr != nil {
			return contextErr
		}
		if count < 0 || count > len(destination)-offset || count == 0 && err == nil {
			return newError(Denied, "source_reader_invalid", err)
		}
		offset += count
		if err != nil {
			if errors.Is(err, io.EOF) && offset == len(destination) {
				return nil
			}
			return newError(Denied, "source_length_mismatch", err)
		}
	}
	return nil
}

func sourceEOF(ctx context.Context, source evidenceingest.Source) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	var extra [1]byte
	count, err := source.ReadContext(ctx, extra[:])
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	if count != 0 || !errors.Is(err, io.EOF) {
		return newError(Denied, "source_length_mismatch", err)
	}
	return nil
}

func (store *Store) newStagePath() (string, string, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(store.random, random); err != nil {
		return "", "", newError(Unavailable, "stage_identity_failed", err)
	}
	locator := rawDigest(random)
	return locator, filepath.Join(store.root, "staging", locator[len("sha256:"):]+".stage"), nil
}

func (store *Store) ensureRoot() error {
	info, err := os.Lstat(store.root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return newError(Denied, "root_security_invalid", err)
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return newError(Unavailable, "directory_create_failed", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return newError(Denied, "directory_security_invalid", err)
	}
	return nil
}

func scopeDigest(scope domain.CaseRef) string {
	return rawDigest([]byte("COH-ENCRYPTED-CAS-SCOPE-V1\x00" + scope.OrganizationID + "\x00" +
		scope.TenantID + "\x00" + scope.CaseID))
}

func formatTime(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05.000000000Z") }

func normalize(reason string, err error) error {
	if err == nil {
		return newError(Denied, reason, nil)
	}
	if errors.Is(err, context.Canceled) {
		return newError(Canceled, "request_canceled", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", err)
	}
	var typed *Error
	if errors.As(err, &typed) {
		return newError(typed.code, reason, err)
	}
	return newError(Unavailable, reason, err)
}

var _ evidenceingest.EncryptedCAS = (*Store)(nil)
