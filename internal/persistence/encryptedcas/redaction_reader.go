package encryptedcas

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"

	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

type plaintextReader struct {
	file       *os.File
	source     io.Reader
	info       os.FileInfo
	object     evidenceingest.EncryptedObject
	aead       cipher.AEAD
	nonce      []byte
	headerSum  [sha256.Size]byte
	cipherHash hash.Hash
	plainHash  hash.Hash
	remaining  int64
	counter    uint32
	buffer     []byte
	offset     int
	done       bool
}

func (store *Store) openRedactionReader(ctx context.Context,
	request evidenceingest.EncryptedObject) (*plaintextReader, error) {
	path, err := store.objectPath(request)
	if err != nil {
		return nil, err
	}
	file, info, err := store.files.openRegular(path)
	if err != nil {
		return nil, err
	}
	fail := func(reason string, cause error) (*plaintextReader, error) {
		_ = file.Close()
		return nil, newError(Denied, reason, cause)
	}
	cipherHash := sha256.New()
	source := io.TeeReader(file, cipherHash)
	header, headerBytes, err := readHeader(source)
	if err != nil || !headerMatchesObject(header, request) {
		return fail("redaction_source_header_invalid", err)
	}
	nonce, err := decodeBinary(header.NoncePrefix, 8)
	if err != nil {
		return fail("redaction_source_nonce_invalid", err)
	}
	wrapped, err := decodeBoundedBinary(header.WrappedKey, 32, 16*1024)
	if err != nil || rawDigest(wrapped) != header.WrappedKeyDigest {
		return fail("redaction_source_wrapped_key_invalid", err)
	}
	keyContext := KeyContext{Case: request.Case, KeyProfile: header.KeyProfile,
		KeyProfileDigest: header.KeyProfileDigest, EncryptionContextDigest: header.EncryptionContextDigest}
	key, err := store.keys.UnwrapDataKey(ctx, WrappedDataKey{Context: keyContext, KeyReference: header.KeyReference,
		KeyRevision: header.KeyRevision, KeyAlgorithm: header.KeyAlgorithm, Wrapped: wrapped})
	if err != nil {
		zero(key)
		return fail("redaction_source_key_unavailable", err)
	}
	aead, err := dataAEAD(key)
	zero(key)
	if err != nil {
		return fail("redaction_source_cipher_invalid", err)
	}
	return &plaintextReader{file: file, source: source, info: info, object: request, aead: aead, nonce: nonce,
		headerSum: sha256.Sum256(headerBytes), cipherHash: cipherHash, plainHash: sha256.New(),
		remaining: request.PlaintextLength}, nil
}

func (reader *plaintextReader) ReadContext(ctx context.Context, destination []byte) (int, error) {
	if err := contextError(ctx); err != nil {
		reader.close()
		return 0, err
	}
	if len(destination) == 0 {
		return 0, nil
	}
	if reader.done {
		return 0, io.EOF
	}
	written := 0
	for written < len(destination) {
		if reader.offset < len(reader.buffer) {
			count := copy(destination[written:], reader.buffer[reader.offset:])
			reader.offset += count
			written += count
			if reader.offset == len(reader.buffer) {
				zero(reader.buffer)
				reader.buffer, reader.offset = nil, 0
			}
			continue
		}
		if reader.remaining == 0 {
			err := reader.finish()
			if written > 0 && err == io.EOF {
				return written, nil
			}
			return written, err
		}
		if err := reader.nextFrame(ctx); err != nil {
			reader.close()
			return written, err
		}
	}
	return written, nil
}

func (reader *plaintextReader) nextFrame(ctx context.Context) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	frameType, ciphertext, err := readFrame(reader.source)
	if err != nil || frameType != frameData {
		return newError(Denied, "redaction_source_frame_invalid", err)
	}
	plaintext, err := reader.aead.Open(nil, frameNonce(reader.nonce, reader.counter), ciphertext,
		frameAAD(reader.headerSum[:], frameData, reader.counter))
	wanted := int64(reader.object.ChunkSize)
	if reader.remaining < wanted {
		wanted = reader.remaining
	}
	if err != nil || int64(len(plaintext)) != wanted {
		zero(plaintext)
		return newError(Denied, "redaction_source_authentication_failed", err)
	}
	reader.plainHash.Write(plaintext)
	reader.buffer = plaintext
	reader.remaining -= wanted
	reader.counter++
	return nil
}

func (reader *plaintextReader) finish() error {
	if reader.done {
		return io.EOF
	}
	frameType, ciphertext, err := readFrame(reader.source)
	if err != nil || frameType != frameFooter {
		reader.close()
		return newError(Denied, "redaction_source_footer_invalid", err)
	}
	plaintext, err := reader.aead.Open(nil, frameNonce(reader.nonce, reader.counter), ciphertext,
		frameAAD(reader.headerSum[:], frameFooter, reader.counter))
	if err != nil {
		reader.close()
		return newError(Denied, "redaction_source_footer_authentication_failed", err)
	}
	footer, err := decodeFooter(plaintext)
	zero(plaintext)
	if err != nil || footer.PlaintextDigest != reader.object.PlaintextDigest ||
		footer.PlaintextLength != reader.object.PlaintextLength || footer.ChunkCount != uint64(reader.counter) ||
		ensureEOF(reader.source) != nil || reader.info.Size() != reader.object.CiphertextLength ||
		"sha256:"+hex.EncodeToString(reader.cipherHash.Sum(nil)) != reader.object.CiphertextDigest ||
		"sha256:"+hex.EncodeToString(reader.plainHash.Sum(nil)) != reader.object.PlaintextDigest {
		reader.close()
		return newError(Denied, "redaction_source_verification_failed", err)
	}
	reader.done = true
	reader.closeFile()
	return io.EOF
}

func (reader *plaintextReader) close() {
	if reader == nil {
		return
	}
	zero(reader.buffer)
	reader.buffer = nil
	reader.done = true
	reader.closeFile()
}
func (reader *plaintextReader) closeFile() {
	if reader.file != nil {
		_ = reader.file.Close()
		reader.file = nil
	}
}

func readSourceExact(ctx context.Context, source interface {
	ReadContext(context.Context, []byte) (int, error)
}, destination []byte) error {
	offset := 0
	for offset < len(destination) {
		count, err := source.ReadContext(ctx, destination[offset:])
		if count < 0 || count > len(destination)-offset || count == 0 && err == nil {
			return newError(Denied, "redaction_source_reader_invalid", err)
		}
		offset += count
		if err != nil && !(errors.Is(err, io.EOF) && offset == len(destination)) {
			return err
		}
	}
	return nil
}
