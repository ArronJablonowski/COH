package encryptedcas

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	fileMagic          = "COHCAS1\n"
	maximumHeaderBytes = 16 * 1024
	frameData          = byte(1)
	frameFooter        = byte(2)
)

type fileHeader struct {
	SchemaVersion           string `json:"schema_version"`
	ScopeDigest             string `json:"scope_digest"`
	PlaintextDigest         string `json:"plaintext_digest"`
	PlaintextLength         int64  `json:"plaintext_length"`
	MediaType               string `json:"media_type"`
	Classification          string `json:"classification"`
	EncryptionFormat        string `json:"encryption_format"`
	ChunkSize               uint32 `json:"chunk_size"`
	KeyProfile              string `json:"key_profile"`
	KeyProfileDigest        string `json:"key_profile_digest"`
	KeyReference            string `json:"key_reference"`
	KeyRevision             uint64 `json:"key_revision"`
	KeyAlgorithm            string `json:"key_algorithm"`
	WrappedKey              string `json:"wrapped_key"`
	WrappedKeyDigest        string `json:"wrapped_key_digest"`
	EncryptionContextDigest string `json:"encryption_context_digest"`
	NoncePrefix             string `json:"nonce_prefix"`
	CreatedAt               string `json:"created_at"`
}

type fileFooter struct {
	PlaintextDigest string `json:"plaintext_digest"`
	PlaintextLength int64  `json:"plaintext_length"`
	ChunkCount      uint64 `json:"chunk_count"`
}

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(Unavailable, "encoding_failed", err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(Denied, "canonicalization_failed", err)
	}
	return canonical, nil
}

func writeHeader(destination io.Writer, header fileHeader) ([]byte, error) {
	canonical, err := canonicalJSON(header)
	if err != nil || len(canonical) > maximumHeaderBytes {
		return nil, newError(Denied, "header_invalid", err)
	}
	if _, err = io.WriteString(destination, fileMagic); err != nil {
		return nil, err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
	if _, err = destination.Write(length[:]); err != nil {
		return nil, err
	}
	if _, err = destination.Write(canonical); err != nil {
		return nil, err
	}
	return canonical, nil
}

func readHeader(source io.Reader) (fileHeader, []byte, error) {
	magic := make([]byte, len(fileMagic))
	if _, err := io.ReadFull(source, magic); err != nil || string(magic) != fileMagic {
		return fileHeader{}, nil, newError(Denied, "file_magic_invalid", err)
	}
	var length [4]byte
	if _, err := io.ReadFull(source, length[:]); err != nil {
		return fileHeader{}, nil, newError(Denied, "header_length_invalid", err)
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > maximumHeaderBytes {
		return fileHeader{}, nil, newError(Denied, "header_length_invalid", nil)
	}
	canonical := make([]byte, size)
	if _, err := io.ReadFull(source, canonical); err != nil {
		return fileHeader{}, nil, newError(Denied, "header_truncated", err)
	}
	var header fileHeader
	decoder := json.NewDecoder(bytesReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&header); err != nil {
		return fileHeader{}, nil, newError(Denied, "header_encoding_invalid", err)
	}
	want, err := canonicalJSON(header)
	if err != nil || string(want) != string(canonical) {
		return fileHeader{}, nil, newError(Denied, "header_noncanonical", err)
	}
	return header, canonical, nil
}

func writeFrame(destination io.Writer, frameType byte, ciphertext []byte) error {
	if len(ciphertext) == 0 || len(ciphertext) > 2<<20 {
		return newError(Denied, "frame_length_invalid", nil)
	}
	header := []byte{frameType, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[1:], uint32(len(ciphertext)))
	if _, err := destination.Write(header); err != nil {
		return err
	}
	_, err := destination.Write(ciphertext)
	return err
}

func readFrame(source io.Reader) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(source, header); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size == 0 || size > 2<<20 {
		return 0, nil, newError(Denied, "frame_length_invalid", nil)
	}
	value := make([]byte, size)
	if _, err := io.ReadFull(source, value); err != nil {
		return 0, nil, err
	}
	return header[0], value, nil
}

func frameNonce(prefix []byte, counter uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[8:], counter)
	return nonce
}

func frameAAD(headerDigest []byte, frameType byte, counter uint32) []byte {
	value := make([]byte, 37)
	copy(value, headerDigest)
	value[32] = frameType
	binary.BigEndian.PutUint32(value[33:], counter)
	return value
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func encodeBinary(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
func decodeBinary(value string, expected int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != expected {
		return nil, newError(Denied, "binary_field_invalid", err)
	}
	return decoded, nil
}

func decodeBoundedBinary(value string, minimum, maximum int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum {
		return nil, newError(Denied, "binary_field_invalid", err)
	}
	return decoded, nil
}

type byteReader struct {
	value  []byte
	offset int
}

func bytesReader(value []byte) *byteReader { return &byteReader{value: value} }
func (reader *byteReader) Read(output []byte) (int, error) {
	if reader.offset == len(reader.value) {
		return 0, io.EOF
	}
	count := copy(output, reader.value[reader.offset:])
	reader.offset += count
	return count, nil
}

func ensureEOF(source io.Reader) error {
	var extra [1]byte
	count, err := source.Read(extra[:])
	if count != 0 || !errors.Is(err, io.EOF) {
		return newError(Denied, "trailing_data", err)
	}
	return nil
}
