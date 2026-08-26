package tamperaudit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
)

func BuildRecord(event Event, sequence uint64, previousHash, appendedAt string) (Record, error) {
	eventBytes, err := CanonicalEvent(event)
	if err != nil || sequence == 0 || !digestPattern.MatchString(previousHash) {
		return Record{}, ErrInvalidInput
	}
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion,
		OrganizationID: event.OrganizationID, TenantID: event.TenantID, Sequence: sequence,
		Event: event, EventDigest: digest(eventBytes), PreviousChainHash: previousHash,
		ChainHash: GenesisHash, AppendedAt: appendedAt}
	if err := ValidateRecord(record); err != nil {
		return Record{}, err
	}
	preimage, err := recordPreimage(record)
	if err != nil {
		return Record{}, err
	}
	record.ChainHash = digest(domainMessage(RecordHashDomain, preimage))
	return record, ValidateRecord(record)
}

func VerifyRecord(record Record, expectedSequence uint64, expectedPreviousHash string) error {
	if err := ValidateRecord(record); err != nil || record.Sequence != expectedSequence ||
		subtle.ConstantTimeCompare([]byte(record.PreviousChainHash), []byte(expectedPreviousHash)) != 1 {
		return ErrIntegrity
	}
	eventBytes, err := CanonicalEvent(record.Event)
	if err != nil || subtle.ConstantTimeCompare([]byte(record.EventDigest), []byte(digest(eventBytes))) != 1 {
		return ErrIntegrity
	}
	preimage, err := recordPreimage(record)
	if err != nil || subtle.ConstantTimeCompare([]byte(record.ChainHash), []byte(digest(domainMessage(RecordHashDomain, preimage)))) != 1 {
		return ErrIntegrity
	}
	return nil
}

func SignCheckpoint(checkpoint Checkpoint, privateKey ed25519.PrivateKey) (Checkpoint, error) {
	checkpoint.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if len(privateKey) != ed25519.PrivateKeySize || ValidateCheckpoint(checkpoint) != nil {
		return Checkpoint{}, ErrInvalidInput
	}
	message, err := checkpointMessage(checkpoint)
	if err != nil {
		return Checkpoint{}, err
	}
	checkpoint.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	return checkpoint, nil
}

func VerifyCheckpoint(checkpoint Checkpoint, publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize || ValidateCheckpoint(checkpoint) != nil {
		return ErrIntegrity
	}
	signature, _ := base64.RawURLEncoding.DecodeString(checkpoint.Signature)
	message, err := checkpointMessage(checkpoint)
	if err != nil || !ed25519.Verify(publicKey, message, signature) {
		return ErrIntegrity
	}
	return nil
}

func recordPreimage(record Record) ([]byte, error) {
	record.ChainHash = GenesisHash
	return CanonicalRecord(record)
}

func checkpointMessage(checkpoint Checkpoint) ([]byte, error) {
	checkpoint.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	canonicalBytes, err := CanonicalCheckpoint(checkpoint)
	if err != nil {
		return nil, err
	}
	return domainMessage(CheckpointDomain, canonicalBytes), nil
}

func domainMessage(domain string, canonicalBytes []byte) []byte {
	message := make([]byte, len(domain)+8+len(canonicalBytes))
	copy(message, domain)
	binary.BigEndian.PutUint64(message[len(domain):], uint64(len(canonicalBytes)))
	copy(message[len(domain)+8:], canonicalBytes)
	return message
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
