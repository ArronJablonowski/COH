package encryptedcas

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"io"
	"regexp"
)

var (
	keyTokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	keyDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type AESKeyManager struct {
	keyReference string
	keyRevision  uint64
	wrappingKey  []byte
	random       io.Reader
}

func NewAESKeyManager(keyReference string, keyRevision uint64, wrappingKey []byte,
	random io.Reader) (*AESKeyManager, error) {
	if !keyTokenPattern.MatchString(keyReference) || keyRevision == 0 || len(wrappingKey) != DataKeyBytes {
		return nil, newError(InvalidInput, "key_configuration_invalid", nil)
	}
	if random == nil {
		random = cryptorand.Reader
	}
	return &AESKeyManager{keyReference: keyReference, keyRevision: keyRevision,
		wrappingKey: append([]byte{}, wrappingKey...), random: random}, nil
}

func (manager *AESKeyManager) GenerateDataKey(ctx context.Context, keyContext KeyContext) (DataKey, error) {
	if err := contextError(ctx); err != nil {
		return DataKey{}, err
	}
	if manager == nil || len(manager.wrappingKey) != DataKeyBytes || !validKeyContext(keyContext) {
		return DataKey{}, newError(Denied, "key_context_invalid", nil)
	}
	plaintext := make([]byte, DataKeyBytes)
	if _, err := io.ReadFull(manager.random, plaintext); err != nil {
		zero(plaintext)
		return DataKey{}, newError(Unavailable, "data_key_generation_failed", err)
	}
	aead, err := manager.aead()
	if err != nil {
		zero(plaintext)
		return DataKey{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(manager.random, nonce); err != nil {
		zero(plaintext)
		return DataKey{}, newError(Unavailable, "wrap_nonce_generation_failed", err)
	}
	aad, err := canonicalJSON(keyContext)
	if err != nil {
		zero(plaintext)
		return DataKey{}, err
	}
	wrapped := append(nonce, aead.Seal(nil, nonce, plaintext, aad)...)
	return DataKey{KeyReference: manager.keyReference, KeyRevision: manager.keyRevision,
		KeyAlgorithm: "aes-256-gcm", Plaintext: plaintext, Wrapped: wrapped}, nil
}

func (manager *AESKeyManager) UnwrapDataKey(ctx context.Context, wrapped WrappedDataKey) ([]byte, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if manager == nil || len(manager.wrappingKey) != DataKeyBytes || !validKeyContext(wrapped.Context) ||
		wrapped.KeyReference != manager.keyReference || wrapped.KeyRevision != manager.keyRevision ||
		wrapped.KeyAlgorithm != "aes-256-gcm" {
		return nil, newError(Denied, "wrapped_key_binding_invalid", nil)
	}
	aead, err := manager.aead()
	if err != nil {
		return nil, err
	}
	if len(wrapped.Wrapped) != aead.NonceSize()+DataKeyBytes+aead.Overhead() {
		return nil, newError(Denied, "wrapped_key_length_invalid", nil)
	}
	nonce := wrapped.Wrapped[:aead.NonceSize()]
	aad, err := canonicalJSON(wrapped.Context)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, wrapped.Wrapped[aead.NonceSize():], aad)
	if err != nil || len(plaintext) != DataKeyBytes {
		zero(plaintext)
		return nil, newError(Denied, "wrapped_key_authentication_failed", err)
	}
	return plaintext, nil
}

func (manager *AESKeyManager) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(manager.wrappingKey)
	if err != nil {
		return nil, newError(Unavailable, "wrapping_key_unavailable", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, newError(Unavailable, "wrapping_cipher_unavailable", err)
	}
	return aead, nil
}

func validKeyContext(value KeyContext) bool {
	return keyTokenPattern.MatchString(value.KeyProfile) && keyDigestPattern.MatchString(value.KeyProfileDigest) &&
		keyDigestPattern.MatchString(value.EncryptionContextDigest) && value.Case.OrganizationID != "" &&
		value.Case.TenantID != "" && value.Case.CaseID != ""
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ KeyManager = (*AESKeyManager)(nil)
