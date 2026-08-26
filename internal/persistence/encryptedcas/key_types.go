// Package encryptedcas implements the encrypted filesystem content-addressed
// store. Raw key material is confined to this persistence adapter package.
package encryptedcas

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
)

const DataKeyBytes = 32

type KeyContext struct {
	Case                    domain.CaseRef
	KeyProfile              string
	KeyProfileDigest        string
	EncryptionContextDigest string
}

// DataKey is short-lived adapter-local material returned for one stage. The
// caller must overwrite Plaintext immediately after constructing the AEAD.
type DataKey struct {
	KeyReference string
	KeyRevision  uint64
	KeyAlgorithm string
	Plaintext    []byte
	Wrapped      []byte
}

type WrappedDataKey struct {
	Context      KeyContext
	KeyReference string
	KeyRevision  uint64
	KeyAlgorithm string
	Wrapped      []byte
}

type KeyManager interface {
	GenerateDataKey(context.Context, KeyContext) (DataKey, error)
	UnwrapDataKey(context.Context, WrappedDataKey) ([]byte, error)
}
