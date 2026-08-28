package profilecomposition

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

// CanonicalLayer returns the exact immutable bytes and digest publishers and
// reviewers sign. It validates the complete data-only layer first.
func CanonicalLayer(ctx context.Context, layer Layer) ([]byte, string, error) {
	if err := contextError(ctx); err != nil {
		return nil, "", err
	}
	if layer.SchemaVersion != LayerSchemaVersion || layer.ContractVersion != ContractVersion {
		return nil, "", newError(Unsupported, "unsupported_contract")
	}
	if err := validateLayer(layer); err != nil {
		return nil, "", err
	}
	encoded, err := json.Marshal(layer)
	if err != nil {
		return nil, "", newError(InvalidInput, "layer_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, "", newError(InvalidInput, "layer_encoding")
	}
	return canonical, digestBytes(layerDigestDomain, canonical), nil
}

// SignatureMessage returns the domain-separated digest message for an Ed25519
// signer. It contains no private key or signing authority.
func SignatureMessage(layerDigest string) ([]byte, error) {
	if !validDigest(layerDigest) {
		return nil, newError(InvalidInput, "layer_digest")
	}
	raw, err := hex.DecodeString(layerDigest[len("sha256:"):])
	if err != nil || len(raw) != 32 {
		return nil, newError(InvalidInput, "layer_digest")
	}
	message := make([]byte, 0, len(signatureDomain)+len(raw))
	message = append(message, signatureDomain...)
	message = append(message, raw...)
	return message, nil
}
