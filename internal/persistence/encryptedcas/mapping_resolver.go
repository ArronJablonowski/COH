package encryptedcas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

const maximumRedactionMappingBytes = int64(8 << 20)

// ResolveRedactionMapping decrypts and validates one exact typed redaction
// mapping. It intentionally does not expose a generic plaintext read API.
func (store *Store) ResolveRedactionMapping(ctx context.Context,
	receipt evidenceingest.Receipt) (redaction.Mapping, error) {
	if err := contextError(ctx); err != nil {
		return redaction.Mapping{}, err
	}
	if store == nil || receipt.Artifact.Length <= 0 || receipt.Artifact.Length > maximumRedactionMappingBytes ||
		receipt.Artifact.MediaType != "application/vnd.coh.redaction-mapping+json" {
		return redaction.Mapping{}, newError(InvalidInput, "mapping_request_invalid", nil)
	}
	if _, err := evidenceingest.CanonicalReceipt(receipt); err != nil {
		return redaction.Mapping{}, newError(InvalidInput, "mapping_receipt_invalid", err)
	}
	object, err := store.Resolve(ctx, receipt.EncryptedArtifact)
	if err != nil || object.Case != receipt.Case || object.PlaintextDigest != receipt.Artifact.Digest ||
		object.PlaintextLength != receipt.Artifact.Length || object.MediaType != receipt.Artifact.MediaType ||
		object.Classification != receipt.Artifact.Classification {
		return redaction.Mapping{}, newError(Denied, "mapping_object_invalid", err)
	}
	reader, err := store.openRedactionReader(ctx, object)
	if err != nil {
		return redaction.Mapping{}, newError(Denied, "mapping_decryption_failed", err)
	}
	defer reader.close()
	canonical := make([]byte, int(receipt.Artifact.Length))
	defer zero(canonical)
	if err = readSourceExact(ctx, reader, canonical); err != nil {
		return redaction.Mapping{}, newError(Denied, "mapping_read_failed", err)
	}
	var trailing [1]byte
	if count, finishErr := reader.ReadContext(ctx, trailing[:]); count != 0 || !errors.Is(finishErr, io.EOF) {
		return redaction.Mapping{}, newError(Denied, "mapping_verification_failed", finishErr)
	}
	plaintextHash := sha256.Sum256(canonical)
	plaintextDigest := "sha256:" + hex.EncodeToString(plaintextHash[:])
	mapping, err := redaction.DecodeMapping(canonical)
	if err != nil || mapping.Case != receipt.Case || plaintextDigest != receipt.Artifact.Digest {
		return redaction.Mapping{}, newError(Denied, "mapping_binding_invalid", err)
	}
	return mapping, nil
}
