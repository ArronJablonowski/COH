package encryptedcas

import (
	"context"
	"errors"
	"io"

	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

const maximumManifestBytes = int64(1 << 20)

// ResolveArtifactManifest decrypts and validates one exact immutable ingestion
// manifest without exposing a generic plaintext-read capability.
func (store *Store) ResolveArtifactManifest(ctx context.Context,
	receipt evidenceingest.Receipt) (evidenceingest.ArtifactManifest, error) {
	if err := contextError(ctx); err != nil {
		return evidenceingest.ArtifactManifest{}, err
	}
	if store == nil || receipt.Manifest.Length <= 0 || receipt.Manifest.Length > maximumManifestBytes {
		return evidenceingest.ArtifactManifest{}, newError(InvalidInput, "manifest_request_invalid", nil)
	}
	if _, err := evidenceingest.CanonicalReceipt(receipt); err != nil {
		return evidenceingest.ArtifactManifest{}, newError(InvalidInput, "manifest_receipt_invalid", err)
	}
	object, err := store.Resolve(ctx, receipt.EncryptedManifest)
	if err != nil || object.Case != receipt.Case || object.PlaintextDigest != receipt.Manifest.Digest ||
		object.PlaintextLength != receipt.Manifest.Length || object.MediaType != receipt.Manifest.MediaType ||
		object.Classification != receipt.Manifest.Classification {
		return evidenceingest.ArtifactManifest{}, newError(Denied, "manifest_object_invalid", err)
	}
	reader, err := store.openRedactionReader(ctx, object)
	if err != nil {
		return evidenceingest.ArtifactManifest{}, newError(Denied, "manifest_decryption_failed", err)
	}
	defer reader.close()
	canonical := make([]byte, int(receipt.Manifest.Length))
	defer zero(canonical)
	if err = readSourceExact(ctx, reader, canonical); err != nil {
		return evidenceingest.ArtifactManifest{}, newError(Denied, "manifest_read_failed", err)
	}
	var trailing [1]byte
	if count, finishErr := reader.ReadContext(ctx, trailing[:]); count != 0 || !errors.Is(finishErr, io.EOF) {
		return evidenceingest.ArtifactManifest{}, newError(Denied, "manifest_verification_failed", finishErr)
	}
	manifest, err := evidenceingest.DecodeManifest(canonical)
	if err != nil || manifest.Case != receipt.Case || manifest.Artifact != receipt.Artifact ||
		manifest.ProvenanceDigest != receipt.ManifestProvenanceDigest ||
		receipt.Manifest.Classification != receipt.Artifact.Classification {
		return evidenceingest.ArtifactManifest{}, newError(Denied, "manifest_binding_invalid", err)
	}
	return manifest, nil
}
