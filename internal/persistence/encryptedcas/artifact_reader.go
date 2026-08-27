package encryptedcas

import (
	"context"
	"errors"
	"io"

	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

// OpenIngestedArtifact opens only the exact immutable artifact bound by a
// canonical ingestion receipt. It deliberately does not expose a generic
// published-object plaintext reader.
func (store *Store) OpenIngestedArtifact(ctx context.Context,
	receipt evidenceingest.Receipt) (io.ReadCloser, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, newError(InvalidInput, "artifact_reader_store_invalid", nil)
	}
	if _, err := evidenceingest.CanonicalReceipt(receipt); err != nil {
		return nil, newError(InvalidInput, "artifact_reader_receipt_invalid", err)
	}
	object, err := store.Resolve(ctx, receipt.EncryptedArtifact)
	if err != nil || object.Case != receipt.Case || object.PlaintextDigest != receipt.Artifact.Digest ||
		object.PlaintextLength != receipt.Artifact.Length || object.MediaType != receipt.Artifact.MediaType ||
		object.Classification != receipt.Artifact.Classification {
		return nil, newError(Denied, "artifact_reader_binding_invalid", err)
	}
	reader, err := store.openRedactionReader(ctx, object)
	if err != nil {
		return nil, newError(Denied, "artifact_reader_decryption_failed", err)
	}
	return &contextReadCloser{ctx: ctx, reader: reader}, nil
}

type contextReadCloser struct {
	ctx    context.Context
	reader *plaintextReader
}

func (reader *contextReadCloser) Read(destination []byte) (int, error) {
	if reader == nil || reader.reader == nil {
		return 0, errors.New("encrypted CAS artifact reader is closed")
	}
	return reader.reader.ReadContext(reader.ctx, destination)
}

func (reader *contextReadCloser) Close() error {
	if reader != nil && reader.reader != nil {
		reader.reader.close()
		reader.reader = nil
	}
	return nil
}
