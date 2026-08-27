package encryptedcas

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

func TestOpenIngestedArtifactRequiresExactReceiptAndVerifiesPlaintext(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	store := newTestEncryptedStore(t, t.TempDir(), testWrappingKey("artifact-reader"), now)
	payload := []byte("receipt-bound immutable evidence")
	object := publishRedactionBytes(t, store, payload, "text/plain", "restricted", now)
	receipt := mappingIngestionReceipt(t, receiptArtifact(object), object, now)

	reader, err := store.OpenIngestedArtifact(t.Context(), receipt)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := io.ReadAll(reader)
	closeErr := reader.Close()
	if err != nil || closeErr != nil || !bytes.Equal(resolved, payload) {
		t.Fatalf("resolved=%q err=%v close=%v", resolved, err, closeErr)
	}

	for name, mutate := range map[string]func(*evidenceingest.Receipt){
		"artifact digest": func(value *evidenceingest.Receipt) { value.Artifact.Digest = testCASDigest([]byte("other")) },
		"ciphertext": func(value *evidenceingest.Receipt) {
			value.EncryptedArtifact.CiphertextDigest = testCASDigest([]byte("other ciphertext"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			tampered := receipt
			mutate(&tampered)
			tampered.ReceiptDigest = ""
			tampered.ReceiptDigest, _ = evidenceingest.ReceiptBindingDigest(tampered)
			if _, openErr := store.OpenIngestedArtifact(t.Context(), tampered); openErr == nil {
				t.Fatal("tampered receipt was accepted")
			}
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = store.OpenIngestedArtifact(canceled, receipt); CodeOf(err) != Canceled {
		t.Fatalf("canceled code=%s err=%v", CodeOf(err), err)
	}
}

func receiptArtifact(object evidenceingest.EncryptedObject) domain.ArtifactRef {
	return domain.ArtifactRef{Digest: object.PlaintextDigest, MediaType: object.MediaType,
		Classification: object.Classification, Length: object.PlaintextLength}
}
