package encryptedcas

import (
	"bytes"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

func TestDisposePublishedRejectsSubstitutionAndConvergesAfterRemoval(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	store := newTestEncryptedStore(t, root, testWrappingKey("disposition"), now)
	plaintext := []byte("exact encrypted object disposition")
	request := stageRequest(t, plaintext, now)
	staged, err := store.Stage(t.Context(), request, &sliceSource{data: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	published, _, err := store.Publish(t.Context(), staged)
	if err != nil {
		t.Fatal(err)
	}
	reference := publishedReference(published)
	objectDigest, err := evidenceingest.EncryptedObjectBindingDigest(published)
	if err != nil {
		t.Fatal(err)
	}
	wrongDigest := testCASDigest([]byte("substituted encrypted object"))
	if _, err = store.DisposePublished(t.Context(), reference, wrongDigest,
		published.KeyRevision); CodeOf(err) != Denied {
		t.Fatalf("substituted digest code=%s err=%v", CodeOf(err), err)
	}
	if _, err = store.DisposePublished(t.Context(), reference, objectDigest,
		published.KeyRevision+1); CodeOf(err) != Denied {
		t.Fatalf("substituted key revision code=%s err=%v", CodeOf(err), err)
	}
	if resolved, resolveErr := store.Resolve(t.Context(), reference); resolveErr != nil ||
		resolved.PlaintextDigest != published.PlaintextDigest {
		t.Fatalf("substitution removed object=%+v err=%v", resolved, resolveErr)
	}
	removed, err := store.DisposePublished(t.Context(), reference, objectDigest, published.KeyRevision)
	if err != nil || !removed || len(objectFiles(t, root)) != 0 {
		t.Fatalf("removed=%v files=%v err=%v", removed, objectFiles(t, root), err)
	}
	removed, err = store.DisposePublished(t.Context(), reference, objectDigest, published.KeyRevision)
	if err != nil || removed {
		t.Fatalf("absent replay removed=%v err=%v", removed, err)
	}
	if bytes.Contains([]byte(objectDigest), plaintext) {
		t.Fatal("object digest exposed plaintext")
	}
}
