package encryptedcas

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

type sliceSource struct {
	data   []byte
	offset int
}

func (source *sliceSource) ReadContext(ctx context.Context, output []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if source.offset == len(source.data) {
		return 0, io.EOF
	}
	count := copy(output, source.data[source.offset:])
	source.offset += count
	return count, nil
}

type blockingSource struct{}

func (blockingSource) ReadContext(ctx context.Context, _ []byte) (int, error) {
	<-ctx.Done()
	return 0, ctx.Err()
}

func TestEncryptedCASStagesVerifiesPublishesResolvesAndDeduplicates(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	store := newTestEncryptedStore(t, root, testWrappingKey("primary"), now)
	plaintext := bytes.Repeat([]byte("sensitive evidence frame\n"), 4097)
	request := stageRequest(t, plaintext, now)
	staged, err := store.Stage(t.Context(), request, &sliceSource{data: plaintext})
	if err != nil || staged.Status != evidenceingest.Staged || staged.PlaintextDigest != request.ExpectedDigest ||
		staged.PlaintextLength != int64(len(plaintext)) {
		t.Fatalf("stage=%+v err=%v", staged, err)
	}
	if err = store.Verify(t.Context(), staged); err != nil {
		t.Fatalf("verify staged: %v", err)
	}
	if candidates, candidateErr := store.Staged(t.Context(), time.Now().UTC().Add(time.Hour), 10); candidateErr != nil || len(candidates) != 1 || candidates[0].LocatorDigest != staged.LocatorDigest {
		t.Fatalf("staged candidates=%+v err=%v", candidates, candidateErr)
	}
	planned, replayed, err := store.Prepare(t.Context(), staged)
	if err != nil || replayed || planned.LocatorDigest == staged.LocatorDigest {
		t.Fatalf("prepare=%+v replayed=%v err=%v", planned, replayed, err)
	}
	pending := evidenceingest.PendingObject{Role: evidenceingest.ArtifactPublication, Case: staged.Case,
		PlaintextDigest: staged.PlaintextDigest, PlaintextLength: staged.PlaintextLength,
		MediaType: staged.MediaType, Classification: staged.Classification,
		EncryptionContextDigest: staged.EncryptionContextDigest, LocatorDigest: planned.LocatorDigest,
		CreatedAt: staged.CreatedAt}
	if _, found, findErr := store.Find(t.Context(), pending); findErr != nil || found {
		t.Fatalf("pre-publication find found=%v err=%v", found, findErr)
	}
	published, replayed, err := store.Publish(t.Context(), staged)
	if err != nil || replayed || published.Status != evidenceingest.Published {
		t.Fatalf("publish=%+v replayed=%v err=%v", published, replayed, err)
	}
	reference := publishedReference(published)
	if foundObject, found, findErr := store.Find(t.Context(), pending); findErr != nil || !found ||
		foundObject.CiphertextDigest != published.CiphertextDigest {
		t.Fatalf("post-publication find=%+v found=%v err=%v", foundObject, found, findErr)
	}
	resolved, err := store.Resolve(t.Context(), reference)
	if err != nil || resolved.CiphertextDigest != published.CiphertextDigest {
		t.Fatalf("resolve=%+v err=%v", resolved, err)
	}
	files := objectFiles(t, root)
	if len(files) != 1 {
		t.Fatalf("published files=%v", files)
	}
	ciphertext, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, plaintext[:1024]) {
		t.Fatal("plaintext evidence appeared in the at-rest object")
	}

	second, err := store.Stage(t.Context(), request, &sliceSource{data: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	deduplicated, replayed, err := store.Publish(t.Context(), second)
	if err != nil || !replayed || deduplicated.CiphertextDigest != published.CiphertextDigest {
		t.Fatalf("deduplicate=%+v replayed=%v err=%v", deduplicated, replayed, err)
	}
	if entries, readErr := os.ReadDir(filepath.Join(root, "staging")); readErr != nil || len(entries) != 0 {
		t.Fatalf("staging entries=%d err=%v", len(entries), readErr)
	}
}

func TestEncryptedCASRejectsLengthDigestTamperScopeAndKeyLoss(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	key := testWrappingKey("primary")
	store := newTestEncryptedStore(t, root, key, now)
	plaintext := []byte("immutable evidence with authenticated metadata")
	request := stageRequest(t, plaintext, now)

	wrongLength := request
	wrongLength.ExpectedLength++
	wrongLength.EncryptionContextDigest, _ = evidenceingest.EncryptionContextBindingDigest(wrongLength)
	if _, err := store.Stage(t.Context(), wrongLength, &sliceSource{data: plaintext}); CodeOf(err) != Denied {
		t.Fatalf("length mismatch code=%s err=%v", CodeOf(err), err)
	}
	wrongDigest := request
	wrongDigest.ExpectedDigest = testCASDigest([]byte("other"))
	wrongDigest.EncryptionContextDigest, _ = evidenceingest.EncryptionContextBindingDigest(wrongDigest)
	if _, err := store.Stage(t.Context(), wrongDigest, &sliceSource{data: plaintext}); CodeOf(err) != Denied {
		t.Fatalf("digest mismatch code=%s err=%v", CodeOf(err), err)
	}

	staged, err := store.Stage(t.Context(), request, &sliceSource{data: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	published, _, err := store.Publish(t.Context(), staged)
	if err != nil {
		t.Fatal(err)
	}
	reference := publishedReference(published)
	foreign := reference
	foreign.Case.CaseID = casUUID("foreign-case")
	if _, err = store.Resolve(t.Context(), foreign); CodeOf(err) != Denied {
		t.Fatalf("foreign scope code=%s err=%v", CodeOf(err), err)
	}

	restartedWithWrongKey := newTestEncryptedStore(t, root, testWrappingKey("lost-replacement"), now)
	if _, err = restartedWithWrongKey.Resolve(t.Context(), reference); CodeOf(err) != Denied {
		t.Fatalf("key loss code=%s err=%v", CodeOf(err), err)
	}

	path := objectFiles(t, root)[0]
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0x80
	if err = os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Resolve(t.Context(), reference); CodeOf(err) != Denied {
		t.Fatalf("ciphertext tamper code=%s err=%v", CodeOf(err), err)
	}
}

func TestEncryptedCASCancellationLeavesNoStageOrReference(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	store := newTestEncryptedStore(t, root, testWrappingKey("primary"), now)
	request := stageRequest(t, []byte("expected bytes"), now)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := store.Stage(ctx, request, blockingSource{}); CodeOf(err) != Timeout {
		t.Fatalf("cancellation code=%s err=%v", CodeOf(err), err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "staging"))
	if err != nil || len(entries) != 0 || len(objectFiles(t, root)) != 0 {
		t.Fatalf("partial publication entries=%d err=%v", len(entries), err)
	}
}

func TestAESKeyManagerBindsContextAndRejectsWrappedTamper(t *testing.T) {
	manager, err := NewAESKeyManager("operator_evidence_key", 7, testWrappingKey("primary"),
		bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)))
	if err != nil {
		t.Fatal(err)
	}
	keyContext := KeyContext{Case: domain.CaseRef{OrganizationID: casUUID("org"), TenantID: casUUID("tenant"),
		CaseID: casUUID("case")}, KeyProfile: "operator_evidence", KeyProfileDigest: testCASDigest([]byte("profile")),
		EncryptionContextDigest: testCASDigest([]byte("context"))}
	dataKey, err := manager.GenerateDataKey(t.Context(), keyContext)
	if err != nil {
		t.Fatal(err)
	}
	wrapper := WrappedDataKey{Context: keyContext, KeyReference: dataKey.KeyReference,
		KeyRevision: dataKey.KeyRevision, KeyAlgorithm: dataKey.KeyAlgorithm, Wrapped: append([]byte{}, dataKey.Wrapped...)}
	unwrapped, err := manager.UnwrapDataKey(t.Context(), wrapper)
	if err != nil || !bytes.Equal(unwrapped, dataKey.Plaintext) {
		t.Fatalf("unwrap err=%v", err)
	}
	zero(unwrapped)
	wrapper.Context.Case.CaseID = casUUID("other-case")
	if _, err = manager.UnwrapDataKey(t.Context(), wrapper); CodeOf(err) != Denied {
		t.Fatalf("changed context code=%s err=%v", CodeOf(err), err)
	}
	wrapper.Context = keyContext
	wrapper.Wrapped[len(wrapper.Wrapped)-1] ^= 1
	if _, err = manager.UnwrapDataKey(t.Context(), wrapper); CodeOf(err) != Denied {
		t.Fatalf("wrapped tamper code=%s err=%v", CodeOf(err), err)
	}
	zero(dataKey.Plaintext)
}

func newTestEncryptedStore(t *testing.T, root string, key []byte, now time.Time) *Store {
	t.Helper()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	manager, err := NewAESKeyManager("operator_evidence_key", 1, key,
		bytes.NewReader(bytes.Repeat([]byte{0x35}, 1<<20)))
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(Config{Root: root, Keys: manager,
		Random: bytes.NewReader(bytes.Repeat([]byte{0x71}, 1<<20)), Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func stageRequest(t *testing.T, plaintext []byte, now time.Time) evidenceingest.StageRequest {
	t.Helper()
	value := evidenceingest.StageRequest{Case: domain.CaseRef{OrganizationID: casUUID("org"),
		TenantID: casUUID("tenant"), CaseID: casUUID("case")}, ExpectedDigest: testCASDigest(plaintext),
		ExpectedLength: int64(len(plaintext)), MediaType: "application/octet-stream", Classification: "restricted",
		KeyProfile: "operator_evidence", KeyProfileDigest: testCASDigest([]byte("key-profile")), Deadline: now.Add(time.Hour)}
	value.EncryptionContextDigest, _ = evidenceingest.EncryptionContextBindingDigest(value)
	return value
}

func publishedReference(value evidenceingest.EncryptedObject) evidenceingest.PublishedObject {
	return evidenceingest.PublishedObject{Case: value.Case, PlaintextDigest: value.PlaintextDigest,
		PlaintextLength: value.PlaintextLength, CiphertextDigest: value.CiphertextDigest,
		CiphertextLength: value.CiphertextLength, EncryptionFormat: value.EncryptionFormat,
		EncryptionContextDigest: value.EncryptionContextDigest, LocatorDigest: value.LocatorDigest}
}

func objectFiles(t *testing.T, root string) []string {
	t.Helper()
	result := []string{}
	err := filepath.WalkDir(filepath.Join(root, "objects"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			result = append(result, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testWrappingKey(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return append([]byte{}, sum[:]...)
}
func testCASDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func casUUID(value string) string {
	sum := sha256.Sum256([]byte(value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
