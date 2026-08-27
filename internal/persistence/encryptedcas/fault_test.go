package encryptedcas

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

var errInjectedIO = errors.New("injected I/O failure")

type failReader struct {
	remaining int
	value     byte
}

func (reader *failReader) Read(output []byte) (int, error) {
	if reader.remaining == 0 {
		return 0, errInjectedIO
	}
	count := len(output)
	if count > reader.remaining {
		count = reader.remaining
	}
	for index := range output[:count] {
		output[index] = reader.value
	}
	reader.remaining -= count
	if count < len(output) {
		return count, errInjectedIO
	}
	return count, nil
}

type failingSource struct {
	first bool
}

func (source *failingSource) ReadContext(ctx context.Context, output []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if source.first {
		return 0, errInjectedIO
	}
	source.first = true
	count := copy(output, []byte("partial"))
	return count, errInjectedIO
}

func TestEncryptedCASGenerationAndSourceFaultsLeaveNoStages(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	plaintext := []byte("fault-boundary evidence")
	tests := []struct {
		name   string
		store  func(*testing.T, string) *Store
		source evidenceingest.Source
		code   Code
	}{
		{name: "stage identity", store: func(t *testing.T, root string) *Store {
			return faultStore(t, root, bytes.NewReader(bytes.Repeat([]byte{0x41}, 4096)), &failReader{}, now)
		}, source: &sliceSource{data: plaintext}, code: Unavailable},
		{name: "data key", store: func(t *testing.T, root string) *Store {
			return faultStore(t, root, &failReader{}, bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096)), now)
		}, source: &sliceSource{data: plaintext}, code: Unavailable},
		{name: "nonce", store: func(t *testing.T, root string) *Store {
			return faultStore(t, root, bytes.NewReader(bytes.Repeat([]byte{0x43}, 4096)),
				&failReader{remaining: 32, value: 0x44}, now)
		}, source: &sliceSource{data: plaintext}, code: Unavailable},
		{name: "source read", store: func(t *testing.T, root string) *Store {
			return faultStore(t, root, bytes.NewReader(bytes.Repeat([]byte{0x45}, 4096)),
				bytes.NewReader(bytes.Repeat([]byte{0x46}, 4096)), now)
		}, source: &failingSource{}, code: Denied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			store := test.store(t, root)
			if _, err := store.Stage(t.Context(), stageRequest(t, plaintext, now), test.source); CodeOf(err) != test.code {
				t.Fatalf("code=%s err=%v", CodeOf(err), err)
			}
			entries, err := os.ReadDir(filepath.Join(root, "staging"))
			if err != nil || len(entries) != 0 || len(objectFiles(t, root)) != 0 {
				t.Fatalf("stages=%d objects=%d err=%v", len(entries), len(objectFiles(t, root)), err)
			}
		})
	}
}

func TestEncryptedCASRejectsUnsafeRootAndStagingEntries(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	manager, err := NewAESKeyManager("operator_evidence_key", 1, testWrappingKey("primary"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Open(Config{Root: root, Keys: manager}); CodeOf(err) != Denied {
		t.Fatalf("unsafe root code=%s err=%v", CodeOf(err), err)
	}
	if err = os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(Config{Root: root, Keys: manager, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "staging", "unexpected"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Staged(t.Context(), now.Add(time.Hour), 10); CodeOf(err) != Denied {
		t.Fatalf("unsafe staging code=%s err=%v", CodeOf(err), err)
	}
}

func faultStore(t *testing.T, root string, keyRandom, storeRandom io.Reader, now time.Time) *Store {
	t.Helper()
	manager, err := NewAESKeyManager("operator_evidence_key", 1, testWrappingKey("primary"), keyRandom)
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(Config{Root: root, Keys: manager, Random: storeRandom,
		Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return store
}
