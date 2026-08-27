package encryptedcas

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errInjectedIO }

func TestEncryptedCASStageFilesystemFaultsLeaveNoObject(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	plaintext := []byte("stage filesystem fault evidence")
	tests := []struct {
		name   string
		inject func(*Store)
	}{
		{name: "create", inject: func(store *Store) {
			store.files.create = func(string) (*os.File, error) { return nil, errInjectedIO }
		}},
		{name: "write", inject: func(store *Store) {
			store.files.writer = func(*os.File) io.Writer { return errorWriter{} }
		}},
		{name: "sync", inject: func(store *Store) {
			store.files.sync = func(*os.File) error { return errInjectedIO }
		}},
		{name: "stat", inject: func(store *Store) {
			store.files.stat = func(*os.File) (os.FileInfo, error) { return nil, errInjectedIO }
		}},
		{name: "close", inject: func(store *Store) {
			closeFile := store.files.close
			store.files.close = func(file *os.File) error {
				_ = closeFile(file)
				return errInjectedIO
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			store := newTestEncryptedStore(t, root, testWrappingKey("primary"), now)
			test.inject(store)
			if _, err := store.Stage(t.Context(), stageRequest(t, plaintext, now),
				&sliceSource{data: plaintext}); CodeOf(err) != Unavailable {
				t.Fatalf("code=%s err=%v", CodeOf(err), err)
			}
			assertObjectCounts(t, root, 0, 0)
		})
	}
}

func TestEncryptedCASPublicationFilesystemFaultsNeverCreateReference(t *testing.T) {
	now := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	plaintext := []byte("publication filesystem fault evidence")
	tests := []struct {
		name        string
		inject      func(*Store)
		wantStages  int
		wantObjects int
	}{
		{name: "reopen", inject: func(store *Store) {
			store.files.openRegular = func(string) (*os.File, os.FileInfo, error) {
				return nil, nil, errInjectedIO
			}
		}, wantStages: 1},
		{name: "link", inject: func(store *Store) {
			store.files.link = func(string, string) error { return errInjectedIO }
		}, wantStages: 1},
		{name: "directory sync", inject: func(store *Store) {
			store.files.syncDirectory = func(string) error { return errInjectedIO }
		}, wantStages: 1, wantObjects: 1},
		{name: "stage unlink", inject: func(store *Store) {
			store.files.remove = func(string) error { return errInjectedIO }
		}, wantStages: 1, wantObjects: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			store := newTestEncryptedStore(t, root, testWrappingKey("primary"), now)
			staged, err := store.Stage(t.Context(), stageRequest(t, plaintext, now),
				&sliceSource{data: plaintext})
			if err != nil {
				t.Fatal(err)
			}
			test.inject(store)
			if _, _, err = store.Publish(t.Context(), staged); CodeOf(err) != Unavailable {
				t.Fatalf("code=%s err=%v", CodeOf(err), err)
			}
			assertObjectCounts(t, root, test.wantStages, test.wantObjects)
		})
	}
}

func assertObjectCounts(t *testing.T, root string, wantStages, wantObjects int) {
	t.Helper()
	stages, err := os.ReadDir(filepath.Join(root, "staging"))
	if err != nil {
		t.Fatal(err)
	}
	objects := objectFiles(t, root)
	if len(stages) != wantStages || len(objects) != wantObjects {
		t.Fatalf("stages=%d want=%d objects=%d want=%d", len(stages), wantStages, len(objects), wantObjects)
	}
}

var _ evidenceingest.EncryptedCAS = (*Store)(nil)
