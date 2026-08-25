package secretresolver

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/secretref"
)

func TestProtectedFileBackendResolvesDescriptorRootedSecret(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := validRecord()
	entry.Value = nil
	path := filepath.Join(root, entry.EntryID+".secret")
	if err := os.WriteFile(path, []byte(testSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	backend, err := NewProtectedFileBackend(root, []Record{entry})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	audit := &auditStub{}
	resolver, err := New([]Backend{backend}, audit, NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	secret, decision, err := resolveTest(resolver, context.Background(), validRequest())
	if err != nil || secret == nil || decision.Outcome != "allowed" {
		t.Fatalf("secret = %v, decision = %+v, err = %v", secret, decision, err)
	}
	defer secret.Destroy()
	if err := secret.Use(func(value []byte) error {
		if string(value) != testSecret {
			t.Fatalf("value = %q", value)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestProtectedFileBackendRejectsUnsafeRootAndFiles(t *testing.T) {
	t.Run("root-symlink", func(t *testing.T) {
		realRoot := t.TempDir()
		link := filepath.Join(t.TempDir(), "root-link")
		if err := os.Symlink(realRoot, link); err != nil {
			t.Fatal(err)
		}
		if _, err := NewProtectedFileBackend(link, []Record{fileEntry()}); secretref.Code(err) != secretref.InvalidInput {
			t.Fatalf("root err = %v", err)
		}
	})
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{"group-readable", func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte(testSecret), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, path string) {
			t.Helper()
			target := filepath.Join(filepath.Dir(path), "target")
			if err := os.WriteFile(target, []byte(testSecret), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized", func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, make([]byte, maximumSecretBytes+1), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			entry := fileEntry()
			test.setup(t, filepath.Join(root, entry.EntryID+".secret"))
			if backend, err := NewProtectedFileBackend(root, []Record{entry}); err == nil {
				_ = backend.Close()
				t.Fatal("unsafe file was accepted at construction")
			}
		})
	}
}

func TestProtectedFileBackendRejectsMaterialChangeWithoutVersionRotation(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := fileEntry()
	path := filepath.Join(root, entry.EntryID+".secret")
	if err := os.WriteFile(path, []byte(testSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	backend, err := NewProtectedFileBackend(root, []Record{entry})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if err := os.WriteFile(path, []byte("changed-secret-without-version"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Fetch(context.Background(), validRequest().Reference); err == nil {
		t.Fatal("changed secret was accepted under the old version")
	}
}

func TestSealedMemoryRotationAndRevocationAreImmediate(t *testing.T) {
	entry := validRecord()
	entry.Backend = sealedMemoryBackendName
	input := entry.Value
	backend, err := NewSealedMemoryBackend([]Record{entry})
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	if !allZero(input) {
		t.Fatalf("constructor did not consume input: %q", input)
	}
	audit := &auditStub{}
	resolver, err := New([]Backend{backend}, audit, NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest()
	request.Reference.Backend = sealedMemoryBackendName
	request.IdempotencyKey = "sealed-first"
	secret, _, err := resolveTest(resolver, context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	secret.Destroy()

	rotatedValue := []byte("rotated-secret-value")
	next := validRecord()
	next.Backend = sealedMemoryBackendName
	next.Version = 8
	next.Revision = 4
	next.Value = rotatedValue
	if err := backend.Replace(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if !allZero(rotatedValue) {
		t.Fatalf("rotation did not consume input: %q", rotatedValue)
	}
	request.IdempotencyKey = "sealed-stale"
	if secret, decision, err := resolveTest(resolver, context.Background(), request); secret != nil || secretref.Code(err) != secretref.Denied || decision.ReasonCode != "stale_reference" {
		t.Fatalf("secret = %v, decision = %+v, err = %v", secret, decision, err)
	}
	request.Reference.Version = 8
	request.IdempotencyKey = "sealed-rotated"
	secret, _, err = resolveTest(resolver, context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	secret.Destroy()

	revoked := next
	revoked.Revision = 5
	revoked.Active = false
	revoked.Value = []byte("rotated-secret-value")
	if err := backend.Replace(context.Background(), revoked); err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = "sealed-revoked"
	if secret, decision, err := resolveTest(resolver, context.Background(), request); secret != nil || secretref.Code(err) != secretref.Denied || decision.ReasonCode != "secret_revoked" {
		t.Fatalf("secret = %v, decision = %+v, err = %v", secret, decision, err)
	}
}

func TestMemoryReplayStoreIsAtomic(t *testing.T) {
	store := NewMemoryReplayStore()
	record := ReplayRecord{
		OrganizationID: testOrganizationID, ActorID: testActorID,
		IdempotencyKey: "atomic", RequestDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	const workers = 64
	var fresh atomic.Int32
	var exact atomic.Int32
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := store.CheckAndStore(context.Background(), record)
			if err != nil {
				t.Errorf("check: %v", err)
				return
			}
			if result == ReplayNew {
				fresh.Add(1)
			} else if result == ReplayExact {
				exact.Add(1)
			} else {
				t.Errorf("result = %q", result)
			}
		}()
	}
	wait.Wait()
	if fresh.Load() != 1 || exact.Load() != workers-1 {
		t.Fatalf("new = %d, exact = %d", fresh.Load(), exact.Load())
	}
}

func fileEntry() Record {
	entry := validRecord()
	entry.Value = nil
	return entry
}
