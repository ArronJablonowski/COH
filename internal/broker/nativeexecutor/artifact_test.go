package nativeexecutor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileArtifactPreparerCopiesVerifiedExecutable(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "tool")
	data := []byte("native tool bytes")
	if err := os.WriteFile(source, data, 0o500); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewFileArtifactPreparer(root)
	if err != nil {
		t.Fatalf("NewFileArtifactPreparer() error=%v", err)
	}
	prepared, err := preparer.Prepare(context.Background(), source, digestBytes(data), 1024)
	if err != nil {
		t.Fatalf("Prepare() error=%v", err)
	}
	staged, err := os.ReadFile(prepared.Path)
	if err != nil || string(staged) != string(data) || prepared.Path == source {
		t.Fatalf("staged=%q path=%q error=%v", staged, prepared.Path, err)
	}
	if err := prepared.Cleanup(); err != nil {
		t.Fatalf("cleanup error=%v", err)
	}
	if _, err := os.Stat(prepared.Path); !os.IsNotExist(err) {
		t.Fatalf("staged artifact still exists: %v", err)
	}
}

func TestFileArtifactPreparerDeniesSymlinkDigestAndBounds(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "tool")
	if err := os.WriteFile(source, []byte("tool"), 0o500); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(source, link); err != nil {
		t.Fatal(err)
	}
	preparer, err := NewFileArtifactPreparer(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, path, digest string
		limit              uint64
		reason             string
	}{
		{"symlink", link, digestBytes([]byte("tool")), 100, "artifact_untrusted"},
		{"digest", source, testDigest, 100, "artifact_digest_mismatch"},
		{"storage", source, digestBytes([]byte("tool")), 2, "artifact_untrusted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := preparer.Prepare(context.Background(), test.path, test.digest, test.limit)
			if Reason(err) != test.reason {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
