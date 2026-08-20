package filesize

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestOSSourceDiscoversGitVisibleFilesAndIgnoresLocalConfig(t *testing.T) {
	root := newGitSourceRepo(t)
	writeTestFile(t, filepath.Join(root, ".gitignore"), []byte("ignored.txt\n"), 0o644)
	writeTestFile(t, filepath.Join(root, "tracked.txt"), []byte("tracked\n"), 0o644)
	writeTestFile(t, filepath.Join(root, "untracked.txt"), []byte("untracked\n"), 0o644)
	writeTestFile(t, filepath.Join(root, "ignored.txt"), []byte("ignored\n"), 0o644)
	gitTestCommand(t, root, "add", ".gitignore", "tracked.txt")

	outside := t.TempDir()
	marker := filepath.Join(outside, "fsmonitor-ran")
	monitor := filepath.Join(outside, "monitor.sh")
	writeTestFile(t, monitor, []byte("#!/bin/bash\n/usr/bin/touch \""+marker+"\"\n"), 0o755)
	gitTestCommand(t, root, "config", "core.worktree", outside)
	gitTestCommand(t, root, "config", "core.fsmonitor", monitor)
	indexPath := filepath.Join(root, ".git", "index")
	indexBefore, err := os.Stat(indexPath)
	if err != nil {
		t.Fatalf("Stat(index) error = %v", err)
	}
	indexBytesBefore, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("ReadFile(index) error = %v", err)
	}

	snapshot, err := (OSSource{}).Snapshot(context.Background(), root)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	paths := make([]string, 0, len(snapshot.Records))
	for _, record := range snapshot.Records {
		paths = append(paths, record.Path)
	}
	for _, required := range []string{".gitignore", "tracked.txt", "untracked.txt"} {
		if !slices.Contains(paths, required) {
			t.Fatalf("snapshot paths %q omit %q", paths, required)
		}
	}
	if slices.Contains(paths, "ignored.txt") {
		t.Fatalf("snapshot paths %q include ignored content", paths)
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("local fsmonitor executed: %v", err)
	}
	indexAfter, err := os.Stat(indexPath)
	if err != nil {
		t.Fatalf("Stat(index after) error = %v", err)
	}
	indexBytesAfter, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("ReadFile(index after) error = %v", err)
	}
	if !indexBefore.ModTime().Equal(indexAfter.ModTime()) || digestBytes(indexBytesBefore) != digestBytes(indexBytesAfter) {
		t.Fatal("read-only source discovery mutated the Git index")
	}
	checker := NewChecker(OSSource{})
	report, err := checker.Check(context.Background(), Request{Root: root, Policy: validPolicy()})
	requirePassed(t, report, err)
}

func TestOSSourceRejectsFileAndAncestorSymlinks(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{"file", func(t *testing.T, root string) {
			writeTestFile(t, filepath.Join(root, "outside.txt"), []byte("outside\n"), 0o644)
			if err := os.Symlink("outside.txt", filepath.Join(root, "linked.txt")); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
		}},
		{"in_root_ancestor", func(t *testing.T, root string) {
			writeTestFile(t, filepath.Join(root, "linked", "input.txt"), []byte("safe\n"), 0o644)
			gitTestCommand(t, root, "add", "linked/input.txt")
			if err := os.Rename(filepath.Join(root, "linked"), filepath.Join(root, "real")); err != nil {
				t.Fatalf("Rename() error = %v", err)
			}
			if err := os.Symlink("real", filepath.Join(root, "linked")); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
		}},
		{"outside_ancestor", func(t *testing.T, root string) {
			writeTestFile(t, filepath.Join(root, "linked", "input.txt"), []byte("safe\n"), 0o644)
			gitTestCommand(t, root, "add", "linked/input.txt")
			if err := os.RemoveAll(filepath.Join(root, "linked")); err != nil {
				t.Fatalf("RemoveAll() error = %v", err)
			}
			outside := t.TempDir()
			writeTestFile(t, filepath.Join(outside, "input.txt"), []byte("outside\n"), 0o644)
			if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
				t.Fatalf("Symlink() error = %v", err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := newGitSourceRepo(t)
			test.setup(t, root)
			_, err := (OSSource{}).Snapshot(context.Background(), root)
			requireCode(t, err, CodeDenied)
		})
	}
}

func TestOSSourceReadRejectsReplacementAndEscapesDiagnostics(t *testing.T) {
	root := newGitSourceRepo(t)
	name := "bad\n\x1b[31m.txt"
	path := filepath.Join(root, name)
	writeTestFile(t, path, []byte("same\n"), 0o644)
	snapshot, err := (OSSource{}).Snapshot(context.Background(), root)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	record := snapshot.Records[0]
	if record.Path != name {
		t.Fatalf("record path=%q, want %q", record.Path, name)
	}
	backup := filepath.Join(root, "backup.txt")
	if err := os.Rename(path, backup); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	writeTestFile(t, path, []byte("same\n"), 0o644)
	_, err = (OSSource{}).Read(context.Background(), root, record)
	requireCode(t, err, CodeDenied)
	message := err.Error()
	if strings.Contains(message, "\n") || strings.ContainsRune(message, '\x1b') || !strings.Contains(message, `\n\x1b`) {
		t.Fatalf("diagnostic contains raw controls: %q", message)
	}
}

func TestOSSourceRejectsSwappedParentAndOversizedFile(t *testing.T) {
	root := newGitSourceRepo(t)
	writeTestFile(t, filepath.Join(root, "dir", "input.txt"), []byte("safe\n"), 0o644)
	snapshot, err := (OSSource{}).Snapshot(context.Background(), root)
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	record := snapshot.Records[0]
	if err := os.Rename(filepath.Join(root, "dir"), filepath.Join(root, "real")); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	if err := os.Symlink("real", filepath.Join(root, "dir")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	_, err = (OSSource{}).Read(context.Background(), root, record)
	requireCode(t, err, CodeDenied)

	largeRoot := newGitSourceRepo(t)
	writeTestFile(t, filepath.Join(largeRoot, "large.txt"), make([]byte, MaximumInputSize+1), 0o644)
	_, err = (OSSource{}).Snapshot(context.Background(), largeRoot)
	requireCode(t, err, CodeDenied)
}

func TestOSSourceRejectsInvalidGitMetadataAndCancellation(t *testing.T) {
	for _, setup := range []func(*testing.T, string){
		func(t *testing.T, root string) {
			if err := os.RemoveAll(filepath.Join(root, ".git")); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(root, ".git"), []byte("not a directory"), 0o644)
		},
		func(t *testing.T, root string) {
			metadata := filepath.Join(t.TempDir(), "metadata")
			if err := os.Rename(filepath.Join(root, ".git"), metadata); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(metadata, filepath.Join(root, ".git")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		root := newGitSourceRepo(t)
		setup(t, root)
		_, err := (OSSource{}).Snapshot(context.Background(), root)
		if CodeOf(err) != CodeInvalidInput {
			t.Fatalf("Snapshot() error=%v code=%q", err, CodeOf(err))
		}
	}

	root := newGitSourceRepo(t)
	writeTestFile(t, filepath.Join(root, "input.txt"), []byte("safe\n"), 0o644)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (OSSource{}).Snapshot(ctx, root)
	requireCode(t, err, CodeCanceled)
}

func TestOSSourceCanonicalDigestIgnoresRuntimePermissionsAndIdentity(t *testing.T) {
	left := newGitSourceRepo(t)
	right := newGitSourceRepo(t)
	writeTestFile(t, filepath.Join(left, "input.txt"), []byte("same\n"), 0o644)
	writeTestFile(t, filepath.Join(right, "input.txt"), []byte("same\n"), 0o444)
	leftSnapshot, leftErr := (OSSource{}).Snapshot(context.Background(), left)
	rightSnapshot, rightErr := (OSSource{}).Snapshot(context.Background(), right)
	if leftErr != nil || rightErr != nil {
		t.Fatalf("Snapshot() errors = %v, %v", leftErr, rightErr)
	}
	if leftSnapshot.Digest != rightSnapshot.Digest {
		t.Fatalf("canonical digests differ: %s != %s", leftSnapshot.Digest, rightSnapshot.Digest)
	}
	if leftSnapshot.Records[0].Identity == rightSnapshot.Records[0].Identity {
		t.Fatal("test did not vary runtime identity")
	}
}

func newGitSourceRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	command := exec.Command("/usr/bin/git", "init", "-q", root)
	command.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	return root
}

func gitTestCommand(t *testing.T, root string, arguments ...string) {
	t.Helper()
	values := append([]string{"-C", root}, arguments...)
	command := exec.Command("/usr/bin/git", values...)
	command.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "LC_ALL=C"}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
}

func writeTestFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
