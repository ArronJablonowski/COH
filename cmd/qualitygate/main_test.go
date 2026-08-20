package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ArronJablonowski/COH/internal/helper/filesize"
)

func TestValidateOutputEnforcesReservedFreshExternalDirectory(t *testing.T) {
	root := t.TempDir()
	artifacts := t.TempDir()
	output := filepath.Join(artifacts, "quality-report.json")
	if err := validateOutput(root, artifacts, output, "quality-report.json", true); err != nil {
		t.Fatalf("valid output rejected: %v", err)
	}
	if err := validateOutput(root, artifacts, filepath.Join(artifacts, "format.log"), "quality-report.json", true); err == nil {
		t.Fatal("reserved evidence overwrite was accepted")
	}
	if err := os.WriteFile(filepath.Join(artifacts, "stale.log"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateOutput(root, artifacts, output, "quality-report.json", true); err == nil {
		t.Fatal("non-empty run directory was accepted")
	}
}

func TestValidateOutputRejectsSymlinkIntoRepository(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(outside, "evidence")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	err := validateOutput(root, link, filepath.Join(link, "quality-report.json"), "quality-report.json", true)
	if err == nil {
		t.Fatal("symlinked artifact directory into repository was accepted")
	}
}

func TestRunMapsInvalidArguments(t *testing.T) {
	if status := run([]string{"-mode", "unknown"}, os.Stdout, os.Stderr); status != 64 {
		t.Fatalf("status=%d, want 64", status)
	}
}

func TestVerifyPublicationModeRequiresArtifactDirectory(t *testing.T) {
	if status := run([]string{"-mode", "verify-publication"}, os.Stdout, os.Stderr); status != 64 {
		t.Fatalf("status=%d, want 64", status)
	}
}

func TestFileSizeModePublishesVerifiableSuccessAndDenial(t *testing.T) {
	for _, test := range []struct {
		name       string
		path       string
		lines      int
		wantStatus int
		outcome    string
	}{
		{name: "warning", path: "docs/long.md", lines: 501, wantStatus: 0, outcome: "passed"},
		{name: "denial", path: "scripts/long.sh", lines: 301, wantStatus: 2, outcome: "denied"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := newFileSizeWorkspace(t, test.path, test.lines)
			artifacts := t.TempDir()
			output := filepath.Join(artifacts, "file-size-report.json")
			var stdout, stderr bytes.Buffer
			status := run([]string{
				"-mode", "file-size", "-root", root, "-input", filepath.Join(root, "ci", "file-size-policy.json"),
				"-artifact-dir", artifacts, "-output", output,
			}, &stdout, &stderr)
			if status != test.wantStatus {
				t.Fatalf("status=%d want=%d stderr=%q", status, test.wantStatus, stderr.String())
			}
			report, err := filesize.ReadAndVerifyReport(output)
			if err != nil || report.Outcome != test.outcome {
				t.Fatalf("report outcome=%q error=%v", report.Outcome, err)
			}
		})
	}
}

func TestReadFileSizePolicyRejectsSymlinkAndReplacementRaces(t *testing.T) {
	root := newFileSizeWorkspace(t, "internal/input.go", 1)
	policy := filepath.Join(root, "ci", "file-size-policy.json")
	original, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("file symlink", func(t *testing.T) {
		outside := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(outside, original, 0o600); err != nil {
			t.Fatal(err)
		}
		linkedRoot := newFileSizeWorkspace(t, "internal/input.go", 1)
		linkedPolicy := filepath.Join(linkedRoot, "ci", "file-size-policy.json")
		if err := os.Remove(linkedPolicy); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, linkedPolicy); err != nil {
			t.Fatal(err)
		}
		if _, err := readFileSizePolicy(linkedRoot, linkedPolicy); err == nil {
			t.Fatal("symlinked policy was accepted")
		}
	})
	t.Run("ancestor symlink", func(t *testing.T) {
		linkedRoot := newFileSizeWorkspace(t, "internal/input.go", 1)
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "file-size-policy.json"), original, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(linkedRoot, "ci"), filepath.Join(linkedRoot, "ci-real")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(linkedRoot, "ci")); err != nil {
			t.Fatal(err)
		}
		if _, err := readFileSizePolicy(linkedRoot, filepath.Join(linkedRoot, "ci", "file-size-policy.json")); err == nil {
			t.Fatal("policy below a symlinked ancestor was accepted")
		}
	})
	t.Run("same size replacement", func(t *testing.T) {
		if _, err := readFileSizePolicyStable(root, policy, func() error {
			moved := policy + ".original"
			if err := os.Rename(policy, moved); err != nil {
				return err
			}
			return os.WriteFile(policy, bytes.Repeat([]byte{'x'}, len(original)), 0o600)
		}); err == nil {
			t.Fatal("same-sized policy replacement was accepted")
		}
	})
}

func newFileSizeWorkspace(t *testing.T, path string, lines int) string {
	t.Helper()
	root := t.TempDir()
	if output, err := exec.Command("/usr/bin/git", "-C", root, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	policy, err := os.ReadFile(filepath.Join("..", "..", "ci", "file-size-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{filepath.Dir(filepath.Join(root, "ci", "file-size-policy.json")), filepath.Dir(filepath.Join(root, path))} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "ci", "file-size-policy.json"), policy, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, path), bytes.Repeat([]byte("line\n"), lines), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}
