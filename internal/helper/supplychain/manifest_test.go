package supplychain

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestManifestRoundTripAndTamperDenial(t *testing.T) {
	directory := t.TempDir()
	names := []string{"coh.cdx.json", "coh.tar.gz", "provenance.intoto.jsonl"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := NewManifest(context.Background(), directory, "v0.1.0", "darwin/arm64", names)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyManifest(context.Background(), directory, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(verified.Artifacts, manifest.Artifacts) {
		t.Fatalf("verified artifacts differ: %#v", verified.Artifacts)
	}
	if err := os.WriteFile(filepath.Join(directory, names[1]), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(context.Background(), directory, encoded); CodeOf(err) != CodeDenied {
		t.Fatalf("tampered artifact code=%q err=%v", CodeOf(err), err)
	}
}

func TestManifestRejectsInvalidAndCanceledInput(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "a"), []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewManifest(context.Background(), directory, "0.1.0", "darwin/arm64", []string{"a"}); CodeOf(err) != CodeInvalidInput {
		t.Fatalf("invalid version code=%q err=%v", CodeOf(err), err)
	}
	if _, err := NewManifest(context.Background(), directory, "v0.1.0", "windows/amd64", []string{"a"}); CodeOf(err) != CodeInvalidInput {
		t.Fatalf("invalid target code=%q err=%v", CodeOf(err), err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewManifest(canceled, directory, "v0.1.0", "darwin/arm64", []string{"a"}); CodeOf(err) != CodeCanceled {
		t.Fatalf("canceled code=%q err=%v", CodeOf(err), err)
	}
	manifest, err := NewManifest(context.Background(), directory, "v0.1.0", "darwin/arm64", []string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	value["unexpected"] = true
	encoded, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(context.Background(), directory, encoded); CodeOf(err) != CodeInvalidInput {
		t.Fatalf("unknown field code=%q err=%v", CodeOf(err), err)
	}
}

func TestAtomicPublicationPreservesCompetingDestination(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "manifest.json")
	if err := os.WriteFile(path, []byte("winner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicNoReplace(path, []byte("loser"), 0o444); CodeOf(err) != CodeDenied {
		t.Fatalf("collision code=%q err=%v", CodeOf(err), err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "winner" {
		t.Fatalf("competing destination changed to %q", data)
	}
}

func TestAtomicPublicationRejectsUnsafeOutputDirectory(t *testing.T) {
	unsafe := t.TempDir()
	if err := os.Chmod(unsafe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicNoReplace(filepath.Join(unsafe, "artifact"), []byte("data"), 0o444); CodeOf(err) != CodeDenied {
		t.Fatalf("public directory code=%q err=%v", CodeOf(err), err)
	}
	if _, err := os.Lstat(filepath.Join(unsafe, "artifact")); !os.IsNotExist(err) {
		t.Fatalf("unsafe output survived: %v", err)
	}
	realParent := t.TempDir()
	if err := os.Chmod(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realParent, linkParent); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicNoReplace(filepath.Join(linkParent, "artifact"), []byte("data"), 0o444); CodeOf(err) != CodeDenied {
		t.Fatalf("symlink ancestor code=%q err=%v", CodeOf(err), err)
	}
	if _, err := os.Lstat(filepath.Join(realParent, "artifact")); !os.IsNotExist(err) {
		t.Fatalf("symlink output escaped: %v", err)
	}
}
