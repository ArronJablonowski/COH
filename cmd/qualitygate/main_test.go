package main

import (
	"os"
	"path/filepath"
	"testing"
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
