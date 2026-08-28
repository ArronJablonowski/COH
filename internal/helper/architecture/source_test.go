package architecture

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestValidateWorkspaceLayoutRejectsNestedModulesAndWorkspaces(t *testing.T) {
	for _, nested := range []string{"nested/go.mod", "nested/go.work"} {
		t.Run(nested, func(t *testing.T) {
			root := newWorkspace(t)
			writeTestFile(t, root, nested, "go 1.26.7\n")
			err := ValidateWorkspaceLayout(context.Background(), root)
			assertErrorCode(t, err, CodeDenied)
		})
	}
}

func TestSourceScanCatchesInactivePlatformBypass(t *testing.T) {
	root := newWorkspace(t)
	writeTestFile(t, root, "internal/domain/domain.go", "package domain\n")
	writeTestFile(t, root, "internal/domain/bypass_windows.go", `//go:build windows

package domain

import _ "github.com/ArronJablonowski/COH/internal/connector"
`)
	if err := ValidateWorkspaceLayout(context.Background(), root); err != nil {
		t.Fatalf("ValidateWorkspaceLayout() error = %v", err)
	}
	packages, err := ScanSourcePackages(context.Background(), root, ModulePath)
	if err != nil {
		t.Fatalf("ScanSourcePackages() error = %v", err)
	}
	report, err := Evaluate(context.Background(), loadContractFixture(t), packages, testProvenance())
	assertErrorCode(t, err, CodeDenied)
	if report.ViolationCount != 1 || report.Violations[0].ImportBoundary != "connector" {
		t.Fatalf("platform bypass report = %#v", report)
	}
}

func TestSourceScanCatchesInactiveCapabilityCompositionBypass(t *testing.T) {
	root := newWorkspace(t)
	writeTestFile(t, root, "internal/workflow/workflow.go", "package workflow\n")
	writeTestFile(t, root, "internal/workflow/bypass_windows.go", `//go:build windows

package workflow

import _ "github.com/ArronJablonowski/COH/internal/domain/capabilityseam"
`)
	packages, err := ScanSourcePackages(context.Background(), root, ModulePath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Evaluate(context.Background(), loadContractFixture(t), packages, testProvenance())
	assertErrorCode(t, err, CodeDenied)
	if report.ViolationCount != 1 || report.Violations[0].Rule != "ARCH-003" {
		t.Fatalf("inactive composition bypass report = %#v", report)
	}
}

func TestSourceDigestBindsFileContent(t *testing.T) {
	root := newWorkspace(t)
	path := "internal/domain/domain.go"
	writeTestFile(t, root, path, "package domain\n")
	packages, err := ScanSourcePackages(context.Background(), root, ModulePath)
	if err != nil {
		t.Fatalf("ScanSourcePackages() error = %v", err)
	}
	manifests, err := ValidateWorkspaceManifests(context.Background(), root)
	if err != nil {
		t.Fatalf("ValidateWorkspaceManifests() error = %v", err)
	}
	first, count, err := DigestSources(context.Background(), packages, manifests)
	if err != nil || count != 3 {
		t.Fatalf("DigestSources() = %q, %d, %v", first, count, err)
	}
	writeTestFile(t, root, path, "package domain\n\n// changed\n")
	if err := VerifyWorkspaceSnapshot(context.Background(), root, ModulePath, packages, manifests); err == nil {
		t.Fatal("VerifyWorkspaceSnapshot(changed) error = nil")
	} else {
		assertErrorCode(t, err, CodeDenied)
	}
	stable, _, err := DigestSources(context.Background(), packages, manifests)
	if err != nil {
		t.Fatalf("DigestSources(snapshot) error = %v", err)
	}
	if first != stable {
		t.Fatal("parsed source snapshot changed after filesystem mutation")
	}
	rescanned, err := ScanSourcePackages(context.Background(), root, ModulePath)
	if err != nil {
		t.Fatalf("ScanSourcePackages(changed) error = %v", err)
	}
	second, _, err := DigestSources(context.Background(), rescanned, manifests)
	if err != nil {
		t.Fatalf("DigestSources(rescanned) error = %v", err)
	}
	if first == second {
		t.Fatal("source digest did not change with file content")
	}
}

func TestVerifyWorkspaceSnapshotDetectsAddedSource(t *testing.T) {
	root := newWorkspace(t)
	writeTestFile(t, root, "internal/domain/domain.go", "package domain\n")
	packages, err := ScanSourcePackages(context.Background(), root, ModulePath)
	if err != nil {
		t.Fatalf("ScanSourcePackages() error = %v", err)
	}
	manifests, err := ValidateWorkspaceManifests(context.Background(), root)
	if err != nil {
		t.Fatalf("ValidateWorkspaceManifests() error = %v", err)
	}
	writeTestFile(t, root, "internal/domain/added.go", "package domain\n")
	err = VerifyWorkspaceSnapshot(context.Background(), root, ModulePath, packages, manifests)
	assertErrorCode(t, err, CodeDenied)
}

func TestParseBuildTagsIsCanonicalAndStrict(t *testing.T) {
	tags, err := ParseBuildTags("linux, coh_test,linux")
	if err != nil {
		t.Fatalf("ParseBuildTags() error = %v", err)
	}
	if !slices.Equal(tags, []string{"coh_test", "linux"}) {
		t.Fatalf("tags = %v", tags)
	}
	if _, err := ParseBuildTags("linux,bad tag"); err == nil {
		t.Fatal("ParseBuildTags(invalid) error = nil")
	}
}

func newWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, root, "go.mod", "module "+ModulePath+"\n\ngo 1.26.7\n\ntoolchain go1.26.7\n")
	writeTestFile(t, root, "go.work", "go 1.26.7\n\ntoolchain go1.26.7\n\nuse .\n")
	return root
}

func writeTestFile(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
