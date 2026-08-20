package supplychain

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestBundleAssembleVerifyAndReproduce(t *testing.T) {
	privatePEM, publicPEM, keyID := testKey(t)
	inputs, requirements := bundleArchiveInputs(t)
	request := testBundleRequest(t, privatePEM, inputs)
	first := filepath.Join(t.TempDir(), "first")
	second := filepath.Join(t.TempDir(), "second")
	if err := os.Mkdir(first, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second, 0o700); err != nil {
		t.Fatal(err)
	}
	request.OutputDirectory = first
	firstResult, err := AssembleBundle(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.OutputDirectory = second
	secondResult, err := AssembleBundle(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if firstResult.Manifest.ManifestDigest != secondResult.Manifest.ManifestDigest {
		t.Fatal("fixed inputs produced different manifests")
	}
	firstNames, err := regularNames(first)
	if err != nil {
		t.Fatal(err)
	}
	secondNames, err := regularNames(second)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(firstNames, secondNames) {
		t.Fatal("fixed inputs produced different file sets")
	}
	for _, name := range firstNames {
		left, err := os.ReadFile(filepath.Join(first, name))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(second, name))
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(left, right) {
			t.Fatalf("fixed inputs changed %s", name)
		}
	}
	verify := testVerifyRequest(request, publicPEM, keyID, requirements)
	verify.Directory = first
	if _, err := VerifyBundle(context.Background(), verify); err != nil {
		t.Fatal(err)
	}
}

func TestBundleDeniesTamperExtraAndCancellation(t *testing.T) {
	privatePEM, publicPEM, keyID := testKey(t)
	inputs, requirements := bundleArchiveInputs(t)
	request := testBundleRequest(t, privatePEM, inputs)
	request.OutputDirectory = filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(request.OutputDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := AssembleBundle(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	verify := testVerifyRequest(request, publicPEM, keyID, requirements)
	if err := os.WriteFile(filepath.Join(request.OutputDirectory, "extra"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(context.Background(), verify); CodeOf(err) != CodeDenied {
		t.Fatalf("extra file code=%q err=%v", CodeOf(err), err)
	}
	if err := os.Remove(filepath.Join(request.OutputDirectory, "extra")); err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(request.OutputDirectory, result.ArchiveName)
	if err := os.Chmod(archivePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundle(context.Background(), verify); CodeOf(err) != CodeDenied {
		t.Fatalf("tampered archive code=%q err=%v", CodeOf(err), err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyBundle(canceled, verify); CodeOf(err) != CodeCanceled {
		t.Fatalf("canceled verify code=%q err=%v", CodeOf(err), err)
	}
}

func bundleArchiveInputs(t *testing.T) ([]ArchiveInput, []ArchiveRequirement) {
	t.Helper()
	directory := t.TempDir()
	paths := []string{"archcheck", "qualitygate"}
	inputs := make([]ArchiveInput, 0, len(paths))
	requirements := make([]ArchiveRequirement, 0, len(paths))
	for _, name := range paths {
		source := filepath.Join(directory, name)
		if err := os.WriteFile(source, []byte(name+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		archivePath := "bin/" + name
		inputs = append(inputs, ArchiveInput{Source: source, Path: archivePath, Mode: 0o555})
		requirements = append(requirements, ArchiveRequirement{Path: archivePath, Mode: 0o555})
	}
	return inputs, requirements
}

func testBundleRequest(t *testing.T, privatePEM []byte, inputs []ArchiveInput) BundleRequest {
	t.Helper()
	return BundleRequest{
		Version: "v0.1.0", Target: "darwin/arm64", GoVersion: "go1.26.7",
		BuilderID: "https://github.com/ArronJablonowski/COH/actions", Revision: strings.Repeat("d", 40),
		Source:        Artifact{Path: "source", SHA256: strings.Repeat("a", 64), Length: 1},
		Toolchain:     Artifact{Path: "go", SHA256: strings.Repeat("b", 64), Length: 1},
		Policy:        Artifact{Path: "release-policy", SHA256: strings.Repeat("c", 64)},
		PrivateKeyPEM: privatePEM, Role: "release", ArchiveInputs: inputs,
	}
}

func testVerifyRequest(request BundleRequest, publicPEM []byte, keyID string, requirements []ArchiveRequirement) VerifyRequest {
	return VerifyRequest{
		Directory: request.OutputDirectory, Version: request.Version, Target: request.Target,
		GoVersion: request.GoVersion, BuilderID: request.BuilderID, Revision: request.Revision,
		Source: request.Source, Toolchain: request.Toolchain, Policy: request.Policy,
		TrustedKey:      TrustedKey{KeyID: keyID, Role: request.Role, PublicPEM: publicPEM},
		ArchiveContents: requirements,
	}
}
