package supplychain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
)

func NewManifest(ctx context.Context, directory, version, target string, names []string) (Manifest, error) {
	if err := ctx.Err(); err != nil {
		return Manifest{}, contextError(err, "manifest")
	}
	if !validVersion(version) || !validTarget(target) || len(names) == 0 || len(names) > 32 {
		return Manifest{}, errorf(CodeInvalidInput, "manifest", "version, target, and bounded artifact names are required", nil)
	}
	if !slices.IsSorted(names) {
		return Manifest{}, errorf(CodeInvalidInput, "artifacts", "artifact names must be sorted", nil)
	}
	artifacts := make([]Artifact, 0, len(names))
	for index, name := range names {
		if index > 0 && name == names[index-1] {
			return Manifest{}, errorf(CodeInvalidInput, "artifacts", "duplicate artifact name", nil)
		}
		artifact, _, err := artifactFor(filepath.Join(directory, name), name)
		if err != nil {
			return Manifest{}, err
		}
		artifacts = append(artifacts, artifact)
	}
	manifest := Manifest{
		SchemaVersion: ManifestSchema, Version: ContractVersion, Issue: releaseIssue,
		Requirements: slices.Clone(releaseRequirements), ReleaseVersion: version,
		Target: target, Artifacts: artifacts,
	}
	if err := finalizeManifest(&manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func EncodeManifest(manifest Manifest) ([]byte, error) {
	if err := verifyManifestSemantics(manifest); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, errorf(CodeToolFailure, "manifest", "cannot encode manifest", err)
	}
	return append(encoded, '\n'), nil
}

func VerifyManifest(ctx context.Context, directory string, encoded []byte) (Manifest, error) {
	if err := ctx.Err(); err != nil {
		return Manifest{}, contextError(err, "manifest")
	}
	var manifest Manifest
	if err := decodeStrict(encoded, &manifest); err != nil {
		return Manifest{}, errorf(CodeInvalidInput, "manifest", "invalid manifest document", err)
	}
	if err := verifyManifestSemantics(manifest); err != nil {
		return Manifest{}, err
	}
	expected := manifest.ManifestDigest
	if err := finalizeManifest(&manifest); err != nil || manifest.ManifestDigest != expected {
		return Manifest{}, errorf(CodeDenied, "manifest", "manifest self-digest differs", err)
	}
	for _, expected := range manifest.Artifacts {
		actual, _, err := artifactFor(filepath.Join(directory, expected.Path), expected.Path)
		if err != nil {
			return Manifest{}, err
		}
		if actual != expected {
			return Manifest{}, errorf(CodeDenied, "manifest.artifacts", "artifact digest or length differs", nil)
		}
	}
	return manifest, nil
}

func WriteManifestAtomic(path string, manifest Manifest) error {
	encoded, err := EncodeManifest(manifest)
	if err != nil {
		return err
	}
	return writeAtomicNoReplace(path, encoded, 0o444)
}

func WriteSignatureAtomic(path string, signature Signature) error {
	encoded, err := EncodeSignature(signature)
	if err != nil {
		return err
	}
	return writeAtomicNoReplace(path, encoded, 0o444)
}

func finalizeManifest(manifest *Manifest) error {
	manifest.ManifestDigest = ""
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return errorf(CodeToolFailure, "manifest", "cannot canonicalize manifest", err)
	}
	digest := sha256.Sum256(encoded)
	manifest.ManifestDigest = hex.EncodeToString(digest[:])
	return nil
}

func verifyManifestSemantics(manifest Manifest) error {
	if manifest.SchemaVersion != ManifestSchema || manifest.Version != ContractVersion ||
		manifest.Issue != releaseIssue || !slices.Equal(manifest.Requirements, releaseRequirements) ||
		!validVersion(manifest.ReleaseVersion) || !validTarget(manifest.Target) ||
		len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > 32 || !validDigest(manifest.ManifestDigest) {
		return errorf(CodeDenied, "manifest", "manifest contract is incomplete or unsupported", nil)
	}
	previous := ""
	for _, artifact := range manifest.Artifacts {
		if filepath.Base(artifact.Path) != artifact.Path || artifact.Path <= previous ||
			!validDigest(artifact.SHA256) || artifact.Length < 0 || artifact.Length > MaximumFileSize {
			return errorf(CodeDenied, "manifest.artifacts", "artifact inventory is invalid or unordered", nil)
		}
		previous = artifact.Path
	}
	return nil
}

func validVersion(value string) bool {
	if len(value) < len("v0.0.0") || len(value) > 64 || value[0] != 'v' {
		return false
	}
	core := value[1:]
	if index := strings.IndexByte(core, '-'); index >= 0 {
		prerelease := core[index+1:]
		core = core[:index]
		if prerelease == "" || strings.HasPrefix(prerelease, ".") || strings.HasSuffix(prerelease, ".") || strings.Contains(prerelease, "..") {
			return false
		}
		for _, character := range prerelease {
			if (character < '0' || character > '9') && (character < 'A' || character > 'Z') &&
				(character < 'a' || character > 'z') && character != '.' && character != '-' {
				return false
			}
		}
	}
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validTarget(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 2 && (parts[0] == "darwin" || parts[0] == "linux") &&
		(parts[1] == "arm64" || parts[1] == "amd64")
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
