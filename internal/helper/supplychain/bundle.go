package supplychain

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type BundleRequest struct {
	OutputDirectory string
	Version         string
	Target          string
	GoVersion       string
	BuilderID       string
	Revision        string
	Source          Artifact
	Toolchain       Artifact
	Policy          Artifact
	PrivateKeyPEM   []byte
	Role            string
	ArchiveInputs   []ArchiveInput
}

type BundleResult struct {
	ArchiveName    string
	Manifest       Manifest
	ManifestName   string
	SignatureName  string
	ArchiveEntries []ArchiveEntry
}

func AssembleBundle(ctx context.Context, request BundleRequest) (BundleResult, error) {
	if err := validateBundleRequest(request); err != nil {
		return BundleResult{}, err
	}
	if err := requireEmptyRealDirectory(request.OutputDirectory); err != nil {
		return BundleResult{}, err
	}
	stem := "coh-" + request.Version + "-" + strings.ReplaceAll(request.Target, "/", "-")
	archiveName := stem + ".tar.gz"
	archivePath := filepath.Join(request.OutputDirectory, archiveName)
	entries, err := CreateArchive(ctx, archivePath, request.ArchiveInputs)
	if err != nil {
		return BundleResult{}, err
	}
	archive, _, err := artifactFor(archivePath, archiveName)
	if err != nil {
		return BundleResult{}, err
	}
	checksumsName := stem + ".sha256"
	checksums := []byte(fmt.Sprintf("%s  %s\n", archive.SHA256, archive.Path))
	if err := writeAtomicNoReplace(filepath.Join(request.OutputDirectory, checksumsName), checksums, 0o444); err != nil {
		return BundleResult{}, err
	}
	sbomName := stem + ".cdx.json"
	sbom, err := GenerateReleaseSBOM(archive, entries, request.Version, request.Target)
	if err != nil {
		return BundleResult{}, err
	}
	if err := writeAtomicNoReplace(filepath.Join(request.OutputDirectory, sbomName), sbom, 0o444); err != nil {
		return BundleResult{}, err
	}
	provenanceName := stem + ".intoto.jsonl"
	provenance, err := GenerateSLSAProvenance(
		archive, request.Source, request.Toolchain, request.Policy, request.Version, request.Target,
		request.GoVersion, request.BuilderID, request.Revision,
	)
	if err != nil {
		return BundleResult{}, err
	}
	if err := writeAtomicNoReplace(filepath.Join(request.OutputDirectory, provenanceName), provenance, 0o444); err != nil {
		return BundleResult{}, err
	}
	signedNames := []string{checksumsName, provenanceName, sbomName}
	artifactNames := []string{archiveName, checksumsName, provenanceName, sbomName}
	for _, name := range signedNames {
		signature, signErr := SignFile(ctx, filepath.Join(request.OutputDirectory, name), name, request.PrivateKeyPEM, request.Role)
		if signErr != nil {
			return BundleResult{}, signErr
		}
		signatureName := name + ".sig"
		if err := WriteSignatureAtomic(filepath.Join(request.OutputDirectory, signatureName), signature); err != nil {
			return BundleResult{}, err
		}
		artifactNames = append(artifactNames, signatureName)
	}
	slices.Sort(artifactNames)
	manifest, err := NewManifest(ctx, request.OutputDirectory, request.Version, request.Target, artifactNames)
	if err != nil {
		return BundleResult{}, err
	}
	manifestName := stem + ".release.json"
	manifestPath := filepath.Join(request.OutputDirectory, manifestName)
	if err := WriteManifestAtomic(manifestPath, manifest); err != nil {
		return BundleResult{}, err
	}
	manifestSignature, err := SignFile(ctx, manifestPath, manifestName, request.PrivateKeyPEM, request.Role)
	if err != nil {
		return BundleResult{}, err
	}
	manifestSignatureName := manifestName + ".sig"
	if err := WriteSignatureAtomic(filepath.Join(request.OutputDirectory, manifestSignatureName), manifestSignature); err != nil {
		return BundleResult{}, err
	}
	return BundleResult{
		ArchiveName: archiveName, Manifest: manifest, ManifestName: manifestName,
		SignatureName: manifestSignatureName, ArchiveEntries: entries,
	}, nil
}

func validateBundleRequest(request BundleRequest) error {
	if !validVersion(request.Version) || !validTarget(request.Target) || !validGoVersion(request.GoVersion) ||
		request.BuilderID == "" || !validRevision(request.Revision) || !validDigest(request.Source.SHA256) ||
		!validDigest(request.Toolchain.SHA256) || len(request.PrivateKeyPEM) == 0 ||
		!validDigest(request.Policy.SHA256) ||
		(request.Role != "release" && request.Role != "ci-fixture") {
		return errorf(CodeInvalidInput, "bundle", "bundle request is incomplete or invalid", nil)
	}
	for _, input := range request.ArchiveInputs {
		if input.Package != "" {
			data, readErr := readStableRegular(input.Source, MaximumFileSize)
			if readErr != nil {
				return readErr
			}
			if err := verifyGoBinaryData(data, input.Package, request.GoVersion, request.Target); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireEmptyRealDirectory(directory string) error {
	if err := rejectSymlinkAncestors(directory); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errorf(CodeDenied, "output", "bundle output must be a private real directory", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return errorf(CodeToolFailure, "output", "cannot inspect bundle output", err)
	}
	if len(entries) != 0 {
		return errorf(CodeDenied, "output", "bundle output must be empty", nil)
	}
	return nil
}
