package supplychain

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

type VerifyRequest struct {
	Directory       string
	Version         string
	Target          string
	GoVersion       string
	BuilderID       string
	Revision        string
	Source          Artifact
	Toolchain       Artifact
	Policy          Artifact
	TrustedKey      TrustedKey
	ArchiveContents []ArchiveRequirement
}

func VerifyBundle(ctx context.Context, request VerifyRequest) (Manifest, error) {
	if !validVersion(request.Version) || !validTarget(request.Target) || !validGoVersion(request.GoVersion) ||
		request.BuilderID == "" || !validRevision(request.Revision) || !validDigest(request.Source.SHA256) ||
		!validDigest(request.Toolchain.SHA256) || !validDigest(request.Policy.SHA256) || request.TrustedKey.KeyID == "" || len(request.ArchiveContents) == 0 {
		return Manifest{}, errorf(CodeInvalidInput, "bundle", "verification request is incomplete or invalid", nil)
	}
	stem := "coh-" + request.Version + "-" + strings.ReplaceAll(request.Target, "/", "-")
	archiveName := stem + ".tar.gz"
	checksumsName := stem + ".sha256"
	sbomName := stem + ".cdx.json"
	provenanceName := stem + ".intoto.jsonl"
	manifestName := stem + ".release.json"
	signedNames := []string{checksumsName, provenanceName, sbomName}
	manifestArtifacts := []string{archiveName, checksumsName, provenanceName, sbomName}
	for _, name := range signedNames {
		manifestArtifacts = append(manifestArtifacts, name+".sig")
	}
	slices.Sort(manifestArtifacts)
	expectedNames := append(slices.Clone(manifestArtifacts), manifestName, manifestName+".sig")
	slices.Sort(expectedNames)
	actualNames, err := regularNames(request.Directory)
	if err != nil {
		return Manifest{}, err
	}
	if !slices.Equal(actualNames, expectedNames) {
		return Manifest{}, errorf(CodeDenied, "bundle", "bundle file set differs", nil)
	}
	manifestPath := filepath.Join(request.Directory, manifestName)
	manifestEncoded, err := readStableRegular(manifestPath, MaximumFileSize)
	if err != nil {
		return Manifest{}, err
	}
	manifestSignature, err := readStableRegular(manifestPath+".sig", MaximumFileSize)
	if err != nil {
		return Manifest{}, err
	}
	if err := VerifyFile(ctx, manifestPath, manifestName, manifestSignature, request.TrustedKey); err != nil {
		return Manifest{}, err
	}
	manifest, err := VerifyManifest(ctx, request.Directory, manifestEncoded)
	if err != nil {
		return Manifest{}, err
	}
	paths := make([]string, len(manifest.Artifacts))
	for index, artifact := range manifest.Artifacts {
		paths[index] = artifact.Path
	}
	if manifest.ReleaseVersion != request.Version || manifest.Target != request.Target || !slices.Equal(paths, manifestArtifacts) {
		return Manifest{}, errorf(CodeDenied, "bundle", "manifest identity or inventory differs", nil)
	}
	for _, name := range signedNames {
		signature, readErr := readStableRegular(filepath.Join(request.Directory, name+".sig"), MaximumFileSize)
		if readErr != nil {
			return Manifest{}, readErr
		}
		if err := VerifyFile(ctx, filepath.Join(request.Directory, name), name, signature, request.TrustedKey); err != nil {
			return Manifest{}, err
		}
	}
	archivePath := filepath.Join(request.Directory, archiveName)
	archive, _, err := artifactFor(archivePath, archiveName)
	if err != nil {
		return Manifest{}, err
	}
	checksum, err := readStableRegular(filepath.Join(request.Directory, checksumsName), MaximumFileSize)
	if err != nil {
		return Manifest{}, err
	}
	if string(checksum) != fmt.Sprintf("%s  %s\n", archive.SHA256, archive.Path) {
		return Manifest{}, errorf(CodeDenied, "checksums", "checksum document differs from archive", nil)
	}
	entries, err := InspectArchive(ctx, archivePath)
	if err != nil {
		return Manifest{}, err
	}
	if !archiveRequirementsMatch(entries, request.ArchiveContents) {
		return Manifest{}, errorf(CodeDenied, "archive", "archive contents differ from release policy", nil)
	}
	if err := verifyPackagedBinaries(ctx, archivePath, request.ArchiveContents, request.GoVersion, request.Target); err != nil {
		return Manifest{}, err
	}
	sbom, err := readStableRegular(filepath.Join(request.Directory, sbomName), MaximumFileSize)
	if err != nil {
		return Manifest{}, err
	}
	if err := VerifyReleaseSBOM(sbom, archive, entries, request.Version, request.Target); err != nil {
		return Manifest{}, err
	}
	provenance, err := readStableRegular(filepath.Join(request.Directory, provenanceName), MaximumFileSize)
	if err != nil {
		return Manifest{}, err
	}
	if err := VerifySLSAProvenance(
		provenance, archive, request.Source, request.Toolchain, request.Policy, request.Version, request.Target,
		request.GoVersion, request.BuilderID, request.Revision,
	); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func archiveRequirementsMatch(entries []ArchiveEntry, requirements []ArchiveRequirement) bool {
	if len(entries) != len(requirements) {
		return false
	}
	for index, entry := range entries {
		if entry.Path != requirements[index].Path || entry.Mode != requirements[index].Mode {
			return false
		}
	}
	return true
}

func regularNames(directory string) ([]string, error) {
	if err := rejectSymlinkAncestors(directory); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, errorf(CodeToolFailure, "bundle", "cannot list bundle directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return nil, errorf(CodeDenied, "bundle", "bundle contains a symlink", nil)
		}
		info, infoErr := entry.Info()
		if infoErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errorf(CodeDenied, "bundle", "bundle contains a non-regular entry", infoErr)
		}
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	return names, nil
}
