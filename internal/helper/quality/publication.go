package quality

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
)

var publicArtifactNames = []string{
	"architecture-report.json",
	"ci-provenance.json",
	"coh.cdx.json",
	"govulndb-verification.json",
	"quality-report.json",
}

// WritePublicationManifestAtomic is the final commit marker. A directory is
// canonical only when this marker and its safe public subset verify.
func WritePublicationManifestAtomic(directory, path string, qualityGatePromotable bool) error {
	if filepath.Base(path) != "publication-manifest.json" || filepath.Dir(path) != directory {
		return qualityError(CodeDenied, "publication", "unsafe publication path", nil)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return qualityError(CodeDenied, "publication", "publication marker must not exist", err)
	}
	artifacts := make([]Artifact, 0, len(publicArtifactNames))
	for _, name := range publicArtifactNames {
		artifact, err := digestArtifact(directory, name)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, artifact)
	}
	report, err := ReadAndVerifyReport(filepath.Join(directory, "quality-report.json"))
	if err != nil {
		return err
	}
	if report.Outcome != "passed" || report.QualityGatePromotable != qualityGatePromotable {
		return qualityError(CodeDenied, "publication", "report is not a matching passed verdict", nil)
	}
	manifest := PublicationManifest{
		SchemaVersion: PublicationSchema, Issue: qualityIssue,
		Requirements: slices.Clone(provenanceRequirements), QualityGatePromotable: qualityGatePromotable,
		Artifacts: artifacts,
	}
	if err := finalizePublication(&manifest); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return qualityError(CodeToolFailure, "publication", "cannot encode publication marker", err)
	}
	return writeAtomic(path, append(encoded, '\n'))
}

// VerifyPublicationManifest validates a downloaded public bundle. Its
// directory must contain exactly the five reviewed artifacts and this marker.
func VerifyPublicationManifest(directory, path string) error {
	if filepath.Base(path) != "publication-manifest.json" || filepath.Dir(path) != directory {
		return qualityError(CodeDenied, "publication", "unsafe publication marker path", nil)
	}
	expectedNames := append(slices.Clone(publicArtifactNames), "publication-manifest.json")
	slices.Sort(expectedNames)
	actualNames, err := regularArtifactNames(directory)
	if err != nil {
		return err
	}
	if !slices.Equal(actualNames, expectedNames) {
		return qualityError(CodeDenied, "publication", "public bundle contains missing or unexpected files", nil)
	}
	data, err := readBoundedRegular(path, maximumArtifactSize)
	if err != nil {
		return err
	}
	var manifest PublicationManifest
	if err := decodeStrict(data, &manifest); err != nil {
		return qualityError(CodeDenied, "publication", "invalid publication marker", err)
	}
	if manifest.SchemaVersion != PublicationSchema || manifest.Issue != qualityIssue ||
		!slices.Equal(manifest.Requirements, provenanceRequirements) || len(manifest.Artifacts) != len(publicArtifactNames) {
		return qualityError(CodeDenied, "publication", "unsupported publication contract", nil)
	}
	expectedDigest := manifest.ManifestDigest
	if err := finalizePublication(&manifest); err != nil || manifest.ManifestDigest != expectedDigest {
		return qualityError(CodeDenied, "publication", "publication digest mismatch", err)
	}
	for index, name := range publicArtifactNames {
		actual, err := digestArtifact(directory, name)
		if err != nil || manifest.Artifacts[index] != actual {
			return qualityError(CodeDenied, "publication", "public artifact mismatch", err)
		}
	}
	report, err := ReadAndVerifyReport(filepath.Join(directory, "quality-report.json"))
	if err != nil {
		return err
	}
	if report.Outcome != "passed" || report.QualityGatePromotable != manifest.QualityGatePromotable {
		return qualityError(CodeDenied, "publication", "marker contradicts its quality report", nil)
	}
	return nil
}

// PublishPublicBundleAtomic copies only the reviewed public artifacts to a
// sibling staging directory, verifies the exact downloaded form, and renames
// it into place. The publication marker is copied last and is the commit point.
func PublishPublicBundleAtomic(ctx context.Context, source, destination string) error {
	return publishPublicBundleAtomic(ctx, source, destination, nil, nil)
}

func publishPublicBundleAtomic(ctx context.Context, source, destination string, beforeRename, afterRename func()) error {
	if err := checkContext(ctx, "publication"); err != nil {
		return err
	}
	if filepath.Clean(destination) != destination || destination == source || filepath.Dir(destination) != filepath.Dir(source) {
		return qualityError(CodeDenied, "publication", "public bundle must be a clean sibling path", nil)
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return qualityError(CodeDenied, "publication", "public bundle destination must not exist", err)
	}
	staging, err := os.MkdirTemp(filepath.Dir(destination), ".coh-public-*")
	if err != nil {
		return qualityError(CodeToolFailure, "publication", "cannot create public staging directory", err)
	}
	complete := false
	renamed := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(staging)
			if renamed {
				_ = os.RemoveAll(destination)
			}
		}
	}()
	for _, name := range append(slices.Clone(publicArtifactNames), "publication-manifest.json") {
		if err := checkContext(ctx, "publication"); err != nil {
			return err
		}
		if err := copyPublicArtifact(filepath.Join(source, name), filepath.Join(staging, name)); err != nil {
			return err
		}
	}
	if err := VerifyPublicationManifest(staging, filepath.Join(staging, "publication-manifest.json")); err != nil {
		return err
	}
	if err := SyncEvidenceBundle(staging); err != nil {
		return err
	}
	if beforeRename != nil {
		beforeRename()
	}
	if err := checkContext(ctx, "publication"); err != nil {
		return err
	}
	if err := os.Rename(staging, destination); err != nil {
		return qualityError(CodeToolFailure, "publication", "cannot commit public bundle", err)
	}
	renamed = true
	if afterRename != nil {
		afterRename()
	}
	parent, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return qualityError(CodeToolFailure, "publication", "cannot open publication parent", err)
	}
	if err := errors.Join(parent.Sync(), parent.Close()); err != nil {
		return qualityError(CodeToolFailure, "publication", "cannot sync publication parent", err)
	}
	if err := VerifyPublicationManifest(destination, filepath.Join(destination, "publication-manifest.json")); err != nil {
		return err
	}
	complete = true
	return nil
}

// CheckContext converts cancellation and deadline expiry to the quality
// contract's stable typed errors.
func CheckContext(ctx context.Context, field string) error {
	return checkContext(ctx, field)
}

func checkContext(ctx context.Context, field string) error {
	select {
	case <-ctx.Done():
		return contextQualityError(ctx.Err(), field)
	default:
		return nil
	}
}

func copyPublicArtifact(source, destination string) error {
	data, err := readBoundedRegular(source, maximumArtifactSize)
	if err != nil {
		return err
	}
	return writeAtomic(destination, data)
}

func finalizePublication(manifest *PublicationManifest) error {
	manifest.ManifestDigest = ""
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return qualityError(CodeToolFailure, "publication", "cannot canonicalize marker", err)
	}
	sum := sha256.Sum256(canonical)
	manifest.ManifestDigest = hex.EncodeToString(sum[:])
	return nil
}
