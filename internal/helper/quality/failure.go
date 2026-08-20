package quality

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
)

// WriteFailureManifestAtomic records a private, content-only inventory for a
// failed run. It never copies or publishes raw failure output.
func WriteFailureManifestAtomic(ctx context.Context, directory, path string, report Report) error {
	if err := checkContext(ctx, "failure_manifest"); err != nil {
		return err
	}
	if filepath.Base(path) != "failure-manifest.json" || filepath.Dir(path) != directory {
		return qualityError(CodeDenied, "failure_manifest", "unsafe failure manifest path", nil)
	}
	if report.Outcome == "passed" || report.FailureCode == "" || report.QualityGatePromotable {
		return qualityError(CodeDenied, "failure_manifest", "failure manifest requires a non-promotable failed report", nil)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return qualityError(CodeDenied, "failure_manifest", "failure manifest output must not exist", err)
	}
	reportPath := filepath.Join(directory, "quality-report.json")
	diskReport, err := ReadAndVerifyReport(reportPath)
	if err != nil || !reportsEqual(diskReport, report) {
		return qualityError(CodeDenied, "failure_manifest", "on-disk failure report mismatch", err)
	}
	names, err := regularArtifactNames(directory, "failure-manifest.json")
	if err != nil {
		return err
	}
	if err := validateFailureArtifactNames(names, report); err != nil {
		return err
	}
	artifacts := make([]Artifact, 0, len(names))
	for _, name := range names {
		artifact, digestErr := digestArtifact(directory, name)
		if digestErr != nil {
			return digestErr
		}
		artifacts = append(artifacts, artifact)
	}
	manifest := FailureManifest{
		SchemaVersion: FailureSchema,
		Issue:         qualityIssue,
		Requirements:  slices.Clone(provenanceRequirements),
		Outcome:       report.Outcome,
		FailureCode:   report.FailureCode,
		Artifacts:     artifacts,
	}
	if err := finalizeFailureManifest(&manifest); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return qualityError(CodeToolFailure, "failure_manifest", "cannot encode failure manifest", err)
	}
	if err := writeAtomic(path, append(encoded, '\n')); err != nil {
		return err
	}
	return VerifyFailureManifest(directory, path)
}

// VerifyFailureManifest verifies exact private failure evidence membership.
func VerifyFailureManifest(directory, path string) error {
	data, err := readBoundedRegular(path, maximumArtifactSize)
	if err != nil {
		return err
	}
	var manifest FailureManifest
	if err := decodeStrict(data, &manifest); err != nil {
		return qualityError(CodeDenied, "failure_manifest", "invalid failure manifest", err)
	}
	if manifest.SchemaVersion != FailureSchema || manifest.Issue != qualityIssue ||
		!slices.Equal(manifest.Requirements, provenanceRequirements) || manifest.Outcome == "passed" ||
		manifest.FailureCode == "" || manifest.Outcome != outcomeFor(manifest.FailureCode) {
		return qualityError(CodeDenied, "failure_manifest", "unsupported failure manifest contract", nil)
	}
	expectedDigest := manifest.ManifestDigest
	if err := finalizeFailureManifest(&manifest); err != nil || manifest.ManifestDigest != expectedDigest {
		return qualityError(CodeDenied, "failure_manifest", "failure manifest digest mismatch", err)
	}
	names, err := regularArtifactNames(directory, "failure-manifest.json")
	if err != nil {
		return err
	}
	report, err := ReadAndVerifyReport(filepath.Join(directory, "quality-report.json"))
	if err != nil {
		return err
	}
	if err := validateFailureArtifactNames(names, report); err != nil {
		return err
	}
	expected := make([]Artifact, 0, len(names))
	for _, name := range names {
		artifact, digestErr := digestArtifact(directory, name)
		if digestErr != nil {
			return digestErr
		}
		expected = append(expected, artifact)
	}
	if !slices.Equal(manifest.Artifacts, expected) {
		return qualityError(CodeDenied, "failure_manifest", "failure artifact set or digest mismatch", nil)
	}
	if report.Outcome != manifest.Outcome || report.FailureCode != manifest.FailureCode || report.QualityGatePromotable {
		return qualityError(CodeDenied, "failure_manifest", "failure marker contradicts its quality report", nil)
	}
	return nil
}

func validateFailureArtifactNames(names []string, report Report) error {
	allowed := map[string]bool{"quality-report.json": true}
	for _, stage := range report.Stages {
		for _, name := range stage.Evidence {
			allowed[name] = true
		}
		if stage.FailureEvidence != nil {
			for _, name := range stageArtifactNames[stage.ID] {
				allowed[name] = true
			}
		}
	}
	for _, name := range names {
		if !allowed[name] {
			return qualityError(CodeDenied, "failure_manifest", "unexpected private failure artifact: "+name, nil)
		}
	}
	if !slices.Contains(names, "quality-report.json") {
		return qualityError(CodeDenied, "failure_manifest", "failure report is missing", nil)
	}
	return nil
}

func finalizeFailureManifest(manifest *FailureManifest) error {
	manifest.ManifestDigest = ""
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return qualityError(CodeToolFailure, "failure_manifest", "cannot canonicalize failure manifest", err)
	}
	sum := sha256.Sum256(canonical)
	manifest.ManifestDigest = hex.EncodeToString(sum[:])
	return nil
}
