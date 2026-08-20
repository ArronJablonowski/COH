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
	"strings"

	"github.com/ArronJablonowski/COH/internal/helper/filesize"
)

const provenanceSchema = "coh.ci-provenance/v1"

var provenanceMaterials = []string{
	".github/workflows/quality.yml",
	"ci/dependencies.allow",
	"ci/fuzz-targets.txt",
	"ci/file-size-policy.json",
	"ci/gitleaks.ignore",
	"ci/gitleaks.toml",
	"ci/govulndb.lock.json",
	"ci/go-mod-tidy.expected.diff",
	"ci/licenses.allow",
	"ci/quality-policy.json",
	"ci/release-policy.json",
	"ci/tools.lock.json",
	"contracts/file-size/v1/file-size-policy.schema.json",
	"contracts/supply-chain/v1/keys/ci-fixture-ed25519.pem",
	"contracts/supply-chain/v1/release-policy.schema.json",
	"scripts/bootstrap_ci_tools.sh",
	"scripts/check_dependencies.sh",
	"scripts/check_dependency_allowlist.sh",
	"scripts/check_fuzz_seeds.sh",
	"scripts/check_file_sizes.sh",
	"scripts/check_go_architecture.sh",
	"scripts/check_licenses.sh",
	"scripts/check_secrets.sh",
	"scripts/check_static_analysis.sh",
	"scripts/check_supply_chain.sh",
	"scripts/check_workflow_policy.sh",
	"scripts/ci_stage.sh",
	"scripts/lib/ci_env.sh",
	"scripts/lib/quality_status.sh",
	"scripts/lib/storage_contract.sh",
	"scripts/lib/tool_promotion.sh",
	"scripts/install_release.sh",
	"scripts/prepare_vulndb.sh",
	"scripts/run_architecture_gate.sh",
	"scripts/run_ci_quality.sh",
	"scripts/test_ci_quality.sh",
	"scripts/test_ci_storage.sh",
	"scripts/test_license_contract.sh",
	"scripts/test_policy_status.sh",
	"scripts/test_secret_contract.sh",
	"scripts/test_release_lifecycle.sh",
	"scripts/test_tool_promotion.sh",
	"third_party/offline-packs/go-vulndb/NOTICE.md",
	"third_party/offline-packs/go-vulndb/vulndb-2026-08-19.zip",
}

var provenanceRequirements = []string{"NFR-027", "EVAL-029"}

const (
	provenancePredicate = "https://coh.invalid/provenance/ci-quality/v1"
	provenanceBuildType = "https://coh.invalid/build-types/ci-quality/v1"
	qualityIssue        = "COH-E02-02 / CYB-33"
)

type CIProvenance struct {
	SchemaVersion   string     `json:"schema_version"`
	PredicateType   string     `json:"predicate_type"`
	BuildType       string     `json:"build_type"`
	Issue           string     `json:"issue"`
	Requirements    []string   `json:"requirements"`
	Materials       []Artifact `json:"materials"`
	Subjects        []Artifact `json:"subjects"`
	StatementDigest string     `json:"statement_digest"`
}

// GenerateProvenance binds fixed CI inputs and every artifact produced before
// the provenance stage. Release signing and release provenance remain CYB-37.
func GenerateProvenance(ctx context.Context, root, artifactDirectory, output string) error {
	if err := ctx.Err(); err != nil {
		return contextQualityError(err, "provenance")
	}
	materials := make([]Artifact, 0, len(provenanceMaterials))
	for _, relative := range provenanceMaterials {
		artifact, err := digestPath(root, relative)
		if err != nil {
			return err
		}
		artifact.Path = "repo/" + relative
		materials = append(materials, artifact)
	}
	subjects, err := artifactSubjects(artifactDirectory)
	if err != nil {
		return err
	}
	statement := CIProvenance{
		SchemaVersion: provenanceSchema,
		PredicateType: provenancePredicate,
		BuildType:     provenanceBuildType,
		Issue:         qualityIssue, Requirements: slices.Clone(provenanceRequirements),
		Materials: materials, Subjects: subjects,
	}
	if err := finalizeProvenance(&statement); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(statement, "", "  ")
	if err != nil {
		return qualityError(CodeToolFailure, "provenance", "cannot encode statement", err)
	}
	if err := writeAtomic(output, append(encoded, '\n')); err != nil {
		return err
	}
	return VerifyProvenance(root, artifactDirectory, output)
}

func VerifyProvenance(root, artifactDirectory, path string) error {
	data, err := readBoundedRegular(path, maximumArtifactSize)
	if err != nil {
		return qualityError(CodeToolFailure, "provenance", "cannot read statement", err)
	}
	var statement CIProvenance
	if err := decodeStrict(data, &statement); err != nil {
		return qualityError(CodeInvalidInput, "provenance", "invalid statement", err)
	}
	if statement.SchemaVersion != provenanceSchema || statement.PredicateType != provenancePredicate ||
		statement.BuildType != provenanceBuildType || statement.Issue != qualityIssue ||
		!slices.Equal(statement.Requirements, provenanceRequirements) {
		return qualityError(CodeDenied, "provenance", "unsupported statement contract", nil)
	}
	expectedDigest := statement.StatementDigest
	if err := finalizeProvenance(&statement); err != nil || statement.StatementDigest != expectedDigest {
		return qualityError(CodeDenied, "provenance", "statement digest mismatch", err)
	}
	expectedMaterials := make([]Artifact, 0, len(provenanceMaterials))
	for _, relative := range provenanceMaterials {
		actual, err := digestPath(root, relative)
		if err != nil {
			return err
		}
		actual.Path = "repo/" + relative
		expectedMaterials = append(expectedMaterials, actual)
	}
	if !slices.Equal(statement.Materials, expectedMaterials) {
		return qualityError(CodeDenied, "provenance", "material set or order mismatch", nil)
	}
	expectedSubjects, err := artifactSubjects(artifactDirectory)
	if err != nil {
		return err
	}
	if !slices.Equal(statement.Subjects, expectedSubjects) {
		return qualityError(CodeDenied, "provenance", "subject set, order, or digest mismatch", nil)
	}
	return nil
}

// VerifyEvidenceBundle checks the final report against the already verified
// provenance statement and rejects missing, duplicate, or uncovered evidence.
func VerifyEvidenceBundle(ctx context.Context, root, artifactDirectory, reportPath string, report Report) error {
	if err := ctx.Err(); err != nil {
		return contextQualityError(err, "evidence")
	}
	if filepath.Base(reportPath) != "quality-report.json" {
		return qualityError(CodeDenied, "evidence", "unexpected report name", nil)
	}
	diskReport, err := ReadAndVerifyReport(reportPath)
	if err != nil {
		return err
	}
	if !reportsEqual(diskReport, report) {
		return qualityError(CodeDenied, "evidence", "on-disk report differs from evaluated verdict", nil)
	}
	if err := verifyQualitySourceBinding(ctx, root, report); err != nil {
		return err
	}
	if err := verifyFileSizeEvidenceBinding(ctx, root, artifactDirectory, report); err != nil {
		return err
	}
	provenancePath := filepath.Join(artifactDirectory, "ci-provenance.json")
	if err := VerifyProvenance(root, artifactDirectory, provenancePath); err != nil {
		return err
	}
	data, err := readBoundedRegular(provenancePath, maximumArtifactSize)
	if err != nil {
		return qualityError(CodeToolFailure, "evidence", "cannot read final provenance", err)
	}
	var statement CIProvenance
	if err := decodeStrict(data, &statement); err != nil {
		return qualityError(CodeDenied, "evidence", "invalid final provenance", err)
	}
	seen := make(map[string]struct{})
	preProvenance := make([]string, 0)
	allExpected := []string{"quality-report.json"}
	for _, stage := range report.Stages {
		for _, name := range stage.Evidence {
			if _, duplicate := seen[name]; duplicate {
				return qualityError(CodeDenied, "evidence", "duplicate evidence reference", nil)
			}
			seen[name] = struct{}{}
			allExpected = append(allExpected, name)
			if err := verifyStageArtifact(artifactDirectory, stage.ID, name); err != nil {
				return err
			}
			if name != "provenance.log" && name != "ci-provenance.json" {
				preProvenance = append(preProvenance, name)
			}
		}
	}
	slices.Sort(preProvenance)
	subjectPaths := make([]string, len(statement.Subjects))
	for index, subject := range statement.Subjects {
		subjectPaths[index] = subject.Path
	}
	if !slices.Equal(subjectPaths, preProvenance) {
		return qualityError(CodeDenied, "evidence", "provenance subjects do not exactly match pre-provenance evidence", nil)
	}
	slices.Sort(allExpected)
	actual, err := regularArtifactNames(artifactDirectory)
	if err != nil {
		return err
	}
	if !slices.Equal(actual, allExpected) {
		return qualityError(CodeDenied, "evidence", "artifact directory contains missing or unexpected files", nil)
	}
	return nil
}

func verifyQualitySourceBinding(ctx context.Context, root string, report Report) error {
	snapshot, err := SnapshotWorkspace(ctx, root)
	if err != nil {
		return err
	}
	if snapshot.Digest != report.Provenance.SourceDigest || snapshot.FileCount != report.Provenance.SourceFiles ||
		snapshot.VCSRevision != report.Provenance.VCSRevision || snapshot.VCSModified != report.Provenance.VCSModified {
		return qualityError(CodeDenied, "evidence.source", "final source differs from the evaluated quality snapshot", nil)
	}
	return nil
}

func verifyFileSizeEvidenceBinding(ctx context.Context, root, artifactDirectory string, outer Report) error {
	nested, err := filesize.ReadAndVerifyReport(filepath.Join(artifactDirectory, "file-size-report.json"))
	if err != nil {
		return qualityError(CodeDenied, "evidence.file-size", "cannot verify nested file-size report", err)
	}
	snapshot, err := (filesize.OSSource{}).Snapshot(ctx, root)
	if err != nil {
		return qualityError(CodeDenied, "evidence.file-size", "cannot reproduce file-size source snapshot", err)
	}
	policyData, err := readBoundedRegular(filepath.Join(root, "ci", "file-size-policy.json"), filesize.MaximumPolicySize)
	if err != nil {
		return qualityError(CodeDenied, "evidence.file-size", "cannot read file-size policy", err)
	}
	policy, err := filesize.DecodePolicy(policyData)
	if err != nil {
		return qualityError(CodeDenied, "evidence.file-size", "cannot decode file-size policy", err)
	}
	policyDigest, err := filesize.PolicyDigest(policy)
	if err != nil {
		return qualityError(CodeDenied, "evidence.file-size", "cannot bind file-size policy", err)
	}
	exceptionsDigest, err := filesize.ExceptionsDigest(policy)
	if err != nil {
		return qualityError(CodeDenied, "evidence.file-size", "cannot bind file-size exceptions", err)
	}
	if nested.SourceDigest != snapshot.Digest || nested.SourceFileCount != snapshot.FileCount ||
		nested.VCSRevision != snapshot.VCSRevision || nested.VCSModified != snapshot.VCSModified ||
		nested.PolicyDigest != policyDigest || nested.ExceptionsDigest != exceptionsDigest ||
		nested.SourceFileCount != outer.Provenance.SourceFiles ||
		nested.VCSRevision != outer.Provenance.VCSRevision || nested.VCSModified != outer.Provenance.VCSModified {
		return qualityError(CodeDenied, "evidence.file-size", "nested file-size provenance differs from the final source and quality verdict", nil)
	}
	return nil
}

// WriteEvidenceManifestAtomic publishes the complete post-report inventory.
// The manifest excludes only itself and therefore covers report + provenance.
func WriteEvidenceManifestAtomic(ctx context.Context, artifactDirectory, path string) (EvidenceManifest, error) {
	if err := ctx.Err(); err != nil {
		return EvidenceManifest{}, contextQualityError(err, "evidence_manifest")
	}
	if filepath.Base(path) != "evidence-manifest.json" || filepath.Dir(path) != artifactDirectory {
		return EvidenceManifest{}, qualityError(CodeDenied, "evidence_manifest", "unsafe manifest path", nil)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return EvidenceManifest{}, qualityError(CodeDenied, "evidence_manifest", "manifest output must not exist", err)
	}
	names, err := regularArtifactNames(artifactDirectory, "evidence-manifest.json", "publication-manifest.json")
	if err != nil {
		return EvidenceManifest{}, err
	}
	artifacts := make([]Artifact, 0, len(names))
	for _, name := range names {
		artifact, err := digestArtifact(artifactDirectory, name)
		if err != nil {
			return EvidenceManifest{}, err
		}
		artifacts = append(artifacts, artifact)
	}
	manifest := EvidenceManifest{
		SchemaVersion: EvidenceSchema, Issue: qualityIssue,
		Requirements: slices.Clone(provenanceRequirements), Artifacts: artifacts,
	}
	if err := finalizeEvidenceManifest(&manifest); err != nil {
		return EvidenceManifest{}, err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return EvidenceManifest{}, qualityError(CodeToolFailure, "evidence_manifest", "cannot encode manifest", err)
	}
	if err := writeAtomic(path, append(encoded, '\n')); err != nil {
		return EvidenceManifest{}, err
	}
	if err := VerifyEvidenceManifest(artifactDirectory, path); err != nil {
		return EvidenceManifest{}, err
	}
	return manifest, nil
}

// VerifyEvidenceManifest enforces exact artifact membership, order, length,
// and digest. Unexpected regular files, directories, and symlinks are denied.
func VerifyEvidenceManifest(artifactDirectory, path string) error {
	data, err := readBoundedRegular(path, maximumArtifactSize)
	if err != nil {
		return err
	}
	var manifest EvidenceManifest
	if err := decodeStrict(data, &manifest); err != nil {
		return qualityError(CodeDenied, "evidence_manifest", "invalid manifest", err)
	}
	if manifest.SchemaVersion != EvidenceSchema || manifest.Issue != qualityIssue ||
		!slices.Equal(manifest.Requirements, provenanceRequirements) {
		return qualityError(CodeDenied, "evidence_manifest", "unsupported manifest contract", nil)
	}
	expectedDigest := manifest.ManifestDigest
	if err := finalizeEvidenceManifest(&manifest); err != nil || manifest.ManifestDigest != expectedDigest {
		return qualityError(CodeDenied, "evidence_manifest", "manifest digest mismatch", err)
	}
	names, err := regularArtifactNames(artifactDirectory, "evidence-manifest.json", "publication-manifest.json")
	if err != nil {
		return err
	}
	expected := make([]Artifact, 0, len(names))
	for _, name := range names {
		artifact, err := digestArtifact(artifactDirectory, name)
		if err != nil {
			return err
		}
		expected = append(expected, artifact)
	}
	if !slices.Equal(manifest.Artifacts, expected) {
		return qualityError(CodeDenied, "evidence_manifest", "artifact set, order, or digest mismatch", nil)
	}
	return nil
}

func finalizeEvidenceManifest(manifest *EvidenceManifest) error {
	manifest.ManifestDigest = ""
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return qualityError(CodeToolFailure, "evidence_manifest", "cannot canonicalize manifest", err)
	}
	sum := sha256.Sum256(canonical)
	manifest.ManifestDigest = hex.EncodeToString(sum[:])
	return nil
}

func regularArtifactNames(directory string, excluded ...string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, qualityError(CodeToolFailure, "evidence", "cannot list artifact directory", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if slices.Contains(excluded, name) {
			continue
		}
		if strings.HasPrefix(name, ".") || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil, qualityError(CodeDenied, "evidence", "unexpected non-regular or hidden artifact: "+name, nil)
		}
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

// SyncEvidenceBundle makes shell-produced files durable before a successful
// report can become quality-gate promotable.
func SyncEvidenceBundle(directory string) error {
	names, err := regularArtifactNames(directory)
	if err != nil {
		return err
	}
	for _, name := range names {
		file, err := os.Open(filepath.Join(directory, name))
		if err != nil {
			return qualityError(CodeToolFailure, "evidence", "cannot open artifact for sync", err)
		}
		syncErr := file.Sync()
		closeErr := file.Close()
		if syncErr != nil || closeErr != nil {
			return qualityError(CodeToolFailure, "evidence", "cannot sync artifact", errors.Join(syncErr, closeErr))
		}
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return qualityError(CodeToolFailure, "evidence", "cannot open artifact directory", err)
	}
	err = errors.Join(directoryHandle.Sync(), directoryHandle.Close())
	if err != nil {
		return qualityError(CodeToolFailure, "evidence", "cannot sync artifact directory", err)
	}
	return nil
}

func reportsEqual(left, right Report) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func artifactSubjects(directory string) ([]Artifact, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, qualityError(CodeToolFailure, "provenance", "cannot list evidence directory", err)
	}
	subjects := make([]Artifact, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || name == "ci-provenance.json" || name == "quality-report.json" || name == "provenance.log" {
			continue
		}
		artifact, err := digestArtifact(directory, name)
		if err != nil {
			return nil, err
		}
		subjects = append(subjects, artifact)
	}
	if len(subjects) == 0 {
		return nil, qualityError(CodeDenied, "provenance", "no run evidence exists", nil)
	}
	slices.SortFunc(subjects, func(a, b Artifact) int { return strings.Compare(a.Path, b.Path) })
	return subjects, nil
}

func digestPath(root, relative string) (Artifact, error) {
	clean := filepath.Clean(relative)
	if clean == "." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return Artifact{}, qualityError(CodeDenied, "artifact", "unsafe path", nil)
	}
	directory := filepath.Join(root, filepath.Dir(clean))
	artifact, err := digestArtifact(directory, filepath.Base(clean))
	if err != nil {
		return Artifact{}, err
	}
	artifact.Path = filepath.ToSlash(clean)
	return artifact, nil
}

func finalizeProvenance(statement *CIProvenance) error {
	statement.StatementDigest = ""
	canonical, err := json.Marshal(statement)
	if err != nil {
		return qualityError(CodeToolFailure, "provenance", "cannot canonicalize statement", err)
	}
	sum := sha256.Sum256(canonical)
	statement.StatementDigest = hex.EncodeToString(sum[:])
	return nil
}
