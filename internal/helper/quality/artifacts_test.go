package quality

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/helper/filesize"
)

func TestStageEvidenceSemanticallyVerifiesFileSizeReport(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "file-size.log"), []byte("passed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	report := filesize.Report{
		SchemaVersion: filesize.ReportSchema, ReportVersion: filesize.ReportVersion,
		Issue: "COH-E02-03 / CYB-38", Requirements: []string{"NFR-016", "NFR-017", "NFR-018", "EVAL-027"},
		Outcome: "passed", PolicyDigest: strings.Repeat("a", 64), ExceptionsDigest: strings.Repeat("b", 64),
		SourceDigest: strings.Repeat("c", 64), SourceFileCount: 1, VCSRevision: strings.Repeat("d", 40),
		EvaluationDate: "2026-08-20", Thresholds: filesize.Thresholds{
			WarningPhysicalLines: 500, HardPhysicalLines: 800, ScriptPhysicalLines: 300,
			NormalMinimumLines: 150, NormalMaximumLines: 400,
		},
		Counts: filesize.Counts{Checked: 1}, ScanComplete: true, Findings: []filesize.Finding{},
	}
	path := filepath.Join(directory, "file-size-report.json")
	if err := filesize.WriteReportAtomic(path, &report); err != nil {
		t.Fatal(err)
	}
	if evidence, err := StageEvidence(directory, "file-size"); err != nil || !slices.Equal(evidence, stageArtifactNames["file-size"]) {
		t.Fatalf("evidence=%v err=%v", evidence, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 1
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StageEvidence(directory, "file-size"); CodeOf(err) != CodeDenied {
		t.Fatalf("tampered file-size report code=%q err=%v", CodeOf(err), err)
	}
}

func TestFinalEvidenceRejectsFileSizeReportSubstitutedAfterStage(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	for stage, names := range stageArtifactNames {
		for _, name := range names {
			if name == "ci-provenance.json" || name == "file-size-report.json" {
				continue
			}
			if err := os.WriteFile(filepath.Join(directory, name), []byte(stage+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	report := boundFileSizeTestReport(t, root)
	fileSizePath := filepath.Join(directory, "file-size-report.json")
	if err := filesize.WriteReportAtomic(fileSizePath, &report); err != nil {
		t.Fatal(err)
	}
	if _, err := StageEvidence(directory, "file-size"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fileSizePath); err != nil {
		t.Fatal(err)
	}
	report.SourceDigest = strings.Repeat("e", 64)
	if err := filesize.WriteReportAtomic(fileSizePath, &report); err != nil {
		t.Fatal(err)
	}
	if err := GenerateProvenance(context.Background(), root, directory, filepath.Join(directory, "ci-provenance.json")); err != nil {
		t.Fatal(err)
	}
	qualityReport := validPassedTestReport()
	qualityReport.Provenance.SourceFiles = report.SourceFileCount
	qualityReport.Provenance.VCSRevision = report.VCSRevision
	qualityReport.Provenance.VCSModified = report.VCSModified
	qualityPath := filepath.Join(directory, "quality-report.json")
	if err := WriteReportAtomic(qualityPath, &qualityReport); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidenceBundle(context.Background(), root, directory, qualityPath, qualityReport); CodeOf(err) != CodeDenied {
		t.Fatalf("substituted file-size report code=%q err=%v", CodeOf(err), err)
	}
}

func TestFinalEvidenceRejectsSameCountSourceMutation(t *testing.T) {
	root := newGitWorkspace(t)
	snapshot, err := SnapshotWorkspace(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	report := validPassedTestReport()
	report.Provenance.SourceDigest = snapshot.Digest
	report.Provenance.SourceFiles = snapshot.FileCount
	report.Provenance.VCSRevision = snapshot.VCSRevision
	report.Provenance.VCSModified = snapshot.VCSModified
	if err := verifyQualitySourceBinding(context.Background(), root, report); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "input.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mutated := slices.Clone(data)
	mutated[0] ^= 1
	if err := os.WriteFile(path, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyQualitySourceBinding(context.Background(), root, report); CodeOf(err) != CodeDenied {
		t.Fatalf("same-count source mutation code=%q err=%v", CodeOf(err), err)
	}
}

func boundFileSizeTestReport(t *testing.T, root string) filesize.Report {
	t.Helper()
	snapshot, err := (filesize.OSSource{}).Snapshot(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "ci", "file-size-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := filesize.DecodePolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := filesize.PolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	exceptionsDigest, err := filesize.ExceptionsDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	report := validFileSizeTestReport()
	report.PolicyDigest, report.ExceptionsDigest = policyDigest, exceptionsDigest
	report.SourceDigest, report.SourceFileCount = snapshot.Digest, snapshot.FileCount
	report.VCSRevision, report.VCSModified = snapshot.VCSRevision, snapshot.VCSModified
	report.Counts = filesize.Counts{Checked: snapshot.FileCount}
	return report
}

func validFileSizeTestReport() filesize.Report {
	return filesize.Report{
		SchemaVersion: filesize.ReportSchema, ReportVersion: filesize.ReportVersion,
		Issue: "COH-E02-03 / CYB-38", Requirements: []string{"NFR-016", "NFR-017", "NFR-018", "EVAL-027"},
		Outcome: "passed", PolicyDigest: strings.Repeat("a", 64), ExceptionsDigest: strings.Repeat("b", 64),
		SourceDigest: strings.Repeat("c", 64), SourceFileCount: 1, VCSRevision: strings.Repeat("d", 40),
		EvaluationDate: "2026-08-20", Thresholds: filesize.Thresholds{
			WarningPhysicalLines: 500, HardPhysicalLines: 800, ScriptPhysicalLines: 300,
			NormalMinimumLines: 150, NormalMaximumLines: 400,
		}, Counts: filesize.Counts{Checked: 1}, ScanComplete: true, Findings: []filesize.Finding{},
	}
}

func TestReportReadBackRejectsTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quality-report.json")
	report := validPassedTestReport()
	if err := WriteReportAtomic(path, &report); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAndVerifyReport(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["outcome"] = "denied"
	tampered, _ := json.Marshal(decoded)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAndVerifyReport(path); CodeOf(err) != CodeDenied {
		t.Fatalf("tampered report code=%q, want denied", CodeOf(err))
	}
}

func TestReportReadBackRejectsSemanticContradictions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Report)
	}{
		{name: "promotable unborn", mutate: func(report *Report) { report.QualityGatePromotable = true }},
		{name: "missing evidence", mutate: func(report *Report) { report.Stages[0].Evidence = nil }},
		{name: "wrong order", mutate: func(report *Report) { report.Stages[0], report.Stages[1] = report.Stages[1], report.Stages[0] }},
		{name: "failure mismatch", mutate: func(report *Report) { report.Outcome = "denied" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := validPassedTestReport()
			test.mutate(&report)
			path := filepath.Join(t.TempDir(), "quality-report.json")
			if err := WriteReportAtomic(path, &report); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadAndVerifyReport(path); CodeOf(err) != CodeDenied {
				t.Fatalf("code=%q err=%v, want denied", CodeOf(err), err)
			}
		})
	}
}

func TestEvidenceAndPublicationManifestsRejectTamperAndExtras(t *testing.T) {
	directory := t.TempDir()
	for _, name := range publicArtifactNames {
		if name == "quality-report.json" {
			continue
		}
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report := validPassedTestReport()
	if err := WriteReportAtomic(filepath.Join(directory, "quality-report.json"), &report); err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(directory, "evidence-manifest.json")
	if _, err := WriteEvidenceManifestAtomic(context.Background(), directory, evidencePath); err != nil {
		t.Fatal(err)
	}
	publicationPath := filepath.Join(directory, "publication-manifest.json")
	if err := WritePublicationManifestAtomic(directory, publicationPath, true); CodeOf(err) != CodeDenied {
		t.Fatalf("contradictory marker code=%q, want denied", CodeOf(err))
	}
	if err := WritePublicationManifestAtomic(directory, publicationPath, false); err != nil {
		t.Fatal(err)
	}
	download := filepath.Join(filepath.Dir(directory), filepath.Base(directory)+".public")
	if err := PublishPublicBundleAtomic(context.Background(), directory, download); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublicationManifest(download, filepath.Join(download, "publication-manifest.json")); err != nil {
		t.Fatalf("downloaded public bundle failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(download, "extra.txt"), []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublicationManifest(download, filepath.Join(download, "publication-manifest.json")); CodeOf(err) != CodeDenied {
		t.Fatalf("public bundle extra-file code=%q, want denied", CodeOf(err))
	}
	if err := os.WriteFile(filepath.Join(directory, "exfil.txt"), []byte("unexpected"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEvidenceManifest(directory, evidencePath); CodeOf(err) != CodeDenied {
		t.Fatalf("unexpected artifact code=%q, want denied", CodeOf(err))
	}
	if err := os.WriteFile(filepath.Join(directory, "quality-report.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(download, "extra.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(download, "quality-report.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublicationManifest(download, filepath.Join(download, "publication-manifest.json")); CodeOf(err) != CodeDenied {
		t.Fatalf("publication tamper code=%q, want denied", CodeOf(err))
	}
}

func TestPublicationCommitHonorsCancellationLinearization(t *testing.T) {
	source := makePublicationFixture(t)
	beforeDestination := filepath.Join(filepath.Dir(source), filepath.Base(source)+".before")
	beforeContext, beforeCancel := context.WithCancel(context.Background())
	err := publishPublicBundleAtomic(beforeContext, source, beforeDestination, beforeCancel, nil)
	if CodeOf(err) != CodeCanceled {
		t.Fatalf("pre-commit cancellation code=%q err=%v", CodeOf(err), err)
	}
	if _, statErr := os.Lstat(beforeDestination); !os.IsNotExist(statErr) {
		t.Fatalf("pre-commit destination survived: %v", statErr)
	}

	afterDestination := filepath.Join(filepath.Dir(source), filepath.Base(source)+".after")
	afterContext, afterCancel := context.WithCancel(context.Background())
	if err := publishPublicBundleAtomic(afterContext, source, afterDestination, nil, afterCancel); err != nil {
		t.Fatalf("committed rename must win cancellation race: %v", err)
	}
	if err := VerifyPublicationManifest(afterDestination, filepath.Join(afterDestination, "publication-manifest.json")); err != nil {
		t.Fatal(err)
	}
}

func TestPublicationVerifierRejectsMissingAndReportContradiction(t *testing.T) {
	missing := makePublicationFixture(t)
	if err := os.Remove(filepath.Join(missing, "coh.cdx.json")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublicationManifest(missing, filepath.Join(missing, "publication-manifest.json")); CodeOf(err) != CodeDenied {
		t.Fatalf("missing file code=%q, want denied", CodeOf(err))
	}

	contradiction := makePublicationFixture(t)
	markerPath := filepath.Join(contradiction, "publication-manifest.json")
	data, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	var marker PublicationManifest
	if err := json.Unmarshal(data, &marker); err != nil {
		t.Fatal(err)
	}
	marker.QualityGatePromotable = true
	if err := finalizePublication(&marker); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublicationManifest(contradiction, markerPath); CodeOf(err) != CodeDenied {
		t.Fatalf("contradictory marker code=%q, want denied", CodeOf(err))
	}
}

func TestFailureManifestBindsPrivateEvidenceAndRejectsExtras(t *testing.T) {
	directory := t.TempDir()
	report := validPassedTestReport()
	report.Outcome = "denied"
	report.FailureCode = CodeDenied
	report.Stages = report.Stages[:1]
	report.Stages[0] = StageResult{
		ID: "format", Outcome: "denied", FailureCode: CodeDenied, CommandDigest: commandDigest("format"),
		FailureEvidence: &FailureEvidence{Expected: "format.log", Status: "present", ExitCode: 2},
	}
	if err := os.WriteFile(filepath.Join(directory, "format.log"), []byte("synthetic failure\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact, err := digestArtifact(directory, "format.log")
	if err != nil {
		t.Fatal(err)
	}
	report.Stages[0].FailureEvidence.Artifact = &artifact
	reportPath := filepath.Join(directory, "quality-report.json")
	if err := WriteReportAtomic(reportPath, &report); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "failure-manifest.json")
	if err := WriteFailureManifestAtomic(context.Background(), directory, manifestPath, report); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFailureManifest(directory, manifestPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "exfil.txt"), []byte("synthetic"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFailureManifest(directory, manifestPath); CodeOf(err) != CodeDenied {
		t.Fatalf("extra private evidence code=%q, want denied", CodeOf(err))
	}
}

func makePublicationFixture(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	for _, name := range publicArtifactNames {
		if name != "quality-report.json" {
			if err := os.WriteFile(filepath.Join(directory, name), []byte(name+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	report := validPassedTestReport()
	if err := WriteReportAtomic(filepath.Join(directory, "quality-report.json"), &report); err != nil {
		t.Fatal(err)
	}
	if err := WritePublicationManifestAtomic(directory, filepath.Join(directory, "publication-manifest.json"), false); err != nil {
		t.Fatal(err)
	}
	return directory
}

func validPassedTestReport() Report {
	report := Report{
		SchemaVersion: ReportSchema, ReportVersion: ReportVersion, Issue: qualityIssue,
		Requirements: slices.Clone(provenanceRequirements), Outcome: "passed",
		Lane: Lane{ID: "baseline", GoVersion: "1.26.7", Enforcement: "required"},
		Provenance: Provenance{
			PolicyDigest: strings.Repeat("a", 64), ToolLockDigest: strings.Repeat("b", 64),
			SourceDigest: strings.Repeat("c", 64), SourceFiles: 1, VCSRevision: "unborn",
			VCSModified: true, GoVersion: "go1.26.7", GOOS: "test", GOARCH: "test",
		},
		Verification: &VerificationResult{Outcome: "passed"},
	}
	for _, stage := range requiredStages {
		report.Stages = append(report.Stages, StageResult{
			ID: stage, Outcome: "passed", CommandDigest: commandDigest(stage),
			Evidence: slices.Clone(stageArtifactNames[stage]),
		})
	}
	return report
}

func TestProvenanceRejectsReorderedMaterials(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "format.log"), []byte("passed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "ci-provenance.json")
	if err := GenerateProvenance(context.Background(), root, directory, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var statement CIProvenance
	if err := json.Unmarshal(data, &statement); err != nil {
		t.Fatal(err)
	}
	statement.Materials[0], statement.Materials[1] = statement.Materials[1], statement.Materials[0]
	if err := finalizeProvenance(&statement); err != nil {
		t.Fatal(err)
	}
	tampered, _ := json.Marshal(statement)
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyProvenance(root, directory, path); CodeOf(err) != CodeDenied {
		t.Fatalf("reordered material code=%q, want denied", CodeOf(err))
	}
}
