package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/helper/quality"
)

func TestFinalizeRunWritesPrivateFailureEvidence(t *testing.T) {
	tests := []struct {
		name     string
		code     quality.ErrorCode
		outcome  string
		status   string
		writeLog bool
		exitCode int
	}{
		{name: "denial", code: quality.CodeDenied, outcome: "denied", status: "present", writeLog: true, exitCode: 2},
		{name: "timeout", code: quality.CodeTimeout, outcome: "timeout", status: "incomplete", exitCode: 124},
		{name: "cancellation", code: quality.CodeCanceled, outcome: "canceled", status: "incomplete", exitCode: 130},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			report := testFailureReport(test.code, test.outcome, test.status, test.exitCode)
			if test.writeLog {
				path := filepath.Join(directory, "format.log")
				if err := os.WriteFile(path, []byte("synthetic private failure\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				digest, err := quality.DigestFile(path)
				if err != nil {
					t.Fatal(err)
				}
				report.Stages[0].FailureEvidence.Artifact = &quality.Artifact{
					Path: "format.log", SHA256: digest, Length: 26,
				}
			}
			runErr := &quality.Error{Code: test.code, Field: "stage.format", Detail: "synthetic"}
			reportPath := filepath.Join(directory, "quality-report.json")
			err := finalizeRunEvidence(context.Background(), t.TempDir(), directory, reportPath, &report, runErr)
			if quality.CodeOf(err) != test.code {
				t.Fatalf("code=%q err=%v", quality.CodeOf(err), err)
			}
			manifestPath := filepath.Join(directory, "failure-manifest.json")
			if err := quality.VerifyFailureManifest(directory, manifestPath); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(directory + ".public"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed run published a public bundle: %v", err)
			}
		})
	}
}

func TestFinalizeRunCancellationRemovesUncommittedSuccess(t *testing.T) {
	directory := t.TempDir()
	report := testPassedReport(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reportPath := filepath.Join(directory, "quality-report.json")
	err := finalizeRunEvidence(ctx, t.TempDir(), directory, reportPath, &report, nil)
	if quality.CodeOf(err) != quality.CodeCanceled {
		t.Fatalf("code=%q err=%v", quality.CodeOf(err), err)
	}
	for _, path := range []string{reportPath, filepath.Join(directory, "publication-manifest.json"), directory + ".public"} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("uncommitted success survived at %s: %v", path, statErr)
		}
	}
}

func testFailureReport(code quality.ErrorCode, outcome, status string, exitCode int) quality.Report {
	report := testReportBase()
	report.Outcome = outcome
	report.FailureCode = code
	report.Stages = []quality.StageResult{{
		ID: "format", Outcome: outcome, FailureCode: code,
		CommandDigest: testCommandDigest("format"),
		FailureEvidence: &quality.FailureEvidence{
			Expected: "format.log", Status: status, ExitCode: exitCode,
		},
	}}
	return report
}

func testPassedReport(t *testing.T) quality.Report {
	t.Helper()
	report := testReportBase()
	report.Outcome = "passed"
	data, err := os.ReadFile(filepath.Join("..", "..", "ci", "quality-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := quality.DecodePolicy(data)
	if err != nil {
		t.Fatal(err)
	}
	evidence := map[string][]string{
		"format": {"format.log"}, "workflow": {"workflow.log"},
		"secret-worktree": {"secret-worktree.log"}, "secret-history": {"secret-history.log"},
		"architecture": {"architecture.log", "architecture-report.json"}, "quality-contract": {"quality-contract.log"},
		"vet": {"vet.log"}, "static-analysis": {"static-analysis.log"}, "unit": {"unit.log"},
		"race": {"race.log"}, "fuzz-seed": {"fuzz-seed.log"}, "license": {"license.log"},
		"dependency": {"dependency.log", "govulncheck.sarif", "govulndb-verification.json"},
		"sbom":       {"sbom.log", "coh.cdx.json"}, "secret-evidence": {"secret-evidence.log"},
		"provenance": {"provenance.log", "ci-provenance.json"},
	}
	for _, stage := range policy.Stages {
		result := quality.StageResult{ID: stage.ID, Outcome: "passed", CommandDigest: testCommandDigest(stage.ID), Evidence: evidence[stage.ID]}
		if runtime.Version() == "go1.27.0" && stage.ID == "static-analysis" {
			result.Outcome = "skipped"
			result.Evidence = nil
			result.Note = "Staticcheck 2026.1 is not qualified for Go 1.27; lane remains required-to-pass and non-promoting"
		}
		report.Stages = append(report.Stages, result)
	}
	return report
}

func testReportBase() quality.Report {
	lane := quality.Lane{ID: "baseline", GoVersion: "1.26.7", Enforcement: "required"}
	if runtime.Version() == "go1.27.0" {
		lane = quality.Lane{ID: "go1.27", GoVersion: "1.27.0", Enforcement: "qualification"}
	}
	return quality.Report{
		SchemaVersion: quality.ReportSchema, ReportVersion: quality.ReportVersion,
		Issue: "COH-E02-02 / CYB-33", Requirements: []string{"NFR-027", "EVAL-029"}, Lane: lane,
		Provenance: quality.Provenance{
			PolicyDigest: strings.Repeat("a", 64), ToolLockDigest: strings.Repeat("b", 64),
			SourceDigest: strings.Repeat("c", 64), SourceFiles: 1, VCSRevision: "unborn", VCSModified: true,
			GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		},
		Verification: &quality.VerificationResult{Outcome: "passed"},
	}
}

func testCommandDigest(stage string) string {
	canonical, _ := json.Marshal([]string{"scripts/ci_stage.sh", stage})
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}
