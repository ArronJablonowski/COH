package filesize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCheckerRejectsUntrustedSourceContractViolations(t *testing.T) {
	baseSource := newMemorySource(map[string][]byte{"docs/input.md": []byte("safe\n")})
	base, err := baseSource.Snapshot(context.Background(), "ignored")
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	cases := map[string]func(*Snapshot){
		"unsafe_path": func(value *Snapshot) { value.Records[0].Path = "../escape"; refreshSnapshot(value) },
		"oversize_path": func(value *Snapshot) {
			value.Records[0].Path = strings.Repeat("p", MaximumPathSize+1)
			refreshSnapshot(value)
		},
		"oversize":          func(value *Snapshot) { value.Records[0].Length = MaximumInputSize + 1; refreshSnapshot(value) },
		"bad_mode":          func(value *Snapshot) { value.Records[0].Mode = uint32(os.ModeSymlink | 0o777); refreshSnapshot(value) },
		"exec_mismatch":     func(value *Snapshot) { value.Records[0].Executable = true; refreshSnapshot(value) },
		"identity_oversize": func(value *Snapshot) { value.Records[0].Identity = strings.Repeat("i", MaximumIdentitySize+1) },
		"identity_control":  func(value *Snapshot) { value.Records[0].Identity = "bad\nidentity" },
		"bad_hash":          func(value *Snapshot) { value.Records[0].SHA256 = strings.Repeat("b", 64); refreshSnapshot(value) },
		"bad_digest":        func(value *Snapshot) { value.Digest = strings.Repeat("c", 64) },
		"count":             func(value *Snapshot) { value.FileCount++ },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			snapshot := base
			snapshot.Records = slices.Clone(base.Records)
			mutate(&snapshot)
			source := newMemorySource(map[string][]byte{"docs/input.md": []byte("safe\n")})
			source.snapshotHook = func(_ int, _ Snapshot) (Snapshot, error) { return snapshot, nil }
			_, err := NewChecker(source).Check(context.Background(), Request{Root: "ignored", Policy: validPolicy()})
			requireCode(t, err, CodeDenied)
		})
	}

	duplicate := base
	duplicate.Records = append(slices.Clone(base.Records), base.Records[0])
	duplicate.FileCount = 2
	refreshSnapshot(&duplicate)
	source := newMemorySource(map[string][]byte{"docs/input.md": []byte("safe\n")})
	source.snapshotHook = func(_ int, _ Snapshot) (Snapshot, error) { return duplicate, nil }
	_, err = NewChecker(source).Check(context.Background(), Request{Root: "ignored", Policy: validPolicy()})
	requireCode(t, err, CodeDenied)
}

func TestCanonicalSnapshotExcludesRuntimeIdentityAndNonsemanticMode(t *testing.T) {
	left := newMemorySource(map[string][]byte{"scripts/tool.sh": []byte("#!/bin/bash\n")})
	left.files["scripts/tool.sh"] = memoryFile{data: []byte("#!/bin/bash\n"), mode: 0o755}
	leftSnapshot, _ := left.Snapshot(context.Background(), "ignored")
	rightSnapshot := leftSnapshot
	rightSnapshot.Records = slices.Clone(leftSnapshot.Records)
	rightSnapshot.Records[0].Mode = 0o555
	rightSnapshot.Records[0].Identity = "other-device:other-inode"
	refreshSnapshot(&rightSnapshot)
	if err := validateSnapshot(leftSnapshot); err != nil {
		t.Fatalf("validateSnapshot(left) error = %v", err)
	}
	if err := validateSnapshot(rightSnapshot); err != nil {
		t.Fatalf("validateSnapshot(right) error = %v", err)
	}
	if leftSnapshot.Digest != rightSnapshot.Digest {
		t.Fatal("runtime identity or nonsemantic permission bits changed canonical source digest")
	}
	rightSnapshot.Records[0].Executable = false
	rightSnapshot.Records[0].Mode = 0o444
	refreshSnapshot(&rightSnapshot)
	if leftSnapshot.Digest == rightSnapshot.Digest {
		t.Fatal("executable status did not change canonical source digest")
	}
}

func TestCheckerRejectsReadMismatchAndSourceRace(t *testing.T) {
	for name, hook := range map[string]func(context.Context, FileRecord) ([]byte, error){
		"length_hash": func(context.Context, FileRecord) ([]byte, error) { return []byte("changed\n"), nil },
		"oversize": func(context.Context, FileRecord) ([]byte, error) {
			return bytes.Repeat([]byte{'x'}, MaximumInputSize+1), nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			source := newMemorySource(map[string][]byte{"docs/input.md": []byte("safe\n")})
			source.readHook = hook
			report, err := NewChecker(source).Check(context.Background(), Request{Root: "ignored", Policy: validPolicy()})
			requireCode(t, err, CodeDenied)
			if report.SchemaVersion == "" || report.ScanComplete {
				t.Fatalf("partial denial report=%+v", report)
			}
		})
	}

	source := newMemorySource(map[string][]byte{"docs/input.md": []byte("safe\n")})
	source.snapshotHook = func(call int, snapshot Snapshot) (Snapshot, error) {
		if call == 2 {
			snapshot.VCSModified = true
		}
		return snapshot, nil
	}
	report, err := NewChecker(source).Check(context.Background(), Request{Root: "ignored", Policy: validPolicy()})
	requireCode(t, err, CodeDenied)
	if !report.ScanComplete {
		t.Fatal("post-scan source race must retain complete scan provenance")
	}
}

func TestCheckerCancellationTimeoutAndRecovery(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if report, err := NewChecker(newMemorySource(map[string][]byte{"a.txt": []byte("x\n")})).Check(canceled, Request{Root: "ignored", Policy: validPolicy()}); CodeOf(err) != CodeCanceled || report.SchemaVersion != "" {
		t.Fatalf("preflight cancel report=%+v error=%v", report, err)
	}

	source := newMemorySource(map[string][]byte{"a.txt": []byte("x\n")})
	source.readHook = func(ctx context.Context, _ FileRecord) ([]byte, error) {
		<-ctx.Done()
		return nil, contextError(ctx.Err(), "source")
	}
	deadline, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	report, err := NewChecker(source).Check(deadline, Request{Root: "ignored", Policy: validPolicy()})
	requireCode(t, err, CodeTimeout)
	if report.Outcome != "timeout" || report.ScanComplete {
		t.Fatalf("timeout report=%+v", report)
	}

	recovered, err := runMemoryCheck(t, map[string][]byte{"a.txt": []byte("x\n")}, validPolicy(), "2026-08-19")
	requirePassed(t, recovered, err)
}

func TestCheckerRejectsSuccessReturnedAfterContextTermination(t *testing.T) {
	for _, stage := range []string{"initial_snapshot", "read", "final_snapshot"} {
		t.Run(stage+"_cancel", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			source := newMemorySource(map[string][]byte{"a.txt": []byte("x\n")})
			switch stage {
			case "initial_snapshot":
				source.snapshotHook = func(call int, snapshot Snapshot) (Snapshot, error) {
					if call == 1 {
						cancel()
					}
					return snapshot, nil
				}
			case "read":
				source.readHook = func(context.Context, FileRecord) ([]byte, error) {
					cancel()
					return []byte("x\n"), nil
				}
			case "final_snapshot":
				source.snapshotHook = func(call int, snapshot Snapshot) (Snapshot, error) {
					if call == 2 {
						cancel()
					}
					return snapshot, nil
				}
			}
			report, err := NewChecker(source).Check(ctx, Request{Root: "ignored", Policy: validPolicy()})
			requireCode(t, err, CodeCanceled)
			if stage == "initial_snapshot" && report.SchemaVersion != "" || stage != "initial_snapshot" && report.Outcome != "canceled" {
				t.Fatalf("report=%+v", report)
			}
		})
	}

	ctx, stop := context.WithTimeout(context.Background(), time.Millisecond)
	defer stop()
	source := newMemorySource(map[string][]byte{"a.txt": []byte("x\n")})
	source.snapshotHook = func(call int, snapshot Snapshot) (Snapshot, error) {
		if call == 2 {
			<-ctx.Done()
		}
		return snapshot, nil
	}
	report, err := NewChecker(source).Check(ctx, Request{Root: "ignored", Policy: validPolicy()})
	requireCode(t, err, CodeTimeout)
	if report.Outcome != "timeout" || !report.ScanComplete {
		t.Fatalf("report=%+v", report)
	}
}

func TestInitializedInvalidInputReportRoundTrips(t *testing.T) {
	for _, afterScan := range []bool{false, true} {
		t.Run(map[bool]string{false: "read", true: "final_snapshot"}[afterScan], func(t *testing.T) {
			source := newMemorySource(map[string][]byte{"docs/input.md": []byte("safe\n")})
			if afterScan {
				source.snapshotHook = func(call int, snapshot Snapshot) (Snapshot, error) {
					if call == 2 {
						return Snapshot{}, contractError(CodeInvalidInput, "root", "root became invalid", nil)
					}
					return snapshot, nil
				}
			} else {
				source.readHook = func(context.Context, FileRecord) ([]byte, error) {
					return nil, contractError(CodeInvalidInput, "root", "root became invalid", nil)
				}
			}
			report, err := NewChecker(source).Check(context.Background(), Request{Root: "ignored", Policy: validPolicy()})
			requireCode(t, err, CodeInvalidInput)
			if report.Outcome != "error" || report.FailureCode != CodeInvalidInput || report.ScanComplete != afterScan {
				t.Fatalf("report=%+v", report)
			}
			path := filepath.Join(t.TempDir(), "invalid.json")
			if err := WriteReportAtomic(path, &report); err != nil {
				t.Fatalf("WriteReportAtomic() error = %v", err)
			}
			if _, err := ReadAndVerifyReport(path); err != nil {
				t.Fatalf("ReadAndVerifyReport() error = %v", err)
			}
		})
	}
}

func TestReportAtomicDeterminismDenialAndTamperChecks(t *testing.T) {
	report, err := runMemoryCheck(t, map[string][]byte{"docs/long.md": lineData(501)}, validPolicy(), "2026-08-19")
	requirePassed(t, report, err)
	first := filepath.Join(t.TempDir(), "first.json")
	second := filepath.Join(t.TempDir(), "second.json")
	if err := WriteReportAtomic(first, &report); err != nil {
		t.Fatalf("WriteReportAtomic(first) error = %v", err)
	}
	nilFindings := report
	nilFindings.Findings = nil
	if err := WriteReportAtomic(filepath.Join(t.TempDir(), "nil-findings.json"), &nilFindings); err == nil {
		t.Fatal("WriteReportAtomic() accepted nil findings")
	}
	copyReport := report
	copyReport.ReportDigest = ""
	if err := WriteReportAtomic(second, &copyReport); err != nil {
		t.Fatalf("WriteReportAtomic(second) error = %v", err)
	}
	firstData, _ := os.ReadFile(first)
	secondData, _ := os.ReadFile(second)
	if !bytes.Equal(firstData, secondData) {
		t.Fatal("same source, policy, and day did not produce byte-identical reports")
	}
	if _, err := ReadAndVerifyReport(first); err != nil {
		t.Fatalf("ReadAndVerifyReport() error = %v", err)
	}
	if err := WriteReportAtomic(first, &report); CodeOf(err) != CodeDenied {
		t.Fatalf("stale output error=%v", err)
	}

	partialSource := newMemorySource(map[string][]byte{"docs/input.md": []byte("safe\n")})
	partialSource.readHook = func(context.Context, FileRecord) ([]byte, error) { return []byte("changed\n"), nil }
	partial, partialErr := NewChecker(partialSource).Check(context.Background(), Request{Root: "ignored", Policy: validPolicy()})
	requireCode(t, partialErr, CodeDenied)
	partialPath := filepath.Join(t.TempDir(), "partial.json")
	if err := WriteReportAtomic(partialPath, &partial); err != nil {
		t.Fatalf("WriteReportAtomic(partial) error = %v", err)
	}
	if _, err := ReadAndVerifyReport(partialPath); err != nil {
		t.Fatalf("partial denial did not verify: %v", err)
	}

	for name, mutate := range map[string]func(*Report){
		"outcome":           func(value *Report) { value.Outcome = "denied"; value.FailureCode = CodeTimeout },
		"generated_warning": func(value *Report) { value.Findings[0].Class = "generated" },
		"script_approved_801": func(value *Report) {
			value.Findings[0] = Finding{Path: "scripts/legacy.sh", Class: "script", PhysicalLines: 801, Limit: 300, Reason: "approved_exception", TrackingIssue: "CYB-38"}
			value.Counts.Exceptions = 1
		},
		"production_missing_target": func(value *Report) {
			value.Findings[0] = Finding{Path: "internal/missing.go", Class: "production", Limit: 800, Reason: "exception_target_missing", TrackingIssue: "CYB-38"}
			value.Counts.Warnings = 0
			value.Counts.Denials = 1
			value.Outcome = "denied"
			value.FailureCode = CodeDenied
		},
		"warning_for_skipped_source": func(value *Report) {
			value.Counts.Checked = 0
			value.Counts.Skipped = 1
		},
		"script_generated_header": func(value *Report) {
			value.Findings[0] = Finding{Path: "scripts/generated.sh", Class: "script", PhysicalLines: 301, Limit: 300, Reason: "exception_generated_header_missing", TrackingIssue: "CYB-38"}
			value.Counts.Warnings = 0
			value.Counts.Denials = 1
			value.Outcome = "denied"
			value.FailureCode = CodeDenied
		},
		"duplicate_path": func(value *Report) {
			value.Findings = append(value.Findings, Finding{Path: value.Findings[0].Path, Class: "other", PhysicalLines: 801, Limit: 800, Reason: "governed_asset_hard_limit"})
			value.Counts.Denials++
		},
		"overflow":      func(value *Report) { value.Counts.Checked = math.MaxInt; value.Counts.Skipped = math.MaxInt },
		"bad_predicate": func(value *Report) { value.Findings[0].PhysicalLines = 500 },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := report
			tampered.Findings = slices.Clone(report.Findings)
			mutate(&tampered)
			path := filepath.Join(t.TempDir(), "tampered.json")
			writeUncheckedReport(t, path, tampered)
			if _, err := ReadAndVerifyReport(path); err == nil {
				t.Fatal("ReadAndVerifyReport() accepted semantic tampering")
			}
		})
	}
}

func TestWriteReportAtomicCannotOverwriteConcurrentDestination(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "report.json")
	sentinel := []byte("created by competing writer\n")
	publisher := func(temporaryPath, destinationPath string) error {
		if err := os.WriteFile(destinationPath, sentinel, 0o600); err != nil {
			return err
		}
		return publishNoReplace(temporaryPath, destinationPath)
	}
	err := writeAtomicWithPublisher(path, []byte("new report\n"), publisher)
	if CodeOf(err) != CodeDenied {
		t.Fatalf("writeAtomicWithPublisher() error=%v code=%q", err, CodeOf(err))
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile() error=%v", readErr)
	}
	if !bytes.Equal(data, sentinel) {
		t.Fatalf("concurrent destination was overwritten: %q", data)
	}
	matches, globErr := filepath.Glob(filepath.Join(directory, ".file-size-report.*.tmp"))
	if globErr != nil || len(matches) != 0 {
		t.Fatalf("temporary reports remain after denied publication: %q, %v", matches, globErr)
	}
}

func TestReportRejectsNoncanonicalAndWrongJSONTypes(t *testing.T) {
	report, err := runMemoryCheck(t, map[string][]byte{"docs/long.md": lineData(501)}, validPolicy(), "2026-08-19")
	requirePassed(t, report, err)
	path := filepath.Join(t.TempDir(), "canonical.json")
	if err := WriteReportAtomic(path, &report); err != nil {
		t.Fatalf("WriteReportAtomic() error = %v", err)
	}
	canonical, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	replacements := map[string][]byte{
		"invalid_utf8":         append(slices.Clone(canonical), 0xff),
		"case_variant":         bytes.Replace(canonical, []byte(`"vcs_modified"`), []byte(`"VCS_Modified"`), 1),
		"duplicate":            bytes.Replace(canonical, []byte(`"issue": "COH-E02-03 / CYB-38",`), []byte(`"issue": "COH-E02-03 / CYB-38",\n  "issue": "COH-E02-03 / CYB-38",`), 1),
		"null_bool":            bytes.Replace(canonical, []byte(`"vcs_modified": false`), []byte(`"vcs_modified": null`), 1),
		"null_integer":         bytes.Replace(canonical, []byte(`"source_file_count": 1`), []byte(`"source_file_count": null`), 1),
		"null_count":           bytes.Replace(canonical, []byte(`"skipped": 0`), []byte(`"skipped": null`), 1),
		"null_string":          bytes.Replace(canonical, []byte(`"vcs_revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`), []byte(`"vcs_revision": null`), 1),
		"null_failure":         bytes.Replace(canonical, []byte(`"outcome": "passed",`), []byte(`"outcome": "passed",\n  "failure_code": null,`), 1),
		"empty_failure":        bytes.Replace(canonical, []byte(`"outcome": "passed",`), []byte(`"outcome": "passed",\n  "failure_code": "",`), 1),
		"null_tracking":        bytes.Replace(canonical, []byte(`"reason": "warning_threshold"`), []byte(`"reason": "warning_threshold",\n      "tracking_issue": null`), 1),
		"null_finding_integer": bytes.Replace(canonical, []byte(`"physical_lines": 501`), []byte(`"physical_lines": null`), 1),
		"alternate_whitespace": compactReportBytes(t, canonical),
	}
	for name, data := range replacements {
		t.Run(name, func(t *testing.T) {
			candidate := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(candidate, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadAndVerifyReport(candidate); err == nil {
				t.Fatal("ReadAndVerifyReport() accepted a noncanonical or wrongly typed report")
			}
		})
	}
}

func compactReportBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		t.Fatalf("Compact() error = %v", err)
	}
	return append(compact.Bytes(), '\n')
}

func TestReportStableReadRejectsSameInodeModeAndSizeChanges(t *testing.T) {
	report, err := runMemoryCheck(t, map[string][]byte{"docs/input.md": []byte("safe\n")}, validPolicy(), "2026-08-19")
	requirePassed(t, report, err)
	for _, test := range []struct {
		name string
		hook func(string) error
	}{
		{"mode", func(path string) error { return os.Chmod(path, 0o644) }},
		{"size", func(path string) error {
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return err
			}
			_, writeErr := file.WriteString(" ")
			return errors.Join(writeErr, file.Close())
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.json")
			copyReport := report
			copyReport.ReportDigest = ""
			if err := WriteReportAtomic(path, &copyReport); err != nil {
				t.Fatal(err)
			}
			_, err := readStableReport(path, func() error { return test.hook(path) })
			requireCode(t, err, CodeDenied)
		})
	}
}

func TestWriteReportRejectsOversizedEvidence(t *testing.T) {
	report, err := runMemoryCheck(t, map[string][]byte{"docs/input.md": []byte("safe\n")}, validPolicy(), "2026-08-19")
	requirePassed(t, report, err)
	report.SourceFileCount = 2200
	report.Counts = Counts{Checked: 2200, Warnings: 2200}
	report.Findings = make([]Finding, 2200)
	for index := range report.Findings {
		report.Findings[index] = Finding{
			Path:  fmt.Sprintf("docs/%04d/%s.txt", index, strings.Repeat("p", 4000)),
			Class: "other", PhysicalLines: 501, Limit: WarningLimit, Reason: "warning_threshold",
		}
	}
	path := filepath.Join(t.TempDir(), "oversized.json")
	if err := WriteReportAtomic(path, &report); CodeOf(err) != CodeDenied {
		t.Fatalf("WriteReportAtomic() error=%v code=%q", err, CodeOf(err))
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized report was published: %v", err)
	}
}

func TestSplitGitPathsBoundsAndEncoding(t *testing.T) {
	if paths, err := splitGitPaths([]byte("line\nname\x00safe\x00")); err != nil || len(paths) != 2 {
		t.Fatalf("splitGitPaths(newline) = %q, %v", paths, err)
	}
	for _, data := range [][]byte{{0xff, 0}, []byte("truncated"), bytes.Repeat([]byte{'x'}, MaximumInputSize+1)} {
		if _, err := splitGitPaths(data); err == nil {
			t.Fatal("splitGitPaths() accepted invalid inventory")
		}
	}
}

func refreshSnapshot(snapshot *Snapshot) {
	canonical, _ := json.Marshal(snapshot.Records)
	snapshot.Digest = digestBytes(canonical)
}

func writeUncheckedReport(t *testing.T, path string, report Report) {
	t.Helper()
	report.ReportDigest = ""
	canonical, _ := json.Marshal(report)
	report.ReportDigest = digestBytes(canonical)
	data, _ := json.MarshalIndent(report, "", "  ")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
