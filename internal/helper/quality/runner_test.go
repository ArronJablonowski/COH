package quality

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type fakeExecutor struct {
	failStage          string
	exitCode           int
	block              bool
	successAfterCancel bool
	cancelOnExecute    context.CancelFunc
	mutate             bool
	content            string
}

func (executor *fakeExecutor) Execute(ctx context.Context, request StageRequest) (Execution, error) {
	if executor.block {
		if executor.cancelOnExecute != nil {
			executor.cancelOnExecute()
		}
		<-ctx.Done()
		return Execution{}, contextQualityError(ctx.Err(), "fake")
	}
	if executor.successAfterCancel {
		<-ctx.Done()
		return Execution{ExitCode: 0}, nil
	}
	if executor.mutate {
		executor.mutate = false
		if err := os.WriteFile(filepath.Join(request.Root, "added.go"), []byte("package added\n"), 0o600); err != nil {
			return Execution{}, err
		}
	}
	if request.ID == executor.failStage {
		return Execution{ExitCode: executor.exitCode}, nil
	}
	for _, name := range stageArtifactNames[request.ID] {
		if err := os.WriteFile(filepath.Join(request.ArtifactDir, name), []byte(executor.content+request.ID+"\n"), 0o600); err != nil {
			return Execution{}, err
		}
	}
	return Execution{}, nil
}

func TestRunnerSuccessRecoveryAndDeterministicVerdict(t *testing.T) {
	root := newGitWorkspace(t)
	policy := loadPolicy(t)
	lane := currentTestLane(t)
	firstDirectory := t.TempDir()
	firstExecutor := &fakeExecutor{content: "first-volatile-log-"}
	first, err := (Runner{Executor: firstExecutor}).Run(context.Background(), policy, lane, root, firstDirectory, "lock")
	if err != nil || first.Outcome != "passed" || first.QualityGatePromotable {
		t.Fatalf("first run outcome=%q promotable=%t err=%v", first.Outcome, first.QualityGatePromotable, err)
	}
	if len(first.Stages) != len(requiredStages) {
		t.Fatalf("stage count=%d, want %d", len(first.Stages), len(requiredStages))
	}
	if err := WriteReportAtomic(filepath.Join(firstDirectory, "quality-report.json"), &first); err != nil {
		t.Fatal(err)
	}

	secondDirectory := t.TempDir()
	secondExecutor := &fakeExecutor{content: "different-volatile-log-"}
	second, err := (Runner{Executor: secondExecutor}).Run(context.Background(), policy, lane, root, secondDirectory, "lock")
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteReportAtomic(filepath.Join(secondDirectory, "quality-report.json"), &second); err != nil {
		t.Fatal(err)
	}
	if first.ReportDigest != second.ReportDigest {
		t.Fatalf("verdict digest drifted with raw logs: %s != %s", first.ReportDigest, second.ReportDigest)
	}

	deniedExecutor := &fakeExecutor{failStage: "workflow", exitCode: 2}
	denied, err := (Runner{Executor: deniedExecutor}).Run(context.Background(), policy, lane, root, t.TempDir(), "lock")
	if CodeOf(err) != CodeDenied || denied.Outcome != "denied" || len(denied.Stages) != 2 || len(denied.Stages[1].Evidence) != 0 {
		t.Fatalf("denied report=%+v err=%v", denied, err)
	}

	recovered, err := (Runner{Executor: &fakeExecutor{content: "recovery-"}}).Run(context.Background(), policy, lane, root, t.TempDir(), "lock")
	if err != nil || recovered.Outcome != "passed" {
		t.Fatalf("recovery outcome=%q err=%v", recovered.Outcome, err)
	}
}

func TestRunnerCancellationTimeoutAndSourceRace(t *testing.T) {
	policy := loadPolicy(t)
	root := newGitWorkspace(t)
	lane := currentTestLane(t)
	canceledContext, cancel := context.WithCancel(context.Background())
	canceled, err := (Runner{Executor: &fakeExecutor{block: true, cancelOnExecute: cancel}}).Run(
		canceledContext, policy, lane, root, t.TempDir(), "lock",
	)
	if CodeOf(err) != CodeCanceled || canceled.Outcome != "canceled" || !incompleteFailureEvidence(canceled) {
		t.Fatalf("cancellation report=%+v code=%q err=%v", canceled, CodeOf(err), err)
	}

	timeoutContext, timeoutCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer timeoutCancel()
	timedOut, err := (Runner{Executor: &fakeExecutor{block: true}}).Run(timeoutContext, policy, lane, root, t.TempDir(), "lock")
	if CodeOf(err) != CodeTimeout || timedOut.Outcome != "timeout" || !incompleteFailureEvidence(timedOut) {
		t.Fatalf("timeout report=%+v code=%q err=%v", timedOut, CodeOf(err), err)
	}

	ignoredDeadline, ignoredCancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer ignoredCancel()
	ignored, err := (Runner{Executor: &fakeExecutor{successAfterCancel: true}}).Run(
		ignoredDeadline, policy, lane, root, t.TempDir(), "lock",
	)
	if CodeOf(err) != CodeTimeout || ignored.Outcome != "timeout" {
		t.Fatalf("ignored deadline outcome=%q code=%q err=%v", ignored.Outcome, CodeOf(err), err)
	}

	race, err := (Runner{Executor: &fakeExecutor{mutate: true}}).Run(context.Background(), policy, lane, root, t.TempDir(), "lock")
	if CodeOf(err) != CodeDenied || race.Outcome != "denied" {
		t.Fatalf("source race outcome=%q code=%q err=%v", race.Outcome, CodeOf(err), err)
	}
}

func incompleteFailureEvidence(report Report) bool {
	if len(report.Stages) == 0 {
		return false
	}
	evidence := report.Stages[len(report.Stages)-1].FailureEvidence
	return evidence != nil && evidence.Status == "incomplete" && evidence.Artifact == nil
}

func TestRunnerPreservesPrimaryFailureWhenSnapshotAlsoDrifts(t *testing.T) {
	root := newGitWorkspace(t)
	report, err := (Runner{Executor: &fakeExecutor{
		failStage: "format", exitCode: 1, mutate: true,
	}}).Run(context.Background(), loadPolicy(t), currentTestLane(t), root, t.TempDir(), strings.Repeat("d", 64))
	if CodeOf(err) != CodeToolFailure || report.Outcome != "error" || report.FailureCode != CodeToolFailure {
		t.Fatalf("primary outcome=%q code=%q err=%v", report.Outcome, report.FailureCode, err)
	}
	if report.Verification == nil || report.Verification.Outcome != "denied" || report.Verification.FailureCode != CodeDenied {
		t.Fatalf("secondary verification=%+v", report.Verification)
	}
	path := filepath.Join(t.TempDir(), "quality-report.json")
	if err := WriteReportAtomic(path, &report); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAndVerifyReport(path); err != nil {
		t.Fatalf("self-inconsistent dual failure report: %v", err)
	}
}

func TestRunnerRejectsInvalidConfiguration(t *testing.T) {
	policy := loadPolicy(t)
	root := newGitWorkspace(t)
	_, err := (Runner{Executor: &fakeExecutor{}}).Run(context.Background(), policy, "unknown", root, t.TempDir(), "lock")
	if CodeOf(err) != CodeInvalidInput {
		t.Fatalf("unknown lane code=%q", CodeOf(err))
	}
	_, err = (Runner{}).Run(context.Background(), policy, currentTestLane(t), root, t.TempDir(), "lock")
	if CodeOf(err) != CodeInvalidInput {
		t.Fatalf("nil executor code=%q", CodeOf(err))
	}
}

func TestRunnerRejectsCompilerLaneMismatch(t *testing.T) {
	otherLane := "baseline"
	if currentTestLane(t) == "baseline" {
		otherLane = "go1.27"
	}
	_, err := (Runner{Executor: &fakeExecutor{}}).Run(context.Background(), loadPolicy(t), otherLane, newGitWorkspace(t), t.TempDir(), "lock")
	if CodeOf(err) != CodeDenied {
		t.Fatalf("compiler/lane mismatch code=%q err=%v", CodeOf(err), err)
	}
}

func currentTestLane(t *testing.T) string {
	t.Helper()
	switch runtime.Version() {
	case "go1.26.7":
		return "baseline"
	case "go1.27.0":
		return "go1.27"
	default:
		t.Fatalf("tests are not qualified for %s", runtime.Version())
		return ""
	}
}

func TestStageExitClassification(t *testing.T) {
	tests := []struct {
		exit int
		want ErrorCode
	}{
		{1, CodeToolFailure}, {2, CodeDenied}, {64, CodeInvalidInput},
		{124, CodeTimeout}, {130, CodeCanceled}, {127, CodeToolFailure}, {-1, CodeToolFailure},
	}
	for _, test := range tests {
		err := classifyStageFailure("unit", test.exit, nil, nil)
		if CodeOf(err) != test.want {
			t.Errorf("exit %d => %q, want %q", test.exit, CodeOf(err), test.want)
		}
	}
}

func TestSnapshotIgnoresHostileGitEnvironment(t *testing.T) {
	root := newGitWorkspace(t)
	other := newGitWorkspace(t)
	marker := filepath.Join(t.TempDir(), "fsmonitor-ran")
	hook := filepath.Join(t.TempDir(), "fsmonitor.sh")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nprintf ran > '"+marker+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	config := exec.Command("git", "-C", root, "config", "core.fsmonitor", hook)
	if output, err := config.CombinedOutput(); err != nil {
		t.Fatalf("git config fsmonitor: %v: %s", err, output)
	}
	t.Setenv("GIT_DIR", filepath.Join(other, ".git"))
	t.Setenv("GIT_WORK_TREE", other)
	t.Setenv("GIT_INDEX_FILE", filepath.Join(other, ".git", "index"))
	snapshot, err := SnapshotWorkspace(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.FileCount != 1 || len(snapshot.records) != 1 || snapshot.records[0].Path != "input.txt" {
		t.Fatalf("snapshot redirected by hostile Git environment: %+v", snapshot.records)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("repository fsmonitor executed: %v", err)
	}
}

func TestSnapshotRejectsIgnoredActiveInput(t *testing.T) {
	root := newGitWorkspace(t)
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("ignored.go\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ignored.go"), []byte("package ignored\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SnapshotWorkspace(context.Background(), root); CodeOf(err) != CodeDenied {
		t.Fatalf("ignored Go input code=%q, want denied", CodeOf(err))
	}
}

func TestWriteReportAtomicRejectsBrokenSink(t *testing.T) {
	directory := t.TempDir()
	blockingFile := filepath.Join(directory, "not-a-directory")
	if err := os.WriteFile(blockingFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := WriteReportAtomic(filepath.Join(blockingFile, "report.json"), &Report{})
	if CodeOf(err) != CodeToolFailure {
		t.Fatalf("broken sink code=%q err=%v", CodeOf(err), err)
	}
}

func newGitWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	command := exec.Command("git", "init", "-q", root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(root, "input.txt"), []byte("stable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}
