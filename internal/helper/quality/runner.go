package quality

import (
	"context"
	"errors"
	"runtime"
	"time"
)

type Runner struct {
	Executor Executor
}

func (runner Runner) Run(
	ctx context.Context,
	policy Policy,
	laneID, root, artifactDir, toolLockDigest string,
) (Report, error) {
	if err := ValidatePolicy(policy); err != nil {
		return Report{}, err
	}
	lane, err := SelectLane(policy, laneID)
	if err != nil {
		return Report{}, err
	}
	if runner.Executor == nil {
		return Report{}, qualityError(CodeInvalidInput, "executor", "executor is required", nil)
	}
	if runtime.Version() != "go"+lane.GoVersion {
		return Report{}, qualityError(CodeDenied, "go_version", "runner compiler does not match selected lane", nil)
	}
	before, err := SnapshotWorkspace(ctx, root)
	if err != nil {
		return Report{}, err
	}
	policyDigest, err := PolicyDigest(policy)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		SchemaVersion: ReportSchema, ReportVersion: ReportVersion,
		Issue: "COH-E02-02 / CYB-33", Requirements: []string{"NFR-027", "EVAL-029"},
		Outcome: "running", Lane: lane,
		QualityGatePromotable: false,
		Provenance: Provenance{
			PolicyDigest: policyDigest, ToolLockDigest: toolLockDigest,
			SourceDigest: before.Digest, SourceFiles: before.FileCount,
			VCSRevision: before.VCSRevision, VCSModified: before.VCSModified,
			GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
		},
	}
	for _, stage := range policy.Stages {
		if lane.ID == "go1.27" && stage.ID == "static-analysis" {
			report.Stages = append(report.Stages, StageResult{
				ID: stage.ID, Outcome: "skipped", CommandDigest: commandDigest(stage.ID),
				Note: "Staticcheck 2026.1 is not qualified for Go 1.27; lane remains required-to-pass and non-promoting",
			})
			continue
		}
		stageCtx, cancel := context.WithTimeout(ctx, time.Duration(stage.TimeoutSeconds)*time.Second)
		execution, executeErr := runner.Executor.Execute(stageCtx, StageRequest{
			ID: stage.ID, Root: root, ArtifactDir: artifactDir, Lane: lane.ID,
		})
		stageCause := stageCtx.Err()
		cancel()
		result := StageResult{ID: stage.ID, Outcome: "passed", CommandDigest: commandDigest(stage.ID)}
		if stageCause != nil || executeErr != nil || execution.ExitCode != 0 {
			failure := classifyStageFailure(stage.ID, execution.ExitCode, executeErr, stageCause)
			result.Outcome = outcomeFor(CodeOf(failure))
			result.FailureCode = CodeOf(failure)
			failureEvidence := captureFailureEvidence(artifactDir, stage.ID, execution.ExitCode, result.FailureCode)
			result.FailureEvidence = &failureEvidence
			report.Stages = append(report.Stages, result)
			return finalizeAfterVerification(ctx, root, before, report, failure)
		}
		result.Evidence, err = StageEvidence(artifactDir, stage.ID)
		if err != nil {
			result.Outcome = outcomeFor(CodeOf(err))
			result.FailureCode = CodeOf(err)
			report.Stages = append(report.Stages, result)
			return finalizeAfterVerification(ctx, root, before, report, err)
		}
		report.Stages = append(report.Stages, result)
	}
	report.Outcome = "passed"
	return finalizeAfterVerification(ctx, root, before, report, nil)
}

func classifyStageFailure(stage string, exitCode int, err, contextErr error) error {
	if contextErr != nil {
		return contextQualityError(contextErr, "stage."+stage)
	}
	if err != nil {
		return err
	}
	switch exitCode {
	case 2:
		return qualityError(CodeDenied, "stage."+stage, "quality gate denied completion", nil)
	case 64:
		return qualityError(CodeInvalidInput, "stage."+stage, "stage rejected invalid input", nil)
	case 124:
		return qualityError(CodeTimeout, "stage."+stage, "stage timed out", nil)
	case 130:
		return qualityError(CodeCanceled, "stage."+stage, "stage was canceled", nil)
	default:
		return qualityError(CodeToolFailure, "stage."+stage, "quality stage failed operationally", nil)
	}
}

func finalizeAfterVerification(ctx context.Context, root string, before Snapshot, report Report, prior error) (Report, error) {
	if verifyErr := VerifySnapshot(ctx, root, before); verifyErr != nil {
		report.Verification = &VerificationResult{Outcome: outcomeFor(CodeOf(verifyErr)), FailureCode: CodeOf(verifyErr)}
		if prior == nil {
			report.Outcome = report.Verification.Outcome
			report.FailureCode = report.Verification.FailureCode
			return report, verifyErr
		}
		report.Outcome = outcomeFor(CodeOf(prior))
		report.FailureCode = CodeOf(prior)
		return report, prior
	}
	report.Verification = &VerificationResult{Outcome: "passed"}
	if prior != nil {
		report.Outcome = outcomeFor(CodeOf(prior))
		report.FailureCode = CodeOf(prior)
		return report, prior
	}
	return report, nil
}

func outcomeFor(code ErrorCode) string {
	switch code {
	case CodeDenied:
		return "denied"
	case CodeTimeout:
		return "timeout"
	case CodeCanceled:
		return "canceled"
	default:
		return "error"
	}
}

func IsContextFailure(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
