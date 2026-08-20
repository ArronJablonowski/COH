package filesize

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"time"
)

type Checker struct {
	source Source
	now    func() time.Time
}

func NewChecker(source Source) Checker {
	return Checker{source: source, now: time.Now}
}

type Request struct {
	Root   string
	Policy Policy
}

func (checker Checker) Check(ctx context.Context, request Request) (Report, error) {
	if checker.source == nil {
		return Report{}, contractError(CodeInvalidInput, "source", "source is required", nil)
	}
	if err := ValidatePolicy(request.Policy); err != nil {
		return Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return Report{}, contextError(err, "check")
	}
	now := time.Now().UTC()
	if checker.now != nil {
		now = checker.now().UTC()
	}
	date, err := parseDate(now.Format("2006-01-02"))
	if err != nil {
		return Report{}, contractError(CodeToolFailure, "evaluation_date", "trusted clock returned an invalid UTC date", err)
	}
	before, err := checker.source.Snapshot(ctx, request.Root)
	if err != nil {
		return Report{}, err
	}
	if err := ctx.Err(); err != nil {
		return Report{}, contextError(err, "check")
	}
	if err := validateSnapshot(before); err != nil {
		return Report{}, err
	}
	report, err := newReport(request.Policy, before, date)
	if err != nil {
		return Report{}, err
	}
	exceptions := make(map[string]Exception, len(request.Policy.Exceptions))
	seenExceptions := make(map[string]bool, len(request.Policy.Exceptions))
	for _, exception := range request.Policy.Exceptions {
		exceptions[exception.Path] = exception
	}
	for _, record := range before.Records {
		if err := ctx.Err(); err != nil {
			return finishReport(report, contextError(err, "check"))
		}
		data, readErr := checker.source.Read(ctx, request.Root, record)
		if err := ctx.Err(); err != nil {
			return finishReport(report, contextError(err, "check"))
		}
		if readErr != nil {
			return finishReport(report, readErr)
		}
		if len(data) > MaximumInputSize || int64(len(data)) != record.Length || digestBytes(data) != record.SHA256 {
			return finishReport(report, contractError(CodeDenied, "source."+record.Path, "source port returned bytes outside the bound record", nil))
		}
		class := classify(record.Path, record.Mode, data)
		exception, hasException := exceptions[record.Path]
		if hasException {
			seenExceptions[record.Path] = true
		}
		if binaryContent(data) {
			if class == "script" || class == "production" || hasException {
				report.Counts.Checked++
				addDenial(&report, Finding{Path: record.Path, Class: class, Limit: limitFor(class), Reason: "classified_binary_input"})
			} else {
				report.Counts.Skipped++
			}
			continue
		}
		report.Counts.Checked++
		lines := physicalLines(data)
		limit := limitFor(class)
		if hasException {
			reason := validateAppliedException(exception, record, class, lines, data, date)
			if reason != "" {
				addDenial(&report, Finding{record.Path, class, lines, limit, reason, exception.TrackingIssue})
			} else {
				report.Counts.Exceptions++
				addWarning(&report, Finding{record.Path, class, lines, limit, "approved_exception", exception.TrackingIssue})
			}
			continue
		}
		switch {
		case class == "script" && lines > ScriptLimit:
			addDenial(&report, Finding{Path: record.Path, Class: class, PhysicalLines: lines, Limit: ScriptLimit, Reason: "script_limit"})
		case class == "production" && lines > HardLimit:
			addDenial(&report, Finding{Path: record.Path, Class: class, PhysicalLines: lines, Limit: HardLimit, Reason: "production_hard_limit"})
		case class == "other" && lines > HardLimit && governedAssetCandidate(record.Path, data):
			addDenial(&report, Finding{Path: record.Path, Class: class, PhysicalLines: lines, Limit: HardLimit, Reason: "governed_asset_hard_limit"})
		case lines > WarningLimit:
			addWarning(&report, Finding{Path: record.Path, Class: class, PhysicalLines: lines, Limit: WarningLimit, Reason: "warning_threshold"})
		}
	}
	for _, exception := range request.Policy.Exceptions {
		if !seenExceptions[exception.Path] {
			addDenial(&report, Finding{
				Path: exception.Path, Class: exception.Category, Limit: exceptionLimit(exception),
				Reason: "exception_target_missing", TrackingIssue: exception.TrackingIssue,
			})
		}
	}
	report.ScanComplete = true
	after, verifyErr := checker.source.Snapshot(ctx, request.Root)
	if err := ctx.Err(); err != nil {
		return finishReport(report, contextError(err, "check"))
	}
	if verifyErr != nil {
		return finishReport(report, verifyErr)
	}
	if validateErr := validateSnapshot(after); validateErr != nil {
		return finishReport(report, validateErr)
	}
	if before.Digest != after.Digest || before.FileCount != after.FileCount ||
		before.VCSRevision != after.VCSRevision || before.VCSModified != after.VCSModified ||
		!slices.Equal(before.Records, after.Records) {
		return finishReport(report, contractError(CodeDenied, "source", "source changed during evaluation", nil))
	}
	if report.Counts.Denials > 0 {
		return finishReport(report, contractError(CodeDenied, "file_size", "one or more files violate the policy", nil))
	}
	if err := ctx.Err(); err != nil {
		return finishReport(report, contextError(err, "check"))
	}
	report.Outcome = "passed"
	return report, nil
}

func validateSnapshot(snapshot Snapshot) error {
	if snapshot.FileCount < 1 || snapshot.FileCount != len(snapshot.Records) || snapshot.FileCount > MaximumFileCount ||
		!digestPattern.MatchString(snapshot.Digest) || !validRevision(snapshot.VCSRevision) {
		return contractError(CodeDenied, "source", "source snapshot metadata is invalid", nil)
	}
	for index, record := range snapshot.Records {
		if !safeSourcePath(record.Path) || record.Length < 0 || record.Length > MaximumInputSize ||
			!os.FileMode(record.Mode).IsRegular() || record.Executable != (os.FileMode(record.Mode)&0o111 != 0) ||
			!digestPattern.MatchString(record.SHA256) || !safeIdentity(record.Identity) ||
			index > 0 && snapshot.Records[index-1].Path >= record.Path {
			return contractError(CodeDenied, "source", "source snapshot records are unsafe, unsorted, or duplicated", nil)
		}
	}
	canonical, err := json.Marshal(snapshot.Records)
	if err != nil {
		return contractError(CodeToolFailure, "source", "cannot canonicalize source snapshot", err)
	}
	if digestBytes(canonical) != snapshot.Digest {
		return contractError(CodeDenied, "source", "source snapshot digest mismatch", nil)
	}
	return nil
}

func newReport(policy Policy, snapshot Snapshot, date time.Time) (Report, error) {
	policyDigest, err := PolicyDigest(policy)
	if err != nil {
		return Report{}, err
	}
	exceptionsDigest, err := ExceptionsDigest(policy)
	if err != nil {
		return Report{}, err
	}
	return Report{
		SchemaVersion: ReportSchema, ReportVersion: ReportVersion,
		Issue: "COH-E02-03 / CYB-38", Requirements: []string{"NFR-016", "NFR-017", "NFR-018", "EVAL-027"},
		Outcome: "running", PolicyDigest: policyDigest, ExceptionsDigest: exceptionsDigest,
		SourceDigest: snapshot.Digest, SourceFileCount: snapshot.FileCount,
		VCSRevision: snapshot.VCSRevision, VCSModified: snapshot.VCSModified,
		EvaluationDate: date.Format("2006-01-02"), Thresholds: requiredThresholds, Findings: []Finding{},
	}, nil
}

func validateAppliedException(exception Exception, record FileRecord, class string, lines int, data []byte, date time.Time) string {
	expires, _ := parseDate(exception.ExpiresOn)
	if date.After(expires) {
		return "exception_expired"
	}
	if lines <= limitFor(class) {
		return "exception_stale_below_limit"
	}
	if record.SHA256 != exception.ContentSHA256 {
		return "exception_content_digest_mismatch"
	}
	if lines > exception.ApprovedMaxPhysicalLines {
		return "exception_approved_max_exceeded"
	}
	if !exceptionClassMatches(exception, record.Path, class, data) {
		return "exception_class_mismatch"
	}
	if exception.Category != "script" && !generatedHeader(data, exception.Generator) {
		return "exception_generated_header_missing"
	}
	return ""
}

func limitFor(class string) int {
	if class == "script" {
		return ScriptLimit
	}
	return HardLimit
}

func exceptionLimit(exception Exception) int {
	if exception.Category == "script" {
		return ScriptLimit
	}
	return HardLimit
}

func addWarning(report *Report, finding Finding) {
	report.Counts.Warnings++
	report.Findings = append(report.Findings, finding)
}

func addDenial(report *Report, finding Finding) {
	report.Counts.Denials++
	report.Findings = append(report.Findings, finding)
}

func finishReport(report Report, err error) (Report, error) {
	report.FailureCode = CodeOf(err)
	switch report.FailureCode {
	case CodeDenied:
		report.Outcome = "denied"
	case CodeTimeout:
		report.Outcome = "timeout"
	case CodeCanceled:
		report.Outcome = "canceled"
	default:
		report.Outcome = "error"
	}
	slices.SortFunc(report.Findings, func(left, right Finding) int {
		if left.Path != right.Path {
			if left.Path < right.Path {
				return -1
			}
			return 1
		}
		if left.Reason < right.Reason {
			return -1
		}
		if left.Reason > right.Reason {
			return 1
		}
		return 0
	})
	return report, err
}
