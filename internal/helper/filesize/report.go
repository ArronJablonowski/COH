package filesize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maximumReportSize = 8 << 20

func WriteReportAtomic(path string, report *Report) error {
	if report == nil || report.SchemaVersion != ReportSchema {
		return contractError(CodeInvalidInput, "report", "initialized report is required", nil)
	}
	if err := validateReport(*report); err != nil {
		return err
	}
	report.ReportDigest = ""
	canonical, err := json.Marshal(report)
	if err != nil {
		return contractError(CodeToolFailure, "report", "cannot canonicalize report", err)
	}
	report.ReportDigest = digestBytes(canonical)
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return contractError(CodeToolFailure, "report", "cannot encode report", err)
	}
	if len(encoded)+1 > maximumReportSize {
		return contractError(CodeDenied, "report", "report exceeds 8 MiB", nil)
	}
	return writeAtomic(path, append(encoded, '\n'))
}

func ReadAndVerifyReport(path string) (Report, error) {
	data, err := readStableReport(path, nil)
	if err != nil {
		return Report{}, err
	}
	if !utf8.Valid(data) || !json.Valid(data) || !bytes.HasSuffix(data, []byte{'\n'}) {
		return Report{}, contractError(CodeDenied, "report", "report encoding is invalid", nil)
	}
	if err := rejectDuplicateJSONNames(data); err != nil {
		return Report{}, contractError(CodeDenied, "report", "report contains duplicate or malformed JSON", err)
	}
	if err := validateReportJSONShape(data); err != nil {
		return Report{}, contractError(CodeDenied, "report", "report keys differ from the v1 contract", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report Report
	if err := decoder.Decode(&report); err != nil {
		return Report{}, contractError(CodeDenied, "report", "cannot decode report", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Report{}, contractError(CodeDenied, "report", "trailing report data is forbidden", err)
	}
	expected := report.ReportDigest
	report.ReportDigest = ""
	canonical, err := json.Marshal(report)
	if err != nil {
		return Report{}, contractError(CodeToolFailure, "report", "cannot canonicalize report", err)
	}
	report.ReportDigest = expected
	if expected == "" || expected != digestBytes(canonical) {
		return Report{}, contractError(CodeDenied, "report", "report digest mismatch", nil)
	}
	if err := validateReport(report); err != nil {
		return Report{}, err
	}
	canonicalEncoding, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return Report{}, contractError(CodeToolFailure, "report", "cannot re-encode verified report", err)
	}
	if !bytes.Equal(data, append(canonicalEncoding, '\n')) {
		return Report{}, contractError(CodeDenied, "report", "report bytes are not canonical", nil)
	}
	return report, nil
}

func readStableReport(path string, afterOpen func() error) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > maximumReportSize {
		return nil, contractError(CodeDenied, "report", "report must be a bounded regular file", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, contractError(CodeToolFailure, "report", "cannot open report", err)
	}
	if afterOpen != nil {
		if err := afterOpen(); err != nil {
			_ = file.Close()
			return nil, contractError(CodeToolFailure, "report", "report read hook failed", err)
		}
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximumReportSize+1))
	opened, statErr := file.Stat()
	closeErr := file.Close()
	after, finalErr := os.Lstat(path)
	if readErr != nil || statErr != nil || closeErr != nil || finalErr != nil {
		return nil, contractError(CodeToolFailure, "report", "cannot read stable report", errors.Join(readErr, statErr, closeErr, finalErr))
	}
	if len(data) > maximumReportSize || !after.Mode().IsRegular() || !os.SameFile(before, opened) || !os.SameFile(opened, after) ||
		before.Mode() != opened.Mode() || opened.Mode() != after.Mode() ||
		before.Size() != opened.Size() || opened.Size() != after.Size() ||
		!before.ModTime().Equal(opened.ModTime()) || !opened.ModTime().Equal(after.ModTime()) ||
		int64(len(data)) != after.Size() {
		return nil, contractError(CodeDenied, "report", "report identity, mode, or size changed while read", nil)
	}
	return data, nil
}

func validateReportJSONShape(data []byte) error {
	required := []string{
		"counts", "evaluation_date", "exceptions_digest", "findings", "issue", "outcome",
		"policy_digest", "report_digest", "report_version", "requirements", "scan_complete", "schema_version",
		"source_digest", "source_file_count", "thresholds", "vcs_modified", "vcs_revision",
	}
	root, err := exactObject(data, required, []string{"failure_code"})
	if err != nil {
		return err
	}
	if err := requireJSONTypes(root,
		map[string]jsonValueKind{
			"schema_version": jsonString, "report_version": jsonString, "issue": jsonString,
			"outcome": jsonString, "policy_digest": jsonString, "exceptions_digest": jsonString,
			"source_digest": jsonString, "vcs_revision": jsonString, "evaluation_date": jsonString,
			"report_digest": jsonString, "source_file_count": jsonInteger, "vcs_modified": jsonBoolean,
			"scan_complete": jsonBoolean, "requirements": jsonArray, "findings": jsonArray,
			"counts": jsonObject, "thresholds": jsonObject,
		},
	); err != nil {
		return err
	}
	if failure, present := root["failure_code"]; present && !matchesJSONKind(failure, jsonString) {
		return errors.New("failure_code must be a string")
	}
	thresholds, err := exactObject(root["thresholds"], []string{
		"hard_physical_lines", "normal_maximum_lines", "normal_minimum_lines",
		"script_physical_lines", "warning_physical_lines",
	}, nil)
	if err != nil {
		return err
	}
	if err := requireJSONTypes(thresholds, map[string]jsonValueKind{
		"hard_physical_lines": jsonInteger, "normal_maximum_lines": jsonInteger,
		"normal_minimum_lines": jsonInteger, "script_physical_lines": jsonInteger,
		"warning_physical_lines": jsonInteger,
	}); err != nil {
		return err
	}
	counts, err := exactObject(root["counts"], []string{"checked", "denials", "exceptions", "skipped", "warnings"}, nil)
	if err != nil {
		return err
	}
	if err := requireJSONTypes(counts, map[string]jsonValueKind{
		"checked": jsonInteger, "denials": jsonInteger, "exceptions": jsonInteger,
		"skipped": jsonInteger, "warnings": jsonInteger,
	}); err != nil {
		return err
	}
	var findings []json.RawMessage
	trimmed := bytes.TrimSpace(root["findings"])
	if len(trimmed) == 0 || trimmed[0] != '[' || json.Unmarshal(trimmed, &findings) != nil {
		return errors.New("findings must be an array")
	}
	for _, finding := range findings {
		object, err := exactObject(finding, []string{"class", "limit", "path", "physical_lines", "reason"}, []string{"tracking_issue"})
		if err != nil {
			return err
		}
		if err := requireJSONTypes(object, map[string]jsonValueKind{
			"class": jsonString, "limit": jsonInteger, "path": jsonString,
			"physical_lines": jsonInteger, "reason": jsonString,
		}); err != nil {
			return err
		}
		if tracking, present := object["tracking_issue"]; present && !matchesJSONKind(tracking, jsonString) {
			return errors.New("tracking_issue must be a string")
		}
	}
	return nil
}

type jsonValueKind byte

const (
	jsonString jsonValueKind = iota
	jsonInteger
	jsonBoolean
	jsonArray
	jsonObject
)

func requireJSONTypes(object map[string]json.RawMessage, fields map[string]jsonValueKind) error {
	for name, kind := range fields {
		if !matchesJSONKind(object[name], kind) {
			return errors.New(name + " has the wrong JSON type")
		}
	}
	return nil
}

func matchesJSONKind(raw json.RawMessage, kind jsonValueKind) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return false
	}
	switch kind {
	case jsonString:
		return trimmed[0] == '"'
	case jsonInteger:
		if trimmed[0] != '-' && (trimmed[0] < '0' || trimmed[0] > '9') {
			return false
		}
		_, err := strconv.ParseInt(string(trimmed), 10, 64)
		return err == nil
	case jsonBoolean:
		return bytes.Equal(trimmed, []byte("true")) || bytes.Equal(trimmed, []byte("false"))
	case jsonArray:
		return trimmed[0] == '['
	case jsonObject:
		return trimmed[0] == '{'
	default:
		return false
	}
}

func validateReport(report Report) error {
	if report.SchemaVersion != ReportSchema || report.ReportVersion != ReportVersion ||
		report.Issue != "COH-E02-03 / CYB-38" ||
		!slices.Equal(report.Requirements, []string{"NFR-016", "NFR-017", "NFR-018", "EVAL-027"}) ||
		report.Thresholds != requiredThresholds || !digestPattern.MatchString(report.PolicyDigest) ||
		!digestPattern.MatchString(report.ExceptionsDigest) || !digestPattern.MatchString(report.SourceDigest) ||
		report.SourceFileCount < 1 || report.SourceFileCount > MaximumFileCount || report.Findings == nil || !validRevision(report.VCSRevision) || report.EvaluationDate == "" || report.Counts.Checked < 0 ||
		report.Counts.Skipped < 0 || report.Counts.Warnings < 0 || report.Counts.Denials < 0 || report.Counts.Exceptions < 0 {
		return contractError(CodeDenied, "report", "report contract or provenance is incomplete", nil)
	}
	if _, err := parseDate(report.EvaluationDate); err != nil {
		return contractError(CodeDenied, "report", "report evaluation date is invalid", err)
	}
	switch report.Outcome {
	case "passed":
		if report.FailureCode != "" || report.Counts.Denials != 0 || !report.ScanComplete {
			return contractError(CodeDenied, "report", "passed report contradicts denial state", nil)
		}
	case "denied":
		if report.FailureCode != CodeDenied {
			return contractError(CodeDenied, "report", "denied report has the wrong failure code", nil)
		}
	case "timeout":
		if report.FailureCode != CodeTimeout {
			return contractError(CodeDenied, "report", "timeout report has the wrong failure code", nil)
		}
	case "canceled":
		if report.FailureCode != CodeCanceled {
			return contractError(CodeDenied, "report", "canceled report has the wrong failure code", nil)
		}
	case "error":
		if report.FailureCode != CodeToolFailure && report.FailureCode != CodeInvalidInput {
			return contractError(CodeDenied, "report", "failed report lacks typed failure", nil)
		}
	default:
		return contractError(CodeDenied, "report", "unsupported report outcome", nil)
	}
	if !slices.IsSortedFunc(report.Findings, compareFinding) {
		return contractError(CodeDenied, "report", "findings are not canonically sorted", nil)
	}
	warnings, denials, exceptions := 0, 0, 0
	scannedFindings, trackedFindings, missingTargets := 0, 0, 0
	for index, finding := range report.Findings {
		if err := validateFinding(finding); err != nil {
			return err
		}
		if index > 0 && report.Findings[index-1].Path == finding.Path {
			return contractError(CodeDenied, "report", "multiple findings for one path are forbidden", nil)
		}
		if finding.Reason == "warning_threshold" || finding.Reason == "approved_exception" {
			warnings++
		} else {
			denials++
		}
		if finding.Reason == "approved_exception" {
			exceptions++
		}
		if finding.Reason == "exception_target_missing" {
			missingTargets++
		} else {
			scannedFindings++
		}
		if finding.TrackingIssue != "" {
			trackedFindings++
		}
	}
	if report.Counts.Warnings != warnings || report.Counts.Denials != denials || report.Counts.Exceptions != exceptions {
		return contractError(CodeDenied, "report", "finding counts do not match the report", nil)
	}
	if report.Counts.Checked > report.SourceFileCount || report.Counts.Skipped > report.SourceFileCount-report.Counts.Checked {
		return contractError(CodeDenied, "report", "source processing counts exceed the source set", nil)
	}
	if scannedFindings > report.Counts.Checked || trackedFindings > MaximumExceptions ||
		missingTargets > MaximumExceptions || report.Counts.Exceptions > MaximumExceptions {
		return contractError(CodeDenied, "report", "finding cardinality exceeds the checked source or exception policy", nil)
	}
	processed := report.Counts.Checked + report.Counts.Skipped
	if report.ScanComplete && processed != report.SourceFileCount {
		return contractError(CodeDenied, "report", "source processing counts are inconsistent", nil)
	}
	return nil
}

func validateFinding(finding Finding) error {
	if !safeSourcePath(finding.Path) || finding.PhysicalLines < 0 || finding.PhysicalLines > MaximumInputSize {
		return contractError(CodeDenied, "report.finding", "finding identity is invalid", nil)
	}
	reasons := map[string]int{
		"warning_threshold": WarningLimit, "script_limit": ScriptLimit,
		"production_hard_limit": HardLimit, "governed_asset_hard_limit": HardLimit,
		"classified_binary_input": limitFor(finding.Class), "approved_exception": limitFor(finding.Class),
		"exception_expired": limitFor(finding.Class), "exception_stale_below_limit": limitFor(finding.Class),
		"exception_content_digest_mismatch": limitFor(finding.Class), "exception_approved_max_exceeded": limitFor(finding.Class),
		"exception_class_mismatch": limitFor(finding.Class), "exception_generated_header_missing": limitFor(finding.Class),
		"exception_target_missing": exceptionClassLimit(finding.Class),
	}
	expected, exists := reasons[finding.Reason]
	if !exists || finding.Limit != expected {
		return contractError(CodeDenied, "report.finding", "finding reason or limit is invalid", nil)
	}
	scannedClass := finding.Class == "production" || finding.Class == "script" || finding.Class == "other"
	exceptionClass := validCategories[finding.Class]
	switch finding.Reason {
	case "warning_threshold":
		if !scannedClass || finding.Class == "script" || finding.PhysicalLines <= WarningLimit ||
			finding.Class == "production" && finding.PhysicalLines > HardLimit {
			return contractError(CodeDenied, "report.finding", "warning line count is outside its class boundary", nil)
		}
	case "script_limit":
		if finding.Class != "script" || finding.PhysicalLines <= ScriptLimit {
			return contractError(CodeDenied, "report.finding", "script denial does not exceed 300", nil)
		}
	case "production_hard_limit":
		if finding.Class != "production" || finding.PhysicalLines <= HardLimit {
			return contractError(CodeDenied, "report.finding", "production denial is unreachable", nil)
		}
	case "governed_asset_hard_limit":
		if finding.Class != "other" || finding.PhysicalLines <= HardLimit {
			return contractError(CodeDenied, "report.finding", "governed asset denial does not exceed 800", nil)
		}
	case "classified_binary_input":
		if !scannedClass || finding.PhysicalLines != 0 {
			return contractError(CodeDenied, "report.finding", "binary finding is unreachable", nil)
		}
	case "approved_exception":
		if !scannedClass || finding.PhysicalLines <= limitFor(finding.Class) ||
			finding.Class == "script" && finding.PhysicalLines > HardLimit ||
			finding.Class != "script" && finding.PhysicalLines > MaximumApproved {
			return contractError(CodeDenied, "report.finding", "approved exception is not above its base limit", nil)
		}
	case "exception_target_missing":
		if !exceptionClass || finding.PhysicalLines != 0 {
			return contractError(CodeDenied, "report.finding", "missing exception target is unreachable", nil)
		}
	case "exception_expired":
		if !scannedClass {
			return contractError(CodeDenied, "report.finding", "expired exception class is unreachable", nil)
		}
	case "exception_stale_below_limit":
		if !scannedClass || finding.PhysicalLines > limitFor(finding.Class) {
			return contractError(CodeDenied, "report.finding", "stale exception line count is unreachable", nil)
		}
	case "exception_content_digest_mismatch", "exception_approved_max_exceeded", "exception_class_mismatch":
		if !scannedClass || finding.PhysicalLines <= limitFor(finding.Class) {
			return contractError(CodeDenied, "report.finding", "exception failure line count is unreachable", nil)
		}
	case "exception_generated_header_missing":
		if (finding.Class != "production" && finding.Class != "other") || finding.PhysicalLines <= HardLimit {
			return contractError(CodeDenied, "report.finding", "generated-header failure is unreachable", nil)
		}
	}
	requiresTracking := finding.Reason == "approved_exception" || strings.HasPrefix(finding.Reason, "exception_")
	if requiresTracking != (finding.TrackingIssue != "") || finding.TrackingIssue != "" && !issuePattern.MatchString(finding.TrackingIssue) {
		return contractError(CodeDenied, "report.finding", "finding tracking issue is invalid", nil)
	}
	return nil
}

func exceptionClassLimit(class string) int {
	if class == "script" {
		return ScriptLimit
	}
	return HardLimit
}

func validRevision(value string) bool {
	if value == "unborn" {
		return true
	}
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}

func compareFinding(left, right Finding) int {
	if left.Path < right.Path {
		return -1
	}
	if left.Path > right.Path {
		return 1
	}
	if left.Reason < right.Reason {
		return -1
	}
	if left.Reason > right.Reason {
		return 1
	}
	return 0
}

func DigestReportBytes(report Report) (string, error) {
	report.ReportDigest = ""
	data, err := json.Marshal(report)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
