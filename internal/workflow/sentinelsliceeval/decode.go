package sentinelsliceeval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const maximumContractBytes = 1 << 20

var (
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	bareDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idPattern         = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)
	tokenPattern      = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	versionPattern    = regexp.MustCompile(`^[0-9]+[.][0-9]+[.][0-9]+$`)
)

func DecodeCorpus(input []byte) (Corpus, error) {
	var value Corpus
	if err := decodeExact(input, &value); err != nil {
		return Corpus{}, err
	}
	if value.SchemaVersion != "coh.sentinel-slicing-corpus/v1" || value.CorpusVersion != "1.0.0" ||
		value.Issue != "COH-E14-06" || !slices.Equal(value.Requirements, []string{"EVAL-016", "FR-052", "FR-054"}) ||
		value.TrialsPerTask != 5 || value.Thresholds != strictThresholds() || len(value.Tasks) < 10 || len(value.Tasks) > 64 {
		return Corpus{}, denied("corpus identity invalid")
	}
	seen, boundaries := map[string]struct{}{}, map[string]struct{}{}
	for _, task := range value.Tasks {
		if err := validateTask(task); err != nil {
			return Corpus{}, err
		}
		if _, exists := seen[task.ID]; exists {
			return Corpus{}, denied("duplicate task")
		}
		seen[task.ID], boundaries[task.Boundary] = struct{}{}, struct{}{}
	}
	if len(boundaries) != 9 {
		return Corpus{}, denied("boundary coverage incomplete")
	}
	return value, nil
}

func DecodeEnvironment(input []byte) (Environment, error) {
	var value Environment
	if err := decodeExact(input, &value); err != nil {
		return Environment{}, err
	}
	if value.SchemaVersion != "coh.sentinel-slicing-environment/v1" || value.EnvironmentVersion != "1.0.0" ||
		value.CorpusVersion != "1.0.0" || value.GoVersion != "1.26.7" || value.QualifiedPlatform != "darwin/arm64" ||
		value.Clock != "logical-trial-clock/v1" || value.Randomness != "none" || value.Network != "disabled" ||
		len(value.Contracts) < 5 || len(value.Contracts) > 16 || len(value.Fixtures) == 0 || len(value.Fixtures) > 16 ||
		!validPins(value.Contracts) || !validPins(value.Fixtures) {
		return Environment{}, denied("environment invalid")
	}
	return value, nil
}

func DecodeRecordings(input []byte) (RecordingSet, error) {
	var value RecordingSet
	if err := decodeExact(input, &value); err != nil {
		return RecordingSet{}, err
	}
	if value.SchemaVersion != "coh.sentinel-slicing-recordings/v1" || value.RecordingVersion != "1.0.0" ||
		!value.Sanitized || value.Network != "disabled" || len(value.Recordings) < 10 || len(value.Recordings) > 64 {
		return RecordingSet{}, denied("recording set invalid")
	}
	seen := map[string]struct{}{}
	for _, recording := range value.Recordings {
		if err := validateRecording(recording); err != nil {
			return RecordingSet{}, err
		}
		if _, exists := seen[recording.ID]; exists {
			return RecordingSet{}, denied("duplicate recording")
		}
		seen[recording.ID] = struct{}{}
	}
	return value, nil
}

func DecodeTrace(input []byte) (Trace, error) {
	var value Trace
	if err := decodeExact(input, &value); err != nil {
		return Trace{}, err
	}
	if value.SchemaVersion != "coh.sentinel-slicing-trace/v1" || !validDigests(value.CorpusDigest,
		value.EnvironmentDigest, value.TaskDigest, value.ReplayDigest) || !idPattern.MatchString(value.TaskID) ||
		value.Trial < 1 || value.Trial > 5 || !validTokenSequence(value.Events, 2, 64) || validateExpected(value.Observed) != nil {
		return Trace{}, denied("trace invalid")
	}
	return value, nil
}

func DecodeGraders(input []byte) (GraderReport, error) {
	var value GraderReport
	if err := decodeExact(input, &value); err != nil {
		return GraderReport{}, err
	}
	if value.SchemaVersion != "coh.sentinel-slicing-graders/v1" ||
		!validDigests(value.CorpusDigest, value.EnvironmentDigest, value.TraceStreamDigest) || !validMetrics(value.Metrics) {
		return GraderReport{}, denied("grader report invalid")
	}
	return value, nil
}

func DecodeThreshold(input []byte) (ThresholdResult, error) {
	var value ThresholdResult
	if err := decodeExact(input, &value); err != nil {
		return ThresholdResult{}, err
	}
	passed := passes(value.Metrics)
	if value.SchemaVersion != "coh.sentinel-slicing-threshold/v1" ||
		!validDigests(value.CorpusDigest, value.EnvironmentDigest) || value.Thresholds != strictThresholds() ||
		!validMetrics(value.Metrics) || value.Passed != passed {
		return ThresholdResult{}, denied("threshold result invalid")
	}
	return value, nil
}

func DecodeArtifacts(input []byte) (ArtifactManifest, error) {
	var value ArtifactManifest
	if err := decodeExact(input, &value); err != nil {
		return ArtifactManifest{}, err
	}
	if value.SchemaVersion != "coh.sentinel-slicing-artifacts/v1" ||
		!validDigests(value.CorpusDigest, value.EnvironmentDigest) ||
		value.ReproductionCommand != "./scripts/verify_sentinel_slicing.sh" || len(value.Artifacts) < 6 || len(value.Artifacts) > 16 {
		return ArtifactManifest{}, denied("artifact manifest invalid")
	}
	seen := map[string]struct{}{}
	for _, artifact := range value.Artifacts {
		if !tokenPattern.MatchString(artifact.Path) || !bareDigestPattern.MatchString(artifact.SHA256) ||
			artifact.Length < 1 || artifact.Length > 100<<20 {
			return ArtifactManifest{}, denied("artifact invalid")
		}
		if _, exists := seen[artifact.Path]; exists {
			return ArtifactManifest{}, denied("duplicate artifact")
		}
		seen[artifact.Path] = struct{}{}
	}
	return value, nil
}

func validateTask(value Task) error {
	if !idPattern.MatchString(value.ID) || !idPattern.MatchString(value.RecordingID) || !validDigests(value.RecordingSHA256) ||
		!slices.Contains(boundaries(), value.Boundary) || !slices.Contains(faults(), value.Fault) ||
		validateExpected(value.Expected) != nil || !validTokenSequence(value.Trajectory, 2, 64) {
		return denied("task invalid")
	}
	return nil
}

func validateRecording(value Recording) error {
	if !idPattern.MatchString(value.ID) || !slices.Contains(boundaries(), value.Boundary) ||
		!slices.Contains(faults(), value.Fault) || !value.Sanitized || value.Network != "disabled" ||
		len(value.Steps) == 0 || len(value.Steps) > 64 || validateExpected(value.Expected) != nil ||
		!validTokenSequence(value.Trajectory, 2, 64) {
		return denied("recording invalid")
	}
	for index, step := range value.Steps {
		start, startOK := parseTime(step.SliceStart)
		end, endOK := parseTime(step.SliceEnd)
		if step.Sequence != index+1 || !tokenPattern.MatchString(step.Event) || !startOK || !endOK || !start.Before(end) ||
			!validTokenSequence(step.RowKeys, 0, 1000) || !validDigestSet(step.RowDigests, 1000) ||
			!slices.Contains([]string{"ok", "error", "canceled", "timeout", "unavailable"}, step.Outcome) ||
			!validDigests(step.RequestDigest, step.ResponseDigest) || (step.Partial && value.Fault != "partial_error") ||
			(!step.EndExclusive && value.Fault != "missing_timespan") {
			return denied("recording step invalid")
		}
	}
	if value.Fault == "partial_error" && !slices.ContainsFunc(value.Steps, func(step RecordingStep) bool { return step.Partial }) {
		return denied("partial error proof missing")
	}
	return nil
}

func validateExpected(value Expected) error {
	if !slices.Contains([]string{"completed", "denied", "canceled", "unknown"}, value.Outcome) ||
		!slices.Contains([]string{"complete", "not_applicable"}, value.Completeness) ||
		!validSortedTokens(value.ReasonCodes, 16) || value.RowsReturned < 0 || value.RowsReturned > 100000 ||
		value.SlicesCompleted < 0 || value.SlicesCompleted > 1000 || value.ReleasedRows < 0 || value.ReleasedRows > 100000 {
		return denied("expected result invalid")
	}
	if value.Completeness == "complete" {
		if value.Outcome != "completed" || len(value.ReasonCodes) != 0 || value.RowsReturned != value.ReleasedRows || value.SlicesCompleted == 0 {
			return denied("complete result invalid")
		}
	} else if value.Outcome == "completed" || len(value.ReasonCodes) == 0 || value.RowsReturned != 0 || value.SlicesCompleted != 0 || value.ReleasedRows != 0 {
		return denied("withheld result invalid")
	}
	return nil
}

func validPins(values []Pin) bool {
	seen := map[string]struct{}{}
	for _, pin := range values {
		if !tokenPattern.MatchString(pin.Name) || !versionPattern.MatchString(pin.Version) || !validDigests(pin.SHA256) {
			return false
		}
		if _, exists := seen[pin.Name]; exists {
			return false
		}
		seen[pin.Name] = struct{}{}
	}
	return true
}

func validMetrics(value Metrics) bool {
	return value.TaskCount >= 10 && value.TaskCount <= 64 && value.TrialCount == value.TaskCount*5 &&
		value.FalseComplete >= 0 && value.ReleasedDeniedRows >= 0 && validRate(value.OutcomeGradeRate) &&
		validRate(value.TrajectoryGradeRate) && validRate(value.ReplayRate) && validRate(value.BoundaryCoverageRate)
}

func passes(value Metrics) bool {
	return value.FalseComplete == 0 && value.ReleasedDeniedRows == 0 && value.OutcomeGradeRate == 1 &&
		value.TrajectoryGradeRate == 1 && value.ReplayRate == 1 && value.BoundaryCoverageRate == 1
}

func strictThresholds() Thresholds {
	return Thresholds{MaximumFalseComplete: 0, MaximumReleasedDeniedRows: 0, MinimumOutcomeGradeRate: 1,
		MinimumTrajectoryGradeRate: 1, MinimumReplayRate: 1, MinimumBoundaryCoverageRate: 1}
}

func decodeExact(input []byte, output interface{}) error {
	if len(input) == 0 || len(input) > maximumContractBytes {
		return denied("contract size invalid")
	}
	unique, err := domaincontract.Canonicalize(input)
	if err != nil {
		return denied("contract JSON invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(unique))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return denied("contract shape invalid")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return denied("trailing contract data")
	}
	return nil
}

func validDigests(values ...string) bool {
	return !slices.ContainsFunc(values, func(value string) bool { return !digestPattern.MatchString(value) })
}

func validDigestSet(values []string, maximum int) bool {
	return len(values) <= maximum && !slices.ContainsFunc(values, func(value string) bool { return !digestPattern.MatchString(value) })
}

func validSortedTokens(values []string, maximum int) bool {
	if len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !tokenPattern.MatchString(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validTokenSequence(values []string, minimum, maximum int) bool {
	return len(values) >= minimum && len(values) <= maximum &&
		!slices.ContainsFunc(values, func(value string) bool { return !tokenPattern.MatchString(value) })
}

func parseTime(value string) (time.Time, bool) {
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	return parsed, err == nil && parsed.Format("2006-01-02T15:04:05.000000000Z") == value
}

func boundaries() []string {
	return []string{"ambiguity", "binding", "cancellation", "dedupe", "limits", "partial_error", "recovery", "slicing", "timespan"}
}

func faults() []string {
	return []string{"boundary_duplicate", "cancel", "duplicate_conflict", "missing_timespan", "none", "partial_error", "slice_limit", "tamper", "timeout", "timestamp_ambiguity", "uncertain_retry"}
}

func validRate(value float64) bool { return value >= 0 && value <= 1 }

func denied(reason string) error {
	return fmt.Errorf("sentinel slicing contract denied: %s", strings.TrimSpace(reason))
}
