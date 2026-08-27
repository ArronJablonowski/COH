package truncationeval

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const maximumContractBytes = 1 << 20

var (
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	bareDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	namePattern       = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	reasonPattern     = regexp.MustCompile(`^[a-z][a-z0-9_]{2,127}$`)
	idPattern         = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)
	pathPattern       = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,512}$`)
	boundaryPattern   = regexp.MustCompile(`^(schema|response|sort|pit|limit|cancellation|recovery|slicing)\.[a-z_]+$`)
	versionPattern    = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

func DecodeCorpus(input []byte) (Corpus, error) {
	var value Corpus
	if err := decodeExact(input, &value); err != nil {
		return Corpus{}, err
	}
	if value.SchemaVersion != "coh.connector-truncation-corpus/v1" || value.CorpusVersion != "1.0.0" ||
		!slices.Equal(value.Requirements, []string{"FR-054", "EVAL-016"}) || value.TrialsPerTask != 5 ||
		value.Thresholds != strictThresholds() || len(value.Tasks) == 0 || len(value.Tasks) > 256 {
		return Corpus{}, denied("corpus identity, trial count, or thresholds invalid")
	}
	seen := map[string]struct{}{}
	for _, task := range value.Tasks {
		if err := validateTask(task); err != nil {
			return Corpus{}, err
		}
		if _, exists := seen[task.ID]; exists {
			return Corpus{}, denied("duplicate task")
		}
		seen[task.ID] = struct{}{}
	}
	return value, nil
}

func DecodeEnvironment(input []byte) (Environment, error) {
	var value Environment
	if err := decodeExact(input, &value); err != nil {
		return Environment{}, err
	}
	if value.SchemaVersion != "coh.connector-truncation-environment/v1" || value.EnvironmentVersion != "1.0.0" ||
		value.CorpusVersion != "1.0.0" || value.GoVersion != "1.26.7" || value.QualifiedPlatform != "darwin/arm64" ||
		value.Clock != "logical-trial-clock/v1" || value.Randomness != "none" || value.Network != "disabled" ||
		len(value.Contracts) < 4 || len(value.Contracts) > 16 || len(value.FixtureManifests) < 2 || len(value.FixtureManifests) > 16 ||
		!validPins(value.Contracts) || !validPins(value.FixtureManifests) {
		return Environment{}, denied("environment invalid")
	}
	return value, nil
}

func DecodeRecordings(input []byte) (RecordingSet, error) {
	var value RecordingSet
	if err := decodeExact(input, &value); err != nil {
		return RecordingSet{}, err
	}
	if value.SchemaVersion != "coh.connector-truncation-recording/v1" || value.RecordingVersion != "1.0.0" ||
		!slices.Contains([]string{"elastic", "security_onion"}, value.Vendor) || !value.Sanitized || value.Network != "disabled" ||
		len(value.Recordings) == 0 || len(value.Recordings) > 128 {
		return RecordingSet{}, denied("recording set identity invalid")
	}
	seen := make(map[string]struct{}, len(value.Recordings))
	for _, recording := range value.Recordings {
		if err := validateRecording(value.Vendor, recording); err != nil {
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
	if value.SchemaVersion != "coh.connector-truncation-trace/v1" || value.CorpusVersion != "1.0.0" ||
		!validDigests(value.CorpusDigest, value.EnvironmentDigest, value.TaskDigest, value.ReplayDigest) ||
		!idPattern.MatchString(value.TaskID) || value.Trial < 1 || value.Trial > 100 ||
		len(value.Events) == 0 || len(value.Events) > 64 || !validTokens(value.Events) || validateObserved(value.Observed) != nil {
		return Trace{}, denied("trace invalid")
	}
	return value, nil
}

func DecodeGraders(input []byte) (GraderReport, error) {
	var value GraderReport
	if err := decodeExact(input, &value); err != nil {
		return GraderReport{}, err
	}
	if value.SchemaVersion != "coh.connector-truncation-graders/v1" || value.CorpusVersion != "1.0.0" ||
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
	if value.SchemaVersion != "coh.connector-truncation-threshold/v1" || !validDigests(value.CorpusDigest, value.EnvironmentDigest) ||
		value.Thresholds != strictThresholds() || !validMetrics(value.Metrics) || !validThresholdOutcome(value) {
		return ThresholdResult{}, denied("threshold result invalid")
	}
	return value, nil
}

func DecodeArtifacts(input []byte) (ArtifactManifest, error) {
	var value ArtifactManifest
	if err := decodeExact(input, &value); err != nil {
		return ArtifactManifest{}, err
	}
	if value.SchemaVersion != "coh.connector-truncation-artifacts/v1" || !validDigests(value.CorpusDigest, value.EnvironmentDigest) ||
		value.ReproductionCommand != "./scripts/verify_connector_truncation.sh" || len(value.Artifacts) < 6 || len(value.Artifacts) > 16 {
		return ArtifactManifest{}, denied("artifact manifest invalid")
	}
	seen := map[string]struct{}{}
	for _, artifact := range value.Artifacts {
		if !namePattern.MatchString(artifact.Path) || !bareDigestPattern.MatchString(artifact.SHA256) || artifact.Length < 1 || artifact.Length > 100<<20 {
			return ArtifactManifest{}, denied("artifact invalid")
		}
		if _, exists := seen[artifact.Path]; exists {
			return ArtifactManifest{}, denied("duplicate artifact")
		}
		seen[artifact.Path] = struct{}{}
	}
	return value, nil
}

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > maximumContractBytes {
		return denied("contract size invalid")
	}
	value, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return denied("contract JSON invalid")
	}
	unique, err := json.Marshal(value)
	if err != nil {
		return denied("contract JSON invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(unique))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return denied("contract shape invalid")
	}
	return nil
}

func denied(reason string) error {
	return fmt.Errorf("connector truncation contract denied: %s", reason)
}

func strictThresholds() Thresholds {
	return Thresholds{MinimumReplayRate: 1, MinimumOutcomeGradeRate: 1,
		MinimumTrajectoryGradeRate: 1, MinimumBoundaryCoverageRate: 1}
}

func validateTask(task Task) error {
	if !idPattern.MatchString(task.ID) || !slices.Contains([]string{"elastic", "security_onion"}, task.Vendor) ||
		!slices.Contains([]string{"esql", "query_dsl_pit", "oql_events", "oql_metrics", "adaptive_slice"}, task.Mode) ||
		!boundaryPattern.MatchString(task.Boundary) ||
		!slices.Contains([]string{"none", "schema_drift", "partial_response", "repeated_sort", "pit_expiry", "pit_rotation", "documented_cap", "undocumented_cap", "embedded_error", "timeout", "cancel", "lost_state", "unproven_slice"}, task.Fault) ||
		len(task.Fixtures) == 0 || len(task.Fixtures) > 16 || len(task.Trajectory) == 0 || len(task.Trajectory) > 64 ||
		!validTokens(task.Trajectory) || validateExpected(task.Expected) != nil {
		return denied("task invalid")
	}
	fixturePaths := make(map[string]struct{}, len(task.Fixtures))
	for _, fixture := range task.Fixtures {
		if !pathPattern.MatchString(fixture.Path) || strings.Contains(fixture.Path, "..") || !validDigests(fixture.SHA256) {
			return denied("fixture reference invalid")
		}
		if _, exists := fixturePaths[fixture.Path]; exists {
			return denied("duplicate fixture reference")
		}
		fixturePaths[fixture.Path] = struct{}{}
	}
	return nil
}

func validateRecording(vendor string, recording Recording) error {
	if !idPattern.MatchString(recording.ID) || !boundaryPattern.MatchString(recording.Boundary) ||
		!slices.Contains([]string{"none", "schema_drift", "partial_response", "repeated_sort", "pit_expiry", "pit_rotation", "documented_cap", "undocumented_cap", "embedded_error", "timeout", "cancel", "lost_state", "unproven_slice"}, recording.Fault) ||
		len(recording.Steps) == 0 || len(recording.Steps) > 64 || len(recording.Trajectory) == 0 || len(recording.Trajectory) > 64 ||
		!validTokens(recording.Trajectory) || validateExpected(recording.Expected) != nil {
		return denied("recording invalid")
	}
	if (vendor == "elastic" && !slices.Contains([]string{"esql", "query_dsl_pit", "adaptive_slice"}, recording.Mode)) ||
		(vendor == "security_onion" && !slices.Contains([]string{"oql_events", "oql_metrics", "adaptive_slice"}, recording.Mode)) {
		return denied("recording vendor mode invalid")
	}
	for index, step := range recording.Steps {
		if step.Sequence != index+1 || !namePattern.MatchString(step.Operation) ||
			!slices.Contains([]string{"ok", "error", "canceled", "timeout", "unavailable"}, step.Outcome) ||
			step.HTTPStatus < 0 || step.HTTPStatus > 599 || len(step.RowIDs) > 1000 || len(step.SortKeys) > 1000 ||
			(step.TotalRelation != "" && !slices.Contains([]string{"eq", "gte", "unknown", "not_applicable"}, step.TotalRelation)) ||
			(step.PITToken != "" && !namePattern.MatchString(step.PITToken)) ||
			(step.ErrorCode != "" && !namePattern.MatchString(step.ErrorCode)) || !validTokens(step.RowIDs) || duplicateAny(step.RowIDs) ||
			(len(step.SortKeys) != 0 && len(step.SortKeys) != len(step.RowIDs)) ||
			(step.Outcome != "ok" && step.ErrorCode == "") {
			return denied("recording step invalid")
		}
	}
	return nil
}

func validateExpected(value Expected) error {
	if !slices.Contains([]string{"completed", "partial", "denied", "canceled", "unknown"}, value.Outcome) ||
		!slices.Contains([]string{"complete", "partial", "unknown", "not_applicable"}, value.CompletenessStatus) ||
		len(value.ReasonCodes) > 16 || !slices.IsSorted(value.ReasonCodes) || duplicate(value.ReasonCodes) || !validReasons(value.ReasonCodes) ||
		value.RowsReturned < 0 || value.RowsReturned > 100000 || value.PagesReturned < 0 || value.PagesReturned > 10000 ||
		!slices.Contains([]string{"not_requested", "proven", "unsupported"}, value.AdaptiveSlicing) {
		return denied("expected result invalid")
	}
	switch value.CompletenessStatus {
	case "complete":
		if value.Outcome != "completed" || value.Partial || value.Truncated || !value.VendorConfirmed || len(value.ReasonCodes) != 0 || value.AdaptiveSlicing == "unsupported" {
			return denied("false complete expectation")
		}
	case "partial":
		if value.Outcome != "partial" || !value.Partial || len(value.ReasonCodes) == 0 {
			return denied("inconsistent partial expectation")
		}
	case "unknown":
		if value.Outcome != "unknown" || value.VendorConfirmed || len(value.ReasonCodes) == 0 {
			return denied("inconsistent unknown expectation")
		}
	case "not_applicable":
		if !slices.Contains([]string{"denied", "canceled"}, value.Outcome) || value.Partial || value.Truncated || value.VendorConfirmed ||
			value.RowsReturned != 0 || value.PagesReturned != 0 || len(value.ReasonCodes) == 0 {
			return denied("inconsistent not-applicable expectation")
		}
	}
	if value.AdaptiveSlicing == "unsupported" && !slices.Contains(value.ReasonCodes, "adaptive_slicing_unproven") {
		return denied("unsupported adaptive slicing reason missing")
	}
	if value.AdaptiveSlicing == "proven" && value.CompletenessStatus != "complete" {
		return denied("adaptive slicing proof incomplete")
	}
	return nil
}

func validateObserved(value Observed) error {
	if validateExpected(value.Expected) != nil || value.DuplicateRows < 0 || value.MissingRows < 0 {
		return denied("observed result invalid")
	}
	return nil
}

func validPins(values []Pin) bool {
	seen := map[string]struct{}{}
	previous := ""
	for _, value := range values {
		if !namePattern.MatchString(value.Name) || !versionPattern.MatchString(value.Version) || !validDigests(value.Digest) || value.Name <= previous {
			return false
		}
		if _, exists := seen[value.Name]; exists {
			return false
		}
		seen[value.Name] = struct{}{}
		previous = value.Name
	}
	return true
}

func validMetrics(value Metrics) bool {
	return value.TaskCount > 0 && value.TrialCount == value.TaskCount*5 && value.RequiredBoundaryCount > 0 &&
		value.CoveredBoundaryCount > 0 && value.CoveredBoundaryCount <= value.RequiredBoundaryCount &&
		value.RequiredBoundaryCount <= value.TaskCount &&
		value.FalseComplete >= 0 && value.DuplicateRows >= 0 && value.MissingRows >= 0 &&
		validRate(value.ReplayRate) && validRate(value.OutcomeGradeRate) && validRate(value.TrajectoryGradeRate) &&
		validRate(value.BoundaryCoverageRate) &&
		math.Abs(value.BoundaryCoverageRate-float64(value.CoveredBoundaryCount)/float64(value.RequiredBoundaryCount)) < 1e-12
}

func validRate(value float64) bool { return value >= 0 && value <= 1 }

func validDigests(values ...string) bool {
	for _, value := range values {
		if !digestPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validTokens(values []string) bool {
	for _, value := range values {
		if !namePattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validReasons(values []string) bool {
	for _, value := range values {
		if !reasonPattern.MatchString(value) {
			return false
		}
	}
	return true
}

func validThresholdOutcome(value ThresholdResult) bool {
	passed := value.Metrics.FalseComplete <= value.Thresholds.MaximumFalseComplete &&
		value.Metrics.DuplicateRows <= value.Thresholds.MaximumDuplicateRows &&
		value.Metrics.MissingRows <= value.Thresholds.MaximumMissingRows &&
		value.Metrics.ReplayRate >= value.Thresholds.MinimumReplayRate &&
		value.Metrics.OutcomeGradeRate >= value.Thresholds.MinimumOutcomeGradeRate &&
		value.Metrics.TrajectoryGradeRate >= value.Thresholds.MinimumTrajectoryGradeRate &&
		value.Metrics.BoundaryCoverageRate >= value.Thresholds.MinimumBoundaryCoverageRate
	return (passed && value.Outcome == "passed") || (!passed && value.Outcome == "denied")
}

func duplicate[T comparable](values []T) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

func duplicateAny[T comparable](values []T) bool {
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}
