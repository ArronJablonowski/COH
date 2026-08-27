package truncationeval

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodersAcceptStrictContracts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  any
		decode func([]byte) error
	}{
		{"corpus", validCorpus(), func(input []byte) error { _, err := DecodeCorpus(input); return err }},
		{"environment", validEnvironment(), func(input []byte) error { _, err := DecodeEnvironment(input); return err }},
		{"trace", validTrace(), func(input []byte) error { _, err := DecodeTrace(input); return err }},
		{"graders with fractional rates", validGraders(), func(input []byte) error { _, err := DecodeGraders(input); return err }},
		{"denied threshold", validThreshold(), func(input []byte) error { _, err := DecodeThreshold(input); return err }},
		{"artifacts", validArtifacts(), func(input []byte) error { _, err := DecodeArtifacts(input); return err }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.decode(mustJSON(t, test.input)); err != nil {
				t.Fatalf("decode valid contract: %v", err)
			}
		})
	}
}

func TestElasticRecordingsAreStrictSanitizedAndComplete(t *testing.T) {
	t.Parallel()
	path := filepath.Join("testdata", "1.0.0", "elastic-recordings.json")
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	recordings, err := DecodeRecordings(input)
	if err != nil {
		t.Fatal(err)
	}
	if recordings.Vendor != "elastic" || len(recordings.Recordings) != 9 {
		t.Fatalf("recordings = %+v", recordings)
	}
	lower := strings.ToLower(string(input))
	for _, forbidden := range []string{"authorization", "credential", "password", "api_key", "://"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("recording contains forbidden sensitive/network marker %q", forbidden)
		}
	}
	requiredFaults := map[string]bool{"schema_drift": false, "partial_response": false, "repeated_sort": false,
		"pit_expiry": false, "pit_rotation": false, "documented_cap": false, "cancel": false, "timeout": false, "lost_state": false}
	for _, recording := range recordings.Recordings {
		requiredFaults[recording.Fault] = true
	}
	for fault, covered := range requiredFaults {
		if !covered {
			t.Fatalf("required Elastic fault %q is missing", fault)
		}
	}
}

func TestDecodersFailClosed(t *testing.T) {
	t.Parallel()

	t.Run("duplicate key", func(t *testing.T) {
		input := []byte(`{"schema_version":"coh.connector-truncation-corpus/v1","schema_version":"coh.connector-truncation-corpus/v1"}`)
		if _, err := DecodeCorpus(input); err == nil {
			t.Fatal("duplicate key accepted")
		}
	})
	t.Run("unknown field", func(t *testing.T) {
		value := contractMap(t, validCorpus())
		value["waiver"] = true
		if _, err := DecodeCorpus(mustJSON(t, value)); err == nil {
			t.Fatal("unknown field accepted")
		}
	})
	t.Run("weakened threshold", func(t *testing.T) {
		value := validCorpus()
		value.Thresholds.MinimumReplayRate = 0.8
		if _, err := DecodeCorpus(mustJSON(t, value)); err == nil {
			t.Fatal("weakened threshold accepted")
		}
	})
	t.Run("false complete", func(t *testing.T) {
		value := validCorpus()
		value.Tasks[0].Expected.Partial = true
		if _, err := DecodeCorpus(mustJSON(t, value)); err == nil {
			t.Fatal("contradictory complete result accepted")
		}
	})
	t.Run("unsorted environment pins", func(t *testing.T) {
		value := validEnvironment()
		value.Contracts[0], value.Contracts[1] = value.Contracts[1], value.Contracts[0]
		if _, err := DecodeEnvironment(mustJSON(t, value)); err == nil {
			t.Fatal("non-deterministic pin order accepted")
		}
	})
	t.Run("unknown trace observation", func(t *testing.T) {
		value := validTrace()
		value.Observed.CompletenessStatus = "unknown"
		value.Observed.Outcome = "completed"
		value.Observed.ReasonCodes = []string{"vendor_limit_unknown"}
		value.Observed.VendorConfirmed = false
		if _, err := DecodeTrace(mustJSON(t, value)); err == nil {
			t.Fatal("contradictory unknown observation accepted")
		}
	})
	t.Run("inconsistent threshold outcome", func(t *testing.T) {
		value := validThreshold()
		value.Outcome = "passed"
		if _, err := DecodeThreshold(mustJSON(t, value)); err == nil {
			t.Fatal("passing label accepted for failing metrics")
		}
	})
	t.Run("invalid artifact digest", func(t *testing.T) {
		value := validArtifacts()
		value.Artifacts[0].SHA256 = strings.Repeat("A", 64)
		if _, err := DecodeArtifacts(mustJSON(t, value)); err == nil {
			t.Fatal("non-canonical artifact digest accepted")
		}
	})
}

func validCorpus() Corpus {
	return Corpus{
		SchemaVersion: "coh.connector-truncation-corpus/v1",
		CorpusVersion: "1.0.0",
		Requirements:  []string{"FR-054", "EVAL-016"},
		TrialsPerTask: 5,
		Thresholds:    strictThresholds(),
		Tasks: []Task{{
			ID: "elastic-complete", Vendor: "elastic", Mode: "query_dsl_pit", Boundary: "pit.complete", Fault: "none",
			Fixtures: []FixtureRef{{Path: "testdata/elastic/complete.json", SHA256: testDigest("a")}},
			Expected: Expected{Outcome: "completed", CompletenessStatus: "complete", VendorConfirmed: true,
				RowsReturned: 2, PagesReturned: 1, AdaptiveSlicing: "not_requested"},
			Trajectory: []string{"request.started", "response.complete"},
		}},
	}
}

func validEnvironment() Environment {
	return Environment{
		SchemaVersion: "coh.connector-truncation-environment/v1", EnvironmentVersion: "1.0.0", CorpusVersion: "1.0.0",
		GoVersion: "1.26.7", QualifiedPlatform: "darwin/arm64", Clock: "logical-trial-clock/v1", Randomness: "none", Network: "disabled",
		Contracts: []Pin{
			{Name: "connector-contract", Version: "1.0.0", Digest: testDigest("a")},
			{Name: "elastic-contract", Version: "1.0.0", Digest: testDigest("b")},
			{Name: "evaluation-contract", Version: "1.0.0", Digest: testDigest("c")},
			{Name: "security-onion-contract", Version: "1.0.0", Digest: testDigest("d")},
		},
		FixtureManifests: []Pin{
			{Name: "elastic-fixtures", Version: "1.0.0", Digest: testDigest("e")},
			{Name: "security-onion-fixtures", Version: "1.0.0", Digest: testDigest("f")},
		},
	}
}

func validTrace() Trace {
	expected := validCorpus().Tasks[0].Expected
	return Trace{
		SchemaVersion: "coh.connector-truncation-trace/v1", CorpusVersion: "1.0.0", CorpusDigest: testDigest("a"),
		EnvironmentDigest: testDigest("b"), TaskDigest: testDigest("c"), TaskID: "elastic-complete", Trial: 1,
		Events: []string{"request.started", "response.complete"}, Observed: Observed{Expected: expected},
		OutcomeGrade: true, TrajectoryGrade: true, ReplayDigest: testDigest("d"),
	}
}

func fixtureMetrics() Metrics {
	return Metrics{TaskCount: 2, TrialCount: 10, RequiredBoundaryCount: 2, CoveredBoundaryCount: 1,
		FalseComplete: 1, ReplayRate: 0.8, OutcomeGradeRate: 0.9, TrajectoryGradeRate: 0.7, BoundaryCoverageRate: 0.5}
}

func validGraders() GraderReport {
	return GraderReport{SchemaVersion: "coh.connector-truncation-graders/v1", CorpusVersion: "1.0.0",
		CorpusDigest: testDigest("a"), EnvironmentDigest: testDigest("b"), Metrics: fixtureMetrics(), TraceStreamDigest: testDigest("c")}
}

func validThreshold() ThresholdResult {
	return ThresholdResult{SchemaVersion: "coh.connector-truncation-threshold/v1", CorpusDigest: testDigest("a"),
		EnvironmentDigest: testDigest("b"), Thresholds: strictThresholds(), Metrics: fixtureMetrics(), Outcome: "denied"}
}

func validArtifacts() ArtifactManifest {
	artifacts := make([]Artifact, 6)
	for index := range artifacts {
		artifacts[index] = Artifact{Path: "artifact-" + string(rune('a'+index)) + ".json", SHA256: strings.Repeat(string(rune('a'+index)), 64), Length: 1}
	}
	return ArtifactManifest{SchemaVersion: "coh.connector-truncation-artifacts/v1", CorpusDigest: testDigest("a"),
		EnvironmentDigest: testDigest("b"), ReproductionCommand: "./scripts/verify_connector_truncation.sh", Artifacts: artifacts}
}

func testDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return encoded
}

func contractMap(t *testing.T, value any) map[string]any {
	t.Helper()
	var output map[string]any
	if err := json.Unmarshal(mustJSON(t, value), &output); err != nil {
		t.Fatalf("unmarshal fixture map: %v", err)
	}
	return output
}
