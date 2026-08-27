package truncationeval

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLockedCorpusRunsFiveDeterministicTrialsPerTask(t *testing.T) {
	t.Parallel()
	suite := loadRepositorySuite(t)
	result := Run(suite)
	metrics := result.Graders.Metrics
	for index := 0; index < len(result.Traces); index += suite.Corpus.TrialsPerTask {
		if !result.Traces[index].OutcomeGrade {
			t.Logf("outcome mismatch task=%s want=%+v got=%+v", suite.Corpus.Tasks[index/suite.Corpus.TrialsPerTask].ID,
				suite.Corpus.Tasks[index/suite.Corpus.TrialsPerTask].Expected, result.Traces[index].Observed)
		}
	}
	if result.Threshold.Outcome != "passed" || metrics.TaskCount != 21 || metrics.TrialCount != 105 ||
		metrics.RequiredBoundaryCount != 21 || metrics.CoveredBoundaryCount != 21 || metrics.FalseComplete != 0 ||
		metrics.DuplicateRows != 0 || metrics.MissingRows != 0 || metrics.ReplayRate != 1 ||
		metrics.OutcomeGradeRate != 1 || metrics.TrajectoryGradeRate != 1 || metrics.BoundaryCoverageRate != 1 {
		t.Fatalf("threshold=%+v metrics=%+v", result.Threshold, metrics)
	}
	for index := 0; index < len(result.Traces); index += suite.Corpus.TrialsPerTask {
		baseline := result.Traces[index].ReplayDigest
		for trial := 0; trial < suite.Corpus.TrialsPerTask; trial++ {
			trace := result.Traces[index+trial]
			if trace.ReplayDigest != baseline || trace.Trial != trial+1 || !trace.OutcomeGrade || !trace.TrajectoryGrade {
				t.Fatalf("non-deterministic trace: %+v", trace)
			}
		}
	}
}

func TestArtifactsAreByteReproducibleAndSelfVerifying(t *testing.T) {
	t.Parallel()
	suite := loadRepositorySuite(t)
	result := Run(suite)
	first, second := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")
	if err := WriteArtifacts(first, suite, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteArtifacts(second, suite, result); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifacts(first); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(first)
	if err != nil || len(entries) != 7 {
		t.Fatalf("entries=%d err=%v", len(entries), err)
	}
	for _, entry := range entries {
		left, leftErr := os.ReadFile(filepath.Join(first, entry.Name()))
		right, rightErr := os.ReadFile(filepath.Join(second, entry.Name()))
		if leftErr != nil || rightErr != nil || !bytes.Equal(left, right) {
			t.Fatalf("artifact %q differs: %v %v", entry.Name(), leftErr, rightErr)
		}
	}
	manifestBytes, err := os.ReadFile(filepath.Join(first, "artifact-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeArtifacts(manifestBytes); err != nil {
		t.Fatal(err)
	}
	graderBytes, _ := os.ReadFile(filepath.Join(first, "grader-report.json"))
	if _, err := DecodeGraders(graderBytes); err != nil {
		t.Fatal(err)
	}
	thresholdBytes, _ := os.ReadFile(filepath.Join(first, "threshold-result.json"))
	if _, err := DecodeThreshold(thresholdBytes); err != nil {
		t.Fatal(err)
	}
	traceFile, _ := os.ReadFile(filepath.Join(first, "trial-traces.jsonl"))
	decoder := json.NewDecoder(bytes.NewReader(traceFile))
	for count := 0; count < 105; count++ {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			t.Fatalf("trace %d: %v", count, err)
		}
		if _, err := DecodeTrace(raw); err != nil {
			t.Fatalf("trace %d: %v", count, err)
		}
	}
}

func loadRepositorySuite(t *testing.T) Suite {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	suite, err := Load(root,
		filepath.Join(root, "contracts/evaluation/truncation/v1/connector-truncation-corpus.json"),
		filepath.Join(root, "contracts/evaluation/truncation/v1/connector-truncation-environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	return suite
}
