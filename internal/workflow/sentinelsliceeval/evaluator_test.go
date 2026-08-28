package sentinelsliceeval

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLockedSuiteRunsFiveDeterministicTrialsPerTask(t *testing.T) {
	suite := loadRepositorySuite(t)
	result := Run(suite)
	metrics := result.Graders.Metrics
	if !result.Threshold.Passed || metrics.TaskCount != 11 || metrics.TrialCount != 55 ||
		metrics.FalseComplete != 0 || metrics.ReleasedDeniedRows != 0 || metrics.OutcomeGradeRate != 1 ||
		metrics.TrajectoryGradeRate != 1 || metrics.ReplayRate != 1 || metrics.BoundaryCoverageRate != 1 {
		t.Fatalf("threshold=%+v metrics=%+v", result.Threshold, metrics)
	}
	for index := 0; index < len(result.Traces); index += suite.Corpus.TrialsPerTask {
		baseline := result.Traces[index].ReplayDigest
		for trial := 0; trial < suite.Corpus.TrialsPerTask; trial++ {
			trace := result.Traces[index+trial]
			if trace.Trial != trial+1 || trace.ReplayDigest != baseline {
				t.Fatalf("non-deterministic trace: %+v", trace)
			}
		}
	}
}

func TestArtifactsAreByteReproducibleAndSelfVerifying(t *testing.T) {
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
	entries, _ := os.ReadDir(first)
	if len(entries) != 7 {
		t.Fatalf("artifact count=%d", len(entries))
	}
	for _, entry := range entries {
		left, leftErr := os.ReadFile(filepath.Join(first, entry.Name()))
		right, rightErr := os.ReadFile(filepath.Join(second, entry.Name()))
		if leftErr != nil || rightErr != nil || !bytes.Equal(left, right) {
			t.Fatalf("artifact %q differs", entry.Name())
		}
	}
}

func TestConcurrentReplayIsIdentical(t *testing.T) {
	suite := loadRepositorySuite(t)
	want := Run(suite)
	results := make(chan RunResult, 16)
	var group sync.WaitGroup
	for index := 0; index < cap(results); index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			results <- Run(suite)
		}()
	}
	group.Wait()
	close(results)
	for result := range results {
		if result.Graders.TraceStreamDigest != want.Graders.TraceStreamDigest || result.Threshold != want.Threshold {
			t.Fatal("concurrent replay differs")
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
		filepath.Join(root, "contracts/evaluation/sentinel-slicing/v1/sentinel-slicing-corpus.json"),
		filepath.Join(root, "contracts/evaluation/sentinel-slicing/v1/sentinel-slicing-environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	return suite
}
