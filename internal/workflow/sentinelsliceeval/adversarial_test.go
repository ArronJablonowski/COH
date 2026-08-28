package sentinelsliceeval

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsContractPinExpectationAndNetworkDrift(t *testing.T) {
	root, _ := filepath.Abs(filepath.Join("..", "..", ".."))
	corpusPath := filepath.Join(root, "contracts/evaluation/sentinel-slicing/v1/sentinel-slicing-corpus.json")
	environmentPath := filepath.Join(root, "contracts/evaluation/sentinel-slicing/v1/sentinel-slicing-environment.json")
	corpusBytes, _ := os.ReadFile(corpusPath)
	environmentBytes, _ := os.ReadFile(environmentPath)
	var corpus Corpus
	if err := json.Unmarshal(corpusBytes, &corpus); err != nil {
		t.Fatal(err)
	}
	changed := corpus
	changed.Tasks = append([]Task(nil), corpus.Tasks...)
	changed.Tasks[0].Expected.RowsReturned++
	cases := map[string][]byte{
		"missing task":      mustMarshal(Corpus{SchemaVersion: corpus.SchemaVersion}),
		"changed expected":  mustMarshal(changed),
		"duplicate key":     bytes.Replace(corpusBytes, []byte(`"corpus_version": "1.0.0"`), []byte(`"corpus_version": "1.0.0", "corpus_version": "1.0.0"`), 1),
		"oversize contract": bytes.Repeat([]byte("x"), maximumContractBytes+1),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "corpus.json")
			if err := os.WriteFile(path, candidate, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(root, path, environmentPath); err == nil {
				t.Fatal("drifted corpus accepted")
			}
		})
	}
	driftedEnvironment := bytes.Replace(environmentBytes, []byte(`"network": "disabled"`), []byte(`"network": "enabled"`), 1)
	environmentCandidate := filepath.Join(t.TempDir(), "environment.json")
	if err := os.WriteFile(environmentCandidate, driftedEnvironment, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root, corpusPath, environmentCandidate); err == nil {
		t.Fatal("network-enabled environment accepted")
	}
}

func TestThresholdAndArtifactVerificationFailClosed(t *testing.T) {
	suite := loadRepositorySuite(t)
	changed := suite
	changed.Corpus.Tasks = append([]Task(nil), suite.Corpus.Tasks...)
	changed.Corpus.Tasks[0].Expected.RowsReturned++
	if result := Run(changed); result.Threshold.Passed || result.Graders.Metrics.OutcomeGradeRate == 1 {
		t.Fatal("changed expectation passed")
	}
	result := Run(suite)
	missing := result
	missing.Traces = append([]Trace(nil), result.Traces[:len(result.Traces)-1]...)
	if err := WriteArtifacts(filepath.Join(t.TempDir(), "missing"), suite, missing); err == nil {
		t.Fatal("missing trial accepted")
	}
	output := filepath.Join(t.TempDir(), "valid")
	if err := WriteArtifacts(output, suite, result); err != nil {
		t.Fatal(err)
	}
	graderPath := filepath.Join(output, "grader-report.json")
	grader, _ := os.ReadFile(graderPath)
	if err := os.WriteFile(graderPath, append(grader, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifacts(output); err == nil {
		t.Fatal("tampered artifact accepted")
	}
}

func TestFailureCoverageAndEvidenceRemainSanitized(t *testing.T) {
	suite := loadRepositorySuite(t)
	result := Run(suite)
	want := map[string]string{"missing-timespan": "denied", "stable-key-conflict": "denied",
		"timestamp-ambiguity": "denied", "partial-error": "unknown", "caller-cancellation": "canceled",
		"uncertain-retry": "unknown", "provenance-tamper": "denied", "slice-limit": "denied"}
	for _, trace := range result.Traces {
		if outcome, ok := want[trace.TaskID]; ok && trace.Trial == 1 {
			if trace.Observed.Outcome != outcome || trace.Observed.ReleasedRows != 0 {
				t.Fatalf("unsafe trace: %+v", trace)
			}
			delete(want, trace.TaskID)
		}
	}
	if len(want) != 0 {
		t.Fatalf("failure traces missing: %v", want)
	}
	output := filepath.Join(t.TempDir(), "evidence")
	if err := WriteArtifacts(output, suite, result); err != nil {
		t.Fatal(err)
	}
	var evidence []byte
	entries, _ := os.ReadDir(output)
	for _, entry := range entries {
		data, _ := os.ReadFile(filepath.Join(output, entry.Name()))
		evidence = append(evidence, data...)
	}
	lower := strings.ToLower(string(evidence))
	for _, forbidden := range []string{"authorization", "bearer ", "password", "api_key", "https://"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("evidence contains %q", forbidden)
		}
	}
}
