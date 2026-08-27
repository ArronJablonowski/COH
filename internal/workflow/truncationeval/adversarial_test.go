package truncationeval

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsManifestEnvironmentAndExpectationDrift(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	corpusPath := filepath.Join(root, "contracts/evaluation/truncation/v1/connector-truncation-corpus.json")
	environmentPath := filepath.Join(root, "contracts/evaluation/truncation/v1/connector-truncation-environment.json")
	corpusBytes, _ := os.ReadFile(corpusPath)
	environmentBytes, _ := os.ReadFile(environmentPath)
	var corpus Corpus
	if err := json.Unmarshal(corpusBytes, &corpus); err != nil {
		t.Fatal(err)
	}
	missing := corpus
	missing.Tasks = append([]Task(nil), corpus.Tasks[:len(corpus.Tasks)-1]...)
	altered := corpus
	altered.Tasks = append([]Task(nil), corpus.Tasks...)
	altered.Tasks[0].Expected.RowsReturned++
	cases := map[string]struct{ corpus, environment []byte }{
		"missing task":        {mustMarshal(missing), environmentBytes},
		"altered expectation": {mustMarshal(altered), environmentBytes},
		"environment drift":   {corpusBytes, bytes.Replace(environmentBytes, []byte(`"network": "disabled"`), []byte(`"network": "enabled"`), 1)},
		"duplicate key":       {bytes.Replace(corpusBytes, []byte(`"corpus_version": "1.0.0"`), []byte(`"corpus_version": "1.0.0", "corpus_version": "1.0.0"`), 1), environmentBytes},
	}
	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			candidateCorpus := filepath.Join(directory, "corpus.json")
			candidateEnvironment := filepath.Join(directory, "environment.json")
			if err := os.WriteFile(candidateCorpus, test.corpus, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(candidateEnvironment, test.environment, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(root, candidateCorpus, candidateEnvironment); err == nil {
				t.Fatal("drifted evaluation contract accepted")
			}
		})
	}
}

func TestThresholdDeniesChangedOutcomeAndDuplicateReplay(t *testing.T) {
	t.Parallel()
	suite := loadRepositorySuite(t)
	changed := suite
	changed.Corpus.Tasks = append([]Task(nil), suite.Corpus.Tasks...)
	changed.Corpus.Tasks[0].Expected.RowsReturned++
	if result := Run(changed); result.Threshold.Outcome != "denied" || result.Graders.Metrics.OutcomeGradeRate >= 1 {
		t.Fatalf("changed expectation passed: %+v", result.Threshold)
	}
	duplicated := suite
	duplicated.Recordings = cloneRecordings(suite.Recordings)
	recording := duplicated.Recordings["elastic-repeated-stable-sort"]
	recording.Steps = append([]RecordingStep(nil), recording.Steps...)
	recording.Steps[2].RowIDs = append([]string(nil), recording.Steps[2].RowIDs...)
	recording.Steps[2].RowIDs[0] = recording.Steps[1].RowIDs[0]
	duplicated.Recordings[recording.ID] = recording
	result := Run(duplicated)
	if result.Threshold.Outcome != "denied" || result.Graders.Metrics.DuplicateRows == 0 || result.Graders.Metrics.MissingRows == 0 {
		t.Fatalf("duplicate replay passed: %+v", result.Threshold)
	}
}

func TestArtifactWriterAndVerifierRejectMissingTrialsAndTampering(t *testing.T) {
	t.Parallel()
	suite := loadRepositorySuite(t)
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

func TestCancellationRecoveryAndEvidenceRemainExactAndSanitized(t *testing.T) {
	t.Parallel()
	suite := loadRepositorySuite(t)
	result := Run(suite)
	want := map[string]string{
		"elastic-cancel-before-request":        "canceled",
		"elastic-recovery-stable-cursor":       "completed",
		"security-onion-cancel-confirmed":      "canceled",
		"security-onion-cancel-lost-state":     "unknown",
		"security-onion-recovery-after-outage": "completed",
	}
	for _, trace := range result.Traces {
		if outcome, exists := want[trace.TaskID]; exists && trace.Trial == 1 {
			if trace.Observed.Outcome != outcome || !trace.OutcomeGrade || !trace.TrajectoryGrade {
				t.Fatalf("task %q trace differs: %+v", trace.TaskID, trace)
			}
			delete(want, trace.TaskID)
		}
	}
	if len(want) != 0 {
		t.Fatalf("required traces missing: %v", want)
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
			t.Fatalf("evidence contains forbidden marker %q", forbidden)
		}
	}
	reproduction, _ := os.ReadFile(filepath.Join(output, "reproduction.txt"))
	if string(reproduction) != "./scripts/verify_connector_truncation.sh\n" {
		t.Fatalf("reproduction command = %q", reproduction)
	}
}

func cloneRecordings(source map[string]Recording) map[string]Recording {
	result := make(map[string]Recording, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
