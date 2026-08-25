package replayeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCorpusRunsAllBoundariesAtLockedThresholds(t *testing.T) {
	suite := loadRepositorySuite(t)
	result := Run(suite)
	if result.Threshold.Outcome != "passed" || result.Graders.Metrics.TaskCount != 31 || result.Graders.Metrics.TrialCount != 155 {
		t.Fatalf("result = %+v", result.Threshold)
	}
	metrics := result.Graders.Metrics
	if metrics.DuplicateConfirmedEffects != 0 || metrics.FalseSuccesses != 0 || metrics.ReconciliationRate != 1 || metrics.ReplayRate != 1 || metrics.OutcomeGradeRate != 1 || metrics.TrajectoryGradeRate != 1 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestRuntimeQualificationRejectsDifferentPlatform(t *testing.T) {
	suite := loadRepositorySuite(t)
	suite.Environment.QualifiedPlatform = "invalid/invalid"
	if err := ValidateRuntime(suite.Environment); err == nil {
		t.Fatal("different runtime platform was accepted")
	}
}

func TestArtifactsAreReproducibleAndChecksummed(t *testing.T) {
	suite := loadRepositorySuite(t)
	result := Run(suite)
	first, second := filepath.Join(t.TempDir(), "first"), filepath.Join(t.TempDir(), "second")
	if err := WriteArtifacts(first, suite, result); err != nil {
		t.Fatal(err)
	}
	if err := WriteArtifacts(second, suite, result); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 7 {
		t.Fatalf("artifact count = %d", len(entries))
	}
	for _, entry := range entries {
		left, err := os.ReadFile(filepath.Join(first, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		right, err := os.ReadFile(filepath.Join(second, entry.Name()))
		if err != nil || !bytes.Equal(left, right) {
			t.Fatalf("artifact %s differs: %v", entry.Name(), err)
		}
	}
	manifestBytes, err := os.ReadFile(filepath.Join(first, "artifact-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest artifactManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Artifacts) != 6 {
		t.Fatalf("manifest artifact count = %d", len(manifest.Artifacts))
	}
	for _, record := range manifest.Artifacts {
		data, err := os.ReadFile(filepath.Join(first, record.Path))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		if record.SHA256 != hex.EncodeToString(sum[:]) || record.Length != int64(len(data)) {
			t.Fatalf("invalid manifest record: %+v", record)
		}
	}
}

func TestContractRejectsUnknownFieldsWeakenedThresholdsAndChangedOutcomes(t *testing.T) {
	root := repositoryRoot(t)
	corpus, err := os.ReadFile(filepath.Join(root, "contracts/evaluation/v1/replay-fault-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	environment := filepath.Join(root, "contracts/evaluation/v1/replay-environment.json")
	tests := map[string][]byte{
		"unknown":          bytes.Replace(corpus, []byte(`"corpus_version": "1.0.0",`), []byte(`"corpus_version": "1.0.0", "unknown": true,`), 1),
		"weakened":         bytes.Replace(corpus, []byte(`"maximum_false_successes": 0`), []byte(`"maximum_false_successes": 1`), 1),
		"changed-outcome":  bytes.Replace(corpus, []byte(`"state":"uncertain"`), []byte(`"state":"verified"`), 1),
		"missing-boundary": removeTask(t, corpus, "workflow-before-start"),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "corpus.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path, environment); err == nil {
				t.Fatal("contract mutation was accepted")
			}
		})
	}
}

func removeTask(t *testing.T, data []byte, id string) []byte {
	t.Helper()
	var corpus Corpus
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	filtered := corpus.Tasks[:0]
	for _, task := range corpus.Tasks {
		if task.ID != id {
			filtered = append(filtered, task)
		}
	}
	corpus.Tasks = filtered
	encoded, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func loadRepositorySuite(t *testing.T) Suite {
	t.Helper()
	root := repositoryRoot(t)
	suite, err := Load(filepath.Join(root, "contracts/evaluation/v1/replay-fault-corpus.json"), filepath.Join(root, "contracts/evaluation/v1/replay-environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	return suite
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}
