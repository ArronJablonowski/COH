package sentinelsliceeval

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
)

type environmentReport struct {
	SchemaVersion     string      `json:"schema_version"`
	Environment       Environment `json:"environment"`
	EnvironmentDigest string      `json:"environment_digest"`
	CorpusDigest      string      `json:"corpus_digest"`
}

func WriteArtifacts(output string, suite Suite, result RunResult) error {
	if output == "" || !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return fmt.Errorf("absolute clean output directory required")
	}
	if !reflect.DeepEqual(result, Run(suite)) {
		return fmt.Errorf("evaluation result differs from deterministic replay")
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(output)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output directory unavailable")
	}
	encoded := make(map[string][]byte)
	encoded["corpus-manifest.json"], err = marshalIndented(suite.Corpus)
	if err != nil {
		return err
	}
	encoded["environment-report.json"], err = marshalIndented(environmentReport{
		SchemaVersion: "coh.sentinel-slicing-environment-report/v1", Environment: suite.Environment,
		EnvironmentDigest: suite.EnvironmentDigest, CorpusDigest: suite.CorpusDigest})
	if err != nil {
		return err
	}
	encoded["grader-report.json"], err = marshalIndented(result.Graders)
	if err != nil {
		return err
	}
	encoded["threshold-result.json"], err = marshalIndented(result.Threshold)
	if err != nil {
		return err
	}
	encoded["trial-traces.jsonl"], err = marshalTraceStream(result.Traces)
	if err != nil {
		return err
	}
	encoded["reproduction.txt"] = []byte("./scripts/verify_sentinel_slicing.sh\n")
	names := make([]string, 0, len(encoded))
	for name := range encoded {
		names = append(names, name)
	}
	sort.Strings(names)
	artifacts := make([]Artifact, 0, len(names))
	for _, name := range names {
		if err := writeAtomic(filepath.Join(output, name), encoded[name]); err != nil {
			return err
		}
		digest := digestBytes(encoded[name])
		artifacts = append(artifacts, Artifact{Path: name, SHA256: digest[len("sha256:"):], Length: int64(len(encoded[name]))})
	}
	manifest, err := marshalIndented(ArtifactManifest{SchemaVersion: "coh.sentinel-slicing-artifacts/v1",
		CorpusDigest: suite.CorpusDigest, EnvironmentDigest: suite.EnvironmentDigest,
		ReproductionCommand: "./scripts/verify_sentinel_slicing.sh", Artifacts: artifacts})
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(output, "artifact-manifest.json"), manifest)
}

func VerifyArtifacts(output string) error {
	manifestBytes, err := readBounded(filepath.Join(output, "artifact-manifest.json"))
	if err != nil {
		return err
	}
	manifest, err := DecodeArtifacts(manifestBytes)
	if err != nil {
		return err
	}
	required := map[string]bool{"corpus-manifest.json": false, "environment-report.json": false,
		"grader-report.json": false, "reproduction.txt": false, "threshold-result.json": false, "trial-traces.jsonl": false}
	if len(manifest.Artifacts) != len(required) {
		return fmt.Errorf("artifact set differs")
	}
	files := make(map[string][]byte, len(required))
	for _, artifact := range manifest.Artifacts {
		if _, ok := required[artifact.Path]; !ok {
			return fmt.Errorf("unexpected artifact %q", artifact.Path)
		}
		data, readErr := readBounded(filepath.Join(output, artifact.Path))
		if readErr != nil || int64(len(data)) != artifact.Length || digestBytes(data) != "sha256:"+artifact.SHA256 {
			return fmt.Errorf("artifact %q differs", artifact.Path)
		}
		required[artifact.Path], files[artifact.Path] = true, data
	}
	for name, found := range required {
		if !found {
			return fmt.Errorf("required artifact %q missing", name)
		}
	}
	return verifyEvidence(manifest, files)
}

func verifyEvidence(manifest ArtifactManifest, files map[string][]byte) error {
	corpus, err := DecodeCorpus(files["corpus-manifest.json"])
	if err != nil {
		return err
	}
	var environment environmentReport
	if err := decodeExact(files["environment-report.json"], &environment); err != nil ||
		environment.SchemaVersion != "coh.sentinel-slicing-environment-report/v1" ||
		environment.CorpusDigest != manifest.CorpusDigest || environment.EnvironmentDigest != manifest.EnvironmentDigest {
		return fmt.Errorf("environment evidence differs")
	}
	if _, err := DecodeEnvironment(mustMarshal(environment.Environment)); err != nil {
		return err
	}
	graders, err := DecodeGraders(files["grader-report.json"])
	if err != nil {
		return err
	}
	threshold, err := DecodeThreshold(files["threshold-result.json"])
	if err != nil {
		return err
	}
	traces, err := decodeTraceStream(files["trial-traces.jsonl"])
	if err != nil || string(files["reproduction.txt"]) != "./scripts/verify_sentinel_slicing.sh\n" ||
		graders.CorpusDigest != manifest.CorpusDigest || graders.EnvironmentDigest != manifest.EnvironmentDigest ||
		threshold.CorpusDigest != manifest.CorpusDigest || threshold.EnvironmentDigest != manifest.EnvironmentDigest ||
		threshold.Metrics != graders.Metrics || !threshold.Passed || graders.TraceStreamDigest != digestBytes(files["trial-traces.jsonl"]) {
		return fmt.Errorf("evaluation evidence differs")
	}
	return verifyTraceCoverage(corpus, manifest, traces)
}

func verifyTraceCoverage(corpus Corpus, manifest ArtifactManifest, traces []Trace) error {
	if len(traces) != len(corpus.Tasks)*corpus.TrialsPerTask {
		return fmt.Errorf("trace trial coverage differs")
	}
	for taskIndex, task := range corpus.Tasks {
		baseline := ""
		for trial := 1; trial <= corpus.TrialsPerTask; trial++ {
			trace := traces[taskIndex*corpus.TrialsPerTask+trial-1]
			if trace.TaskID != task.ID || trace.Trial != trial || trace.TaskDigest != taskDigest(task) ||
				trace.CorpusDigest != manifest.CorpusDigest || trace.EnvironmentDigest != manifest.EnvironmentDigest ||
				!reflect.DeepEqual(trace.Observed, task.Expected) || !reflect.DeepEqual(trace.Events, task.Trajectory) ||
				(baseline != "" && trace.ReplayDigest != baseline) {
				return fmt.Errorf("trace coverage differs for task %q trial %d", task.ID, trial)
			}
			baseline = trace.ReplayDigest
		}
	}
	return nil
}

func decodeTraceStream(input []byte) ([]Trace, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	var traces []Trace
	for {
		var raw json.RawMessage
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			return traces, nil
		}
		if err != nil {
			return nil, err
		}
		trace, err := DecodeTrace(raw)
		if err != nil {
			return nil, err
		}
		traces = append(traces, trace)
	}
}

func marshalTraceStream(traces []Trace) ([]byte, error) {
	var output bytes.Buffer
	buffer := bufio.NewWriterSize(&output, 64*1024)
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	for _, trace := range traces {
		if err := encoder.Encode(trace); err != nil {
			return nil, err
		}
	}
	if err := buffer.Flush(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func marshalIndented(value interface{}) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	return append(encoded, '\n'), err
}

func mustMarshal(value interface{}) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func writeAtomic(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".sentinel-slicing-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}
