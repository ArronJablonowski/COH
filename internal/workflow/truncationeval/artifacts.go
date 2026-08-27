package truncationeval

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(output)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output directory unavailable")
	}
	encoded := make(map[string][]byte)
	if encoded["corpus-manifest.json"], err = marshalIndented(suite.Corpus); err != nil {
		return err
	}
	if encoded["environment-report.json"], err = marshalIndented(environmentReport{SchemaVersion: "coh.connector-truncation-environment-report/v1",
		Environment: suite.Environment, EnvironmentDigest: suite.EnvironmentDigest, CorpusDigest: suite.CorpusDigest}); err != nil {
		return err
	}
	if encoded["grader-report.json"], err = marshalIndented(result.Graders); err != nil {
		return err
	}
	if encoded["threshold-result.json"], err = marshalIndented(result.Threshold); err != nil {
		return err
	}
	if encoded["trial-traces.jsonl"], err = marshalTraceStream(result.Traces); err != nil {
		return err
	}
	encoded["reproduction.txt"] = []byte("./scripts/verify_connector_truncation.sh\n")
	names := make([]string, 0, len(encoded))
	for name := range encoded {
		names = append(names, name)
	}
	sort.Strings(names)
	records := make([]Artifact, 0, len(names))
	for _, name := range names {
		if err := writeAtomic(filepath.Join(output, name), encoded[name]); err != nil {
			return err
		}
		digest := digestBytes(encoded[name])
		records = append(records, Artifact{Path: name, SHA256: digest[len("sha256:"):], Length: int64(len(encoded[name]))})
	}
	manifest, err := marshalIndented(ArtifactManifest{SchemaVersion: "coh.connector-truncation-artifacts/v1",
		CorpusDigest: suite.CorpusDigest, EnvironmentDigest: suite.EnvironmentDigest,
		ReproductionCommand: "./scripts/verify_connector_truncation.sh", Artifacts: records})
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
	for _, artifact := range manifest.Artifacts {
		data, err := readBounded(filepath.Join(output, artifact.Path))
		if err != nil || int64(len(data)) != artifact.Length {
			return fmt.Errorf("artifact %q length differs", artifact.Path)
		}
		digest := digestBytes(data)
		decoded, _ := hex.DecodeString(artifact.SHA256)
		if len(decoded) != 32 || digest != "sha256:"+artifact.SHA256 {
			return fmt.Errorf("artifact %q digest differs", artifact.Path)
		}
	}
	return nil
}

func marshalIndented(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
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

func writeAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".truncation-eval-*")
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
