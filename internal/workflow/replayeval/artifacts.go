package replayeval

import (
	"bufio"
	"crypto/sha256"
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

type artifactRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Length int64  `json:"length"`
}

type artifactManifest struct {
	SchemaVersion string           `json:"schema_version"`
	Artifacts     []artifactRecord `json:"artifacts"`
}

func WriteArtifacts(output string, suite Suite, result RunResult) error {
	if output == "" || !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return fmt.Errorf("absolute clean output directory is required")
	}
	if err := os.MkdirAll(output, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(output)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("output directory is unavailable")
	}
	encoded := map[string][]byte{}
	if encoded["corpus-manifest.json"], err = marshalJSON(suite.Corpus); err != nil {
		return err
	}
	if encoded["environment-report.json"], err = marshalJSON(environmentReport{
		SchemaVersion: "coh.replay-environment-report/v1", Environment: suite.Environment,
		EnvironmentDigest: suite.EnvironmentDigest, CorpusDigest: suite.CorpusDigest,
	}); err != nil {
		return err
	}
	if encoded["grader-report.json"], err = marshalJSON(result.Graders); err != nil {
		return err
	}
	if encoded["threshold-result.json"], err = marshalJSON(result.Threshold); err != nil {
		return err
	}
	encoded["reproduction.txt"] = []byte("./scripts/verify_replay_faults.sh\n")
	if encoded["trial-traces.jsonl"], err = marshalTraces(result.Traces); err != nil {
		return err
	}
	names := make([]string, 0, len(encoded))
	for name := range encoded {
		names = append(names, name)
	}
	sort.Strings(names)
	records := make([]artifactRecord, 0, len(names))
	for _, name := range names {
		if err := writeFileAtomic(filepath.Join(output, name), encoded[name]); err != nil {
			return err
		}
		sum := sha256.Sum256(encoded[name])
		records = append(records, artifactRecord{Path: name, SHA256: hex.EncodeToString(sum[:]), Length: int64(len(encoded[name]))})
	}
	manifest, err := marshalJSON(artifactManifest{SchemaVersion: "coh.replay-fault-artifacts/v1", Artifacts: records})
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(output, "artifact-manifest.json"), manifest)
}

func marshalJSON(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func marshalTraces(traces []Trace) ([]byte, error) {
	var result []byte
	buffer := bufio.NewWriterSize(sliceWriter{target: &result}, 64*1024)
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
	return result, nil
}

type sliceWriter struct{ target *[]byte }

func (writer sliceWriter) Write(data []byte) (int, error) {
	*writer.target = append(*writer.target, data...)
	return len(data), nil
}

func writeFileAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".replay-eval-*")
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
