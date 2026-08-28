package sentinelsliceeval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
)

const (
	lockedCorpusDigest      = "sha256:c542d7e2b6601e86aefb14e7480fb74b05c3a0739462377ae59fabc68778407e"
	lockedEnvironmentDigest = "sha256:4c3e54347ed0aa1c2cd68c73d74537cc2eca2138a1f94f18ae3f2f1677e6da65"
)

var sentinelContractPaths = map[string]string{
	"common-query":                "contracts/query/v1/query-connector.schema.json",
	"kusto-helper-response":       "contracts/kusto-validator/v1/helper-response.schema.json",
	"sentinel-query":              "contracts/sentinel-query/v1/sentinel-query-contracts.schema.json",
	"sentinel-slicing-evaluation": "contracts/evaluation/sentinel-slicing/v1/sentinel-slicing-evaluation.schema.json",
	"sentinel-query-denials":      "contracts/sentinel-query/v1/fixtures/denial-corpus.json",
}

var sentinelFixturePaths = map[string]string{
	"sentinel-recordings":          "contracts/evaluation/sentinel-slicing/v1/sentinel-recordings.json",
	"sentinel-success":             "contracts/sentinel-query/v1/fixtures/vendor/success.json",
	"sentinel-partial-error":       "contracts/sentinel-query/v1/fixtures/vendor/partial-error.json",
	"sentinel-identical-timestamp": "contracts/sentinel-query/v1/fixtures/vendor/identical-timestamp-ambiguous.json",
}

func Load(root, corpusPath, environmentPath string) (Suite, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return Suite{}, fmt.Errorf("absolute clean repository root required")
	}
	corpusBytes, err := readBounded(corpusPath)
	if err != nil {
		return Suite{}, fmt.Errorf("read corpus: %w", err)
	}
	environmentBytes, err := readBounded(environmentPath)
	if err != nil {
		return Suite{}, fmt.Errorf("read environment: %w", err)
	}
	corpus, err := DecodeCorpus(corpusBytes)
	if err != nil {
		return Suite{}, fmt.Errorf("decode corpus: %w", err)
	}
	environment, err := DecodeEnvironment(environmentBytes)
	if err != nil {
		return Suite{}, fmt.Errorf("decode environment: %w", err)
	}
	suite := Suite{Corpus: corpus, Environment: environment, CorpusDigest: digestBytes(corpusBytes),
		EnvironmentDigest: digestBytes(environmentBytes), Recordings: make(map[string]Recording)}
	if suite.CorpusDigest != lockedCorpusDigest || suite.EnvironmentDigest != lockedEnvironmentDigest {
		return Suite{}, fmt.Errorf("corpus or environment differs from locked evaluator")
	}
	if err := validatePins(root, environment.Contracts, sentinelContractPaths); err != nil {
		return Suite{}, err
	}
	if err := validatePins(root, environment.Fixtures, sentinelFixturePaths); err != nil {
		return Suite{}, err
	}
	recordingBytes, err := readBounded(filepath.Join(root, sentinelFixturePaths["sentinel-recordings"]))
	if err != nil {
		return Suite{}, err
	}
	recordings, err := DecodeRecordings(recordingBytes)
	if err != nil {
		return Suite{}, err
	}
	for _, recording := range recordings.Recordings {
		suite.Recordings[recording.ID] = recording
	}
	if err := bindTasks(suite); err != nil {
		return Suite{}, err
	}
	return suite, nil
}

func ValidateRuntime(environment Environment) error {
	if runtime.Version() != "go"+environment.GoVersion || runtime.GOOS+"/"+runtime.GOARCH != environment.QualifiedPlatform {
		return fmt.Errorf("runtime differs from qualified evaluation environment")
	}
	return nil
}

func readBounded(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximumContractBytes {
		return nil, fmt.Errorf("path is not a bounded regular file")
	}
	return os.ReadFile(path)
}

func validatePins(root string, pins []Pin, paths map[string]string) error {
	if len(pins) != len(paths) {
		return fmt.Errorf("pin set is incomplete")
	}
	for _, pin := range pins {
		relative, ok := paths[pin.Name]
		if !ok {
			return fmt.Errorf("unknown pin %q", pin.Name)
		}
		data, err := readBounded(filepath.Join(root, relative))
		if err != nil || digestBytes(data) != pin.SHA256 {
			return fmt.Errorf("pin %q differs", pin.Name)
		}
	}
	return nil
}

func bindTasks(suite Suite) error {
	if len(suite.Corpus.Tasks) != len(suite.Recordings) {
		return fmt.Errorf("corpus does not cover every recording")
	}
	for _, task := range suite.Corpus.Tasks {
		recording, ok := suite.Recordings[task.RecordingID]
		if !ok || task.ID != recording.ID || task.RecordingSHA256 != "sha256:1b1242605fb1b8d6b8ae7ccd718376c8cf661b292a3e8dd1bd707322adf01589" ||
			task.Boundary != recording.Boundary || task.Fault != recording.Fault ||
			!reflect.DeepEqual(task.Expected, recording.Expected) || !reflect.DeepEqual(task.Trajectory, recording.Trajectory) {
			return fmt.Errorf("task %q differs from its recording", task.ID)
		}
	}
	return nil
}

func taskDigest(task Task) string {
	encoded, _ := json.Marshal(task)
	return digestBytes(encoded)
}

func digestBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
