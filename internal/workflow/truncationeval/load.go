package truncationeval

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
	lockedCorpusDigest      = "sha256:1a341c2824118f4ba0014a273e15a64068db4bd893d9c0441e4e746751ee7ef0"
	lockedEnvironmentDigest = "sha256:3090ae88736726c8a5bb8c08a48ef58a5db608b23fd478d0960bc06b6e3349c3"
)

var contractPaths = map[string]string{
	"artifacts-contract":   "contracts/evaluation/truncation/v1/connector-truncation-artifacts.schema.json",
	"corpus-contract":      "contracts/evaluation/truncation/v1/connector-truncation-corpus.schema.json",
	"environment-contract": "contracts/evaluation/truncation/v1/connector-truncation-environment.schema.json",
	"graders-contract":     "contracts/evaluation/truncation/v1/connector-truncation-graders.schema.json",
	"recording-contract":   "contracts/evaluation/truncation/v1/connector-truncation-recording.schema.json",
	"threshold-contract":   "contracts/evaluation/truncation/v1/connector-truncation-threshold.schema.json",
	"trace-contract":       "contracts/evaluation/truncation/v1/connector-truncation-trace.schema.json",
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
		return Suite{}, fmt.Errorf("corpus or environment bytes differ from locked evaluator")
	}
	if err := validatePins(root, environment.Contracts, contractPaths); err != nil {
		return Suite{}, err
	}
	fixturePaths := make(map[string]string, len(environment.FixtureManifests))
	for _, pin := range environment.FixtureManifests {
		fixturePaths[pin.Name] = pin.Digest
	}
	if err := loadRecordings(root, fixturePaths, &suite); err != nil {
		return Suite{}, err
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
		return fmt.Errorf("contract pin set is incomplete")
	}
	for _, pin := range pins {
		relative, ok := paths[pin.Name]
		if !ok {
			return fmt.Errorf("unknown contract pin %q", pin.Name)
		}
		data, err := readBounded(filepath.Join(root, relative))
		if err != nil || digestBytes(data) != pin.Digest {
			return fmt.Errorf("contract pin %q differs", pin.Name)
		}
	}
	return nil
}

func loadRecordings(root string, pins map[string]string, suite *Suite) error {
	files := []struct{ name, path string }{
		{"elastic-recordings", "internal/workflow/truncationeval/testdata/1.0.0/elastic-recordings.json"},
		{"security-onion-recordings", "internal/workflow/truncationeval/testdata/1.0.0/security-onion-recordings.json"},
	}
	if len(pins) != len(files) {
		return fmt.Errorf("fixture pin set is incomplete")
	}
	for _, file := range files {
		data, err := readBounded(filepath.Join(root, file.path))
		if err != nil || pins[file.name] != digestBytes(data) {
			return fmt.Errorf("fixture pin %q differs", file.name)
		}
		set, err := DecodeRecordings(data)
		if err != nil {
			return fmt.Errorf("decode fixture %q: %w", file.name, err)
		}
		for _, recording := range set.Recordings {
			if _, exists := suite.Recordings[recording.ID]; exists {
				return fmt.Errorf("duplicate recording %q", recording.ID)
			}
			suite.Recordings[recording.ID] = recording
		}
	}
	return nil
}

func bindTasks(suite Suite) error {
	if len(suite.Corpus.Tasks) != len(suite.Recordings) {
		return fmt.Errorf("corpus does not cover every recording")
	}
	seenBoundaries := make(map[string]struct{})
	for _, task := range suite.Corpus.Tasks {
		recording, exists := suite.Recordings[task.ID]
		if !exists || len(task.Fixtures) != 1 || recording.Mode != task.Mode || recording.Boundary != task.Boundary ||
			recording.Fault != task.Fault || !reflect.DeepEqual(recording.Expected, task.Expected) ||
			!reflect.DeepEqual(recording.Trajectory, task.Trajectory) {
			return fmt.Errorf("task %q differs from its recording", task.ID)
		}
		wantVendor := "security_onion"
		wantFixture := FixtureRef{Path: "internal/workflow/truncationeval/testdata/1.0.0/security-onion-recordings.json",
			SHA256: "sha256:ae6bf9060d8ad0ce0d3ebcdcb8eb8cc8fd50a2c9723c324ae5dccfd7263b9046"}
		if len(task.ID) >= 8 && task.ID[:8] == "elastic-" {
			wantVendor = "elastic"
			wantFixture = FixtureRef{Path: "internal/workflow/truncationeval/testdata/1.0.0/elastic-recordings.json",
				SHA256: "sha256:5a7b46f4e21e064bbba6d9061122561ccff2bfdcdb38391b356995347dcaaa0f"}
		}
		if task.Vendor != wantVendor || task.Fixtures[0] != wantFixture {
			return fmt.Errorf("task %q vendor or fixture differs", task.ID)
		}
		seenBoundaries[task.Boundary] = struct{}{}
	}
	if len(seenBoundaries) != len(suite.Corpus.Tasks) {
		return fmt.Errorf("required boundary coverage is incomplete")
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
