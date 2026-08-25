package replayeval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
)

const maximumContractBytes = 1 << 20

const (
	lockedCorpusDigest      = "sha256:fe2079b238cabb3c0ba358cf9f3da6993cd1e22e965d36c86c1bcc1fc4a7b8cb"
	lockedEnvironmentDigest = "sha256:4a08b5f6bb3cdcaca95557821dabaae658169a0cb41f7f6f1aa59da7df170752"
)

var requiredRequirements = []string{"FR-013", "FR-014", "EVAL-010", "EVAL-011", "EVAL-015"}

func Load(corpusPath, environmentPath string) (Suite, error) {
	var suite Suite
	corpusBytes, err := readBounded(corpusPath)
	if err != nil {
		return suite, fmt.Errorf("read corpus: %w", err)
	}
	environmentBytes, err := readBounded(environmentPath)
	if err != nil {
		return suite, fmt.Errorf("read environment: %w", err)
	}
	if err := decodeExact(corpusBytes, &suite.Corpus); err != nil {
		return Suite{}, fmt.Errorf("decode corpus: %w", err)
	}
	if err := decodeExact(environmentBytes, &suite.Environment); err != nil {
		return Suite{}, fmt.Errorf("decode environment: %w", err)
	}
	suite.CorpusDigest = digest(corpusBytes)
	suite.EnvironmentDigest = digest(environmentBytes)
	if err := validateSuite(suite); err != nil {
		return Suite{}, err
	}
	return suite, nil
}

// ValidateRuntime proves that generated evidence came from the qualified
// executable environment rather than merely describing it in a manifest.
func ValidateRuntime(environment Environment) error {
	if runtime.Version() != "go"+environment.GoVersion || runtime.GOOS+"/"+runtime.GOARCH != environment.QualifiedPlatform {
		return fmt.Errorf("runtime differs from the qualified evaluation environment")
	}
	return nil
}

func readBounded(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maximumContractBytes {
		return nil, fmt.Errorf("contract path is not a bounded regular file")
	}
	return os.ReadFile(path)
}

func decodeExact(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	return nil
}

func validateSuite(suite Suite) error {
	if suite.CorpusDigest != lockedCorpusDigest || suite.EnvironmentDigest != lockedEnvironmentDigest {
		return fmt.Errorf("corpus or environment bytes differ from the locked evaluator")
	}
	corpus := suite.Corpus
	if corpus.SchemaVersion != "coh.replay-fault-corpus/v1" || corpus.CorpusVersion != "1.0.0" || !reflect.DeepEqual(corpus.Requirements, requiredRequirements) {
		return fmt.Errorf("unsupported corpus identity or requirement set")
	}
	if corpus.TrialsPerTask < 5 || corpus.TrialsPerTask > 100 || corpus.Thresholds != strictThresholds() {
		return fmt.Errorf("trial bounds or release thresholds differ from the locked contract")
	}
	environment := suite.Environment
	wantEnvironment := Environment{
		SchemaVersion: "coh.replay-environment/v1", EnvironmentVersion: "1.0.0", CorpusVersion: corpus.CorpusVersion,
		GoVersion: "1.26.7", TemporalSDK: "go.temporal.io/sdk@v1.45.0", TemporalAPI: "go.temporal.io/api@v1.62.12",
		SQLiteDriver: "modernc.org/sqlite@v1.57.0", PostgresDriver: "github.com/jackc/pgx/v5@v5.10.0",
		PostgresImage:     "postgres@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777",
		QualifiedPlatform: "darwin/arm64", Clock: "logical-trial-clock/v1", Randomness: "none",
	}
	if environment != wantEnvironment {
		return fmt.Errorf("environment differs from the qualified contract")
	}
	seenIDs, seenBoundaries := make(map[string]bool), make(map[string]bool)
	for _, task := range corpus.Tasks {
		if task.ID == "" || seenIDs[task.ID] || !allowedBoundaries[task.Boundary] {
			return fmt.Errorf("invalid or duplicate task identity %q", task.ID)
		}
		observed, _, ok := simulate(task.Mode)
		if !ok || observed != task.Expected {
			return fmt.Errorf("task %q mode or expected result is not registered", task.ID)
		}
		seenIDs[task.ID], seenBoundaries[task.Boundary] = true, true
	}
	for boundary := range allowedBoundaries {
		if !seenBoundaries[boundary] {
			return fmt.Errorf("required boundary %q is missing", boundary)
		}
	}
	return nil
}

func strictThresholds() Thresholds {
	return Thresholds{MinimumReconciliationRate: 1, MinimumReplayRate: 1, MinimumOutcomeGradeRate: 1, MinimumTrajectoryGradeRate: 1}
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
