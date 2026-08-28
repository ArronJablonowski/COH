// Package sentinelsliceeval evaluates the Sentinel bounded-query boundary
// against a locked deterministic no-network fixture corpus.
package sentinelsliceeval

type Thresholds struct {
	MaximumFalseComplete        int     `json:"maximum_false_complete"`
	MaximumReleasedDeniedRows   int     `json:"maximum_released_denied_rows"`
	MinimumOutcomeGradeRate     float64 `json:"minimum_outcome_grade_rate"`
	MinimumTrajectoryGradeRate  float64 `json:"minimum_trajectory_grade_rate"`
	MinimumReplayRate           float64 `json:"minimum_replay_rate"`
	MinimumBoundaryCoverageRate float64 `json:"minimum_boundary_coverage_rate"`
}

type Expected struct {
	Outcome         string   `json:"outcome"`
	Completeness    string   `json:"completeness"`
	ReasonCodes     []string `json:"reason_codes"`
	RowsReturned    int      `json:"rows_returned"`
	SlicesCompleted int      `json:"slices_completed"`
	ReleasedRows    int      `json:"released_rows"`
}

type Task struct {
	ID              string   `json:"id"`
	Boundary        string   `json:"boundary"`
	Fault           string   `json:"fault"`
	RecordingID     string   `json:"recording_id"`
	RecordingSHA256 string   `json:"recording_sha256"`
	Expected        Expected `json:"expected"`
	Trajectory      []string `json:"trajectory"`
}

type Corpus struct {
	SchemaVersion string     `json:"schema_version"`
	CorpusVersion string     `json:"corpus_version"`
	Issue         string     `json:"issue"`
	Requirements  []string   `json:"requirements"`
	TrialsPerTask int        `json:"trials_per_task"`
	Thresholds    Thresholds `json:"thresholds"`
	Tasks         []Task     `json:"tasks"`
}

type Pin struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type Environment struct {
	SchemaVersion      string `json:"schema_version"`
	EnvironmentVersion string `json:"environment_version"`
	CorpusVersion      string `json:"corpus_version"`
	GoVersion          string `json:"go_version"`
	QualifiedPlatform  string `json:"qualified_platform"`
	Clock              string `json:"clock"`
	Randomness         string `json:"randomness"`
	Network            string `json:"network"`
	Contracts          []Pin  `json:"contracts"`
	Fixtures           []Pin  `json:"fixtures"`
}

type RecordingStep struct {
	Sequence         int      `json:"sequence"`
	Event            string   `json:"event"`
	SliceStart       string   `json:"slice_start"`
	SliceEnd         string   `json:"slice_end"`
	EndExclusive     bool     `json:"end_exclusive"`
	RowKeys          []string `json:"row_keys"`
	RowDigests       []string `json:"row_digests"`
	Outcome          string   `json:"outcome"`
	Partial          bool     `json:"partial"`
	ThresholdReached bool     `json:"threshold_reached"`
	RequestDigest    string   `json:"request_digest"`
	ResponseDigest   string   `json:"response_digest"`
}

type Recording struct {
	ID         string          `json:"id"`
	Boundary   string          `json:"boundary"`
	Fault      string          `json:"fault"`
	Sanitized  bool            `json:"sanitized"`
	Network    string          `json:"network"`
	Steps      []RecordingStep `json:"steps"`
	Expected   Expected        `json:"expected"`
	Trajectory []string        `json:"trajectory"`
}

type RecordingSet struct {
	SchemaVersion    string      `json:"schema_version"`
	RecordingVersion string      `json:"recording_version"`
	Sanitized        bool        `json:"sanitized"`
	Network          string      `json:"network"`
	Recordings       []Recording `json:"recordings"`
}

type Trace struct {
	SchemaVersion     string   `json:"schema_version"`
	CorpusDigest      string   `json:"corpus_digest"`
	EnvironmentDigest string   `json:"environment_digest"`
	TaskDigest        string   `json:"task_digest"`
	TaskID            string   `json:"task_id"`
	Trial             int      `json:"trial"`
	Events            []string `json:"events"`
	Observed          Expected `json:"observed"`
	ReplayDigest      string   `json:"replay_digest"`
}

type Metrics struct {
	TaskCount            int     `json:"task_count"`
	TrialCount           int     `json:"trial_count"`
	FalseComplete        int     `json:"false_complete"`
	ReleasedDeniedRows   int     `json:"released_denied_rows"`
	OutcomeGradeRate     float64 `json:"outcome_grade_rate"`
	TrajectoryGradeRate  float64 `json:"trajectory_grade_rate"`
	ReplayRate           float64 `json:"replay_rate"`
	BoundaryCoverageRate float64 `json:"boundary_coverage_rate"`
}

type GraderReport struct {
	SchemaVersion     string  `json:"schema_version"`
	CorpusDigest      string  `json:"corpus_digest"`
	EnvironmentDigest string  `json:"environment_digest"`
	TraceStreamDigest string  `json:"trace_stream_digest"`
	Metrics           Metrics `json:"metrics"`
}

type ThresholdResult struct {
	SchemaVersion     string     `json:"schema_version"`
	CorpusDigest      string     `json:"corpus_digest"`
	EnvironmentDigest string     `json:"environment_digest"`
	Thresholds        Thresholds `json:"thresholds"`
	Metrics           Metrics    `json:"metrics"`
	Passed            bool       `json:"passed"`
}

type Artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Length int64  `json:"length"`
}

type ArtifactManifest struct {
	SchemaVersion       string     `json:"schema_version"`
	CorpusDigest        string     `json:"corpus_digest"`
	EnvironmentDigest   string     `json:"environment_digest"`
	ReproductionCommand string     `json:"reproduction_command"`
	Artifacts           []Artifact `json:"artifacts"`
}

type Suite struct {
	Corpus            Corpus
	Environment       Environment
	CorpusDigest      string
	EnvironmentDigest string
	Recordings        map[string]Recording
}

type RunResult struct {
	Traces    []Trace
	Graders   GraderReport
	Threshold ThresholdResult
}
