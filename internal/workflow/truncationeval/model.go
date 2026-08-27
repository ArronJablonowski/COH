// Package truncationeval evaluates connector completeness against a locked,
// deterministic, no-network fixture corpus.
package truncationeval

type Thresholds struct {
	MaximumFalseComplete        int     `json:"maximum_false_complete"`
	MaximumDuplicateRows        int     `json:"maximum_duplicate_rows"`
	MaximumMissingRows          int     `json:"maximum_missing_rows"`
	MinimumReplayRate           float64 `json:"minimum_replay_rate"`
	MinimumOutcomeGradeRate     float64 `json:"minimum_outcome_grade_rate"`
	MinimumTrajectoryGradeRate  float64 `json:"minimum_trajectory_grade_rate"`
	MinimumBoundaryCoverageRate float64 `json:"minimum_boundary_coverage_rate"`
}

type FixtureRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Expected struct {
	Outcome            string   `json:"outcome"`
	CompletenessStatus string   `json:"completeness_status"`
	ReasonCodes        []string `json:"reason_codes"`
	Truncated          bool     `json:"truncated"`
	Partial            bool     `json:"partial"`
	VendorConfirmed    bool     `json:"vendor_confirmed"`
	RowsReturned       int      `json:"rows_returned"`
	PagesReturned      int      `json:"pages_returned"`
	AdaptiveSlicing    string   `json:"adaptive_slicing"`
}

type Task struct {
	ID         string       `json:"id"`
	Vendor     string       `json:"vendor"`
	Mode       string       `json:"mode"`
	Boundary   string       `json:"boundary"`
	Fault      string       `json:"fault"`
	Fixtures   []FixtureRef `json:"fixtures"`
	Expected   Expected     `json:"expected"`
	Trajectory []string     `json:"trajectory"`
}

type RecordingStep struct {
	Sequence       int      `json:"sequence"`
	Operation      string   `json:"operation"`
	Outcome        string   `json:"outcome"`
	HTTPStatus     int      `json:"http_status,omitempty"`
	RowIDs         []string `json:"row_ids,omitempty"`
	SortKeys       []string `json:"sort_keys,omitempty"`
	RowTimestamps  []string `json:"row_timestamps,omitempty"`
	TotalHits      int      `json:"total_hits,omitempty"`
	RequestedLimit int      `json:"requested_limit,omitempty"`
	OmittedCount   int      `json:"omitted_count,omitempty"`
	TotalRelation  string   `json:"total_relation,omitempty"`
	HasMore        bool     `json:"has_more,omitempty"`
	PITToken       string   `json:"pit_token,omitempty"`
	Partial        bool     `json:"partial,omitempty"`
	Truncated      bool     `json:"truncated,omitempty"`
	ErrorCode      string   `json:"error_code,omitempty"`
	CloseConfirmed bool     `json:"close_confirmed,omitempty"`
	SliceStart     string   `json:"slice_start,omitempty"`
	SliceEnd       string   `json:"slice_end,omitempty"`
	EndExclusive   bool     `json:"end_exclusive,omitempty"`
	StableIdentity bool     `json:"stable_identity,omitempty"`
	StableSort     bool     `json:"stable_sort,omitempty"`
}

type Recording struct {
	Vendor     string          `json:"-"`
	ID         string          `json:"id"`
	Mode       string          `json:"mode"`
	Boundary   string          `json:"boundary"`
	Fault      string          `json:"fault"`
	Steps      []RecordingStep `json:"steps"`
	Expected   Expected        `json:"expected"`
	Trajectory []string        `json:"trajectory"`
}

type RecordingSet struct {
	SchemaVersion    string      `json:"schema_version"`
	RecordingVersion string      `json:"recording_version"`
	Vendor           string      `json:"vendor"`
	Sanitized        bool        `json:"sanitized"`
	Network          string      `json:"network"`
	Recordings       []Recording `json:"recordings"`
}

type Corpus struct {
	SchemaVersion string     `json:"schema_version"`
	CorpusVersion string     `json:"corpus_version"`
	Requirements  []string   `json:"requirements"`
	TrialsPerTask int        `json:"trials_per_task"`
	Thresholds    Thresholds `json:"thresholds"`
	Tasks         []Task     `json:"tasks"`
}

type Pin struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
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
	FixtureManifests   []Pin  `json:"fixture_manifests"`
}

type Observed struct {
	Expected
	DuplicateRows int `json:"duplicate_rows"`
	MissingRows   int `json:"missing_rows"`
}

type Trace struct {
	SchemaVersion     string   `json:"schema_version"`
	CorpusVersion     string   `json:"corpus_version"`
	CorpusDigest      string   `json:"corpus_digest"`
	EnvironmentDigest string   `json:"environment_digest"`
	TaskDigest        string   `json:"task_digest"`
	TaskID            string   `json:"task_id"`
	Trial             int      `json:"trial"`
	Events            []string `json:"events"`
	Observed          Observed `json:"observed"`
	OutcomeGrade      bool     `json:"outcome_grade"`
	TrajectoryGrade   bool     `json:"trajectory_grade"`
	ReplayDigest      string   `json:"replay_digest"`
}

type Metrics struct {
	TaskCount             int     `json:"task_count"`
	TrialCount            int     `json:"trial_count"`
	RequiredBoundaryCount int     `json:"required_boundary_count"`
	CoveredBoundaryCount  int     `json:"covered_boundary_count"`
	FalseComplete         int     `json:"false_complete"`
	DuplicateRows         int     `json:"duplicate_rows"`
	MissingRows           int     `json:"missing_rows"`
	ReplayRate            float64 `json:"replay_rate"`
	OutcomeGradeRate      float64 `json:"outcome_grade_rate"`
	TrajectoryGradeRate   float64 `json:"trajectory_grade_rate"`
	BoundaryCoverageRate  float64 `json:"boundary_coverage_rate"`
}

type GraderReport struct {
	SchemaVersion     string  `json:"schema_version"`
	CorpusVersion     string  `json:"corpus_version"`
	CorpusDigest      string  `json:"corpus_digest"`
	EnvironmentDigest string  `json:"environment_digest"`
	Metrics           Metrics `json:"metrics"`
	TraceStreamDigest string  `json:"trace_stream_digest"`
}

type ThresholdResult struct {
	SchemaVersion     string     `json:"schema_version"`
	CorpusDigest      string     `json:"corpus_digest"`
	EnvironmentDigest string     `json:"environment_digest"`
	Thresholds        Thresholds `json:"thresholds"`
	Metrics           Metrics    `json:"metrics"`
	Outcome           string     `json:"outcome"`
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
