// Package replayeval runs the deterministic CYB-44 crash-fault corpus.
package replayeval

type Corpus struct {
	SchemaVersion string     `json:"schema_version"`
	CorpusVersion string     `json:"corpus_version"`
	Requirements  []string   `json:"requirements"`
	TrialsPerTask int        `json:"trials_per_task"`
	Thresholds    Thresholds `json:"thresholds"`
	Tasks         []Task     `json:"tasks"`
}

type Thresholds struct {
	MaximumDuplicateConfirmedEffects int     `json:"maximum_duplicate_confirmed_effects"`
	MaximumFalseSuccesses            int     `json:"maximum_false_successes"`
	MinimumReconciliationRate        float64 `json:"minimum_reconciliation_rate"`
	MinimumReplayRate                float64 `json:"minimum_replay_rate"`
	MinimumOutcomeGradeRate          float64 `json:"minimum_outcome_grade_rate"`
	MinimumTrajectoryGradeRate       float64 `json:"minimum_trajectory_grade_rate"`
}

type Task struct {
	ID       string   `json:"id"`
	Boundary string   `json:"boundary"`
	Fault    string   `json:"fault"`
	Mode     string   `json:"mode"`
	Expected Observed `json:"expected"`
}

type Observed struct {
	State                  string `json:"state"`
	Dispatches             int    `json:"dispatches"`
	ExternalEffects        int    `json:"external_effects"`
	ConfirmedEffects       int    `json:"confirmed_effects"`
	RequiresReconciliation bool   `json:"requires_reconciliation"`
	Replayed               bool   `json:"replayed"`
}

type Environment struct {
	SchemaVersion      string `json:"schema_version"`
	EnvironmentVersion string `json:"environment_version"`
	CorpusVersion      string `json:"corpus_version"`
	GoVersion          string `json:"go_version"`
	TemporalSDK        string `json:"temporal_sdk"`
	TemporalAPI        string `json:"temporal_api"`
	SQLiteDriver       string `json:"sqlite_driver"`
	PostgresDriver     string `json:"postgres_driver"`
	PostgresImage      string `json:"postgres_image"`
	QualifiedPlatform  string `json:"qualified_platform"`
	Clock              string `json:"clock"`
	Randomness         string `json:"randomness"`
}

type Suite struct {
	Corpus            Corpus
	Environment       Environment
	CorpusDigest      string
	EnvironmentDigest string
}

type Trace struct {
	SchemaVersion   string   `json:"schema_version"`
	CorpusVersion   string   `json:"corpus_version"`
	TaskID          string   `json:"task_id"`
	Trial           int      `json:"trial"`
	Boundary        string   `json:"boundary"`
	Fault           string   `json:"fault"`
	Events          []string `json:"events"`
	Observed        Observed `json:"observed"`
	OutcomeGrade    bool     `json:"outcome_grade"`
	TrajectoryGrade bool     `json:"trajectory_grade"`
}

type Metrics struct {
	TaskCount                 int     `json:"task_count"`
	TrialCount                int     `json:"trial_count"`
	DuplicateConfirmedEffects int     `json:"duplicate_confirmed_effects"`
	FalseSuccesses            int     `json:"false_successes"`
	ReconciliationRate        float64 `json:"reconciliation_rate"`
	ReplayRate                float64 `json:"replay_rate"`
	OutcomeGradeRate          float64 `json:"outcome_grade_rate"`
	TrajectoryGradeRate       float64 `json:"trajectory_grade_rate"`
}

type GraderReport struct {
	SchemaVersion     string  `json:"schema_version"`
	CorpusVersion     string  `json:"corpus_version"`
	CorpusDigest      string  `json:"corpus_digest"`
	EnvironmentDigest string  `json:"environment_digest"`
	Metrics           Metrics `json:"metrics"`
}

type ThresholdResult struct {
	SchemaVersion string     `json:"schema_version"`
	Thresholds    Thresholds `json:"thresholds"`
	Metrics       Metrics    `json:"metrics"`
	Outcome       string     `json:"outcome"`
}

type RunResult struct {
	Traces    []Trace
	Graders   GraderReport
	Threshold ThresholdResult
}
