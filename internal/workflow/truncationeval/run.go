package truncationeval

import (
	"encoding/json"
	"reflect"
)

func Run(suite Suite) RunResult {
	traces := make([]Trace, 0, len(suite.Corpus.Tasks)*suite.Corpus.TrialsPerTask)
	metrics := Metrics{TaskCount: len(suite.Corpus.Tasks)}
	boundaries := make(map[string]struct{}, len(suite.Corpus.Tasks))
	replayPassed, outcomePassed, trajectoryPassed := 0, 0, 0
	for _, task := range suite.Corpus.Tasks {
		boundaries[task.Boundary] = struct{}{}
		baseline := ""
		for trial := 1; trial <= suite.Corpus.TrialsPerTask; trial++ {
			observed, events := observe(suite.Recordings[task.ID])
			outcomeGrade := reflect.DeepEqual(observed.Expected, task.Expected) && observed.DuplicateRows == 0 && observed.MissingRows == 0
			trajectoryGrade := reflect.DeepEqual(events, task.Trajectory) && safeTrajectory(observed)
			taskHash := taskDigest(task)
			replayHash := digestJSON(struct {
				Task     string
				Observed Observed
				Events   []string
			}{taskHash, observed, events})
			if baseline == "" {
				baseline = replayHash
			}
			if replayHash == baseline {
				replayPassed++
			}
			if outcomeGrade {
				outcomePassed++
			}
			if trajectoryGrade {
				trajectoryPassed++
			}
			if observed.CompletenessStatus == "complete" && !completeProven(suite.Recordings[task.ID]) {
				metrics.FalseComplete++
			}
			metrics.DuplicateRows += observed.DuplicateRows
			metrics.MissingRows += observed.MissingRows
			metrics.TrialCount++
			traces = append(traces, Trace{SchemaVersion: "coh.connector-truncation-trace/v1", CorpusVersion: suite.Corpus.CorpusVersion,
				CorpusDigest: suite.CorpusDigest, EnvironmentDigest: suite.EnvironmentDigest, TaskDigest: taskHash,
				TaskID: task.ID, Trial: trial, Events: events, Observed: observed, OutcomeGrade: outcomeGrade,
				TrajectoryGrade: trajectoryGrade, ReplayDigest: replayHash})
		}
	}
	metrics.RequiredBoundaryCount = len(suite.Corpus.Tasks)
	metrics.CoveredBoundaryCount = len(boundaries)
	metrics.ReplayRate = ratio(replayPassed, metrics.TrialCount)
	metrics.OutcomeGradeRate = ratio(outcomePassed, metrics.TrialCount)
	metrics.TrajectoryGradeRate = ratio(trajectoryPassed, metrics.TrialCount)
	metrics.BoundaryCoverageRate = ratio(metrics.CoveredBoundaryCount, metrics.RequiredBoundaryCount)
	traceBytes, _ := marshalTraceStream(traces)
	traceDigest := digestBytes(traceBytes)
	graders := GraderReport{SchemaVersion: "coh.connector-truncation-graders/v1", CorpusVersion: suite.Corpus.CorpusVersion,
		CorpusDigest: suite.CorpusDigest, EnvironmentDigest: suite.EnvironmentDigest, Metrics: metrics, TraceStreamDigest: traceDigest}
	threshold := ThresholdResult{SchemaVersion: "coh.connector-truncation-threshold/v1", CorpusDigest: suite.CorpusDigest,
		EnvironmentDigest: suite.EnvironmentDigest, Thresholds: suite.Corpus.Thresholds, Metrics: metrics, Outcome: "denied"}
	if validThresholdOutcome(ThresholdResult{Thresholds: threshold.Thresholds, Metrics: metrics, Outcome: "passed"}) {
		threshold.Outcome = "passed"
	}
	return RunResult{Traces: traces, Graders: graders, Threshold: threshold}
}

func observe(recording Recording) (Observed, []string) {
	if recording.Mode == "adaptive_slice" {
		if recording.Expected.AdaptiveSlicing == "unsupported" {
			return Observed{Expected: Expected{Outcome: "denied", CompletenessStatus: "not_applicable",
				ReasonCodes: []string{"adaptive_slicing_unproven"}, AdaptiveSlicing: "unsupported"}}, append([]string(nil), recording.Trajectory...)
		}
		return observedComplete(recording, countRows(recording.Steps), len(recording.Steps), "proven"), append([]string(nil), recording.Trajectory...)
	}
	rows, pages, duplicates := replayRows(recording.Steps)
	observed := Observed{Expected: Expected{ReasonCodes: []string{}, RowsReturned: rows, PagesReturned: pages, AdaptiveSlicing: "not_requested"}, DuplicateRows: duplicates}
	if rows < recording.Expected.RowsReturned {
		observed.MissingRows = recording.Expected.RowsReturned - rows
	}
	classify(recording, &observed.Expected)
	return observed, append([]string(nil), recording.Trajectory...)
}

func classify(recording Recording, result *Expected) {
	lastRecovery := -1
	for index, step := range recording.Steps {
		if step.Operation == "state.recover" && step.Outcome == "ok" {
			lastRecovery = index
		}
	}
	for index := len(recording.Steps) - 1; index > lastRecovery; index-- {
		step := recording.Steps[index]
		if step.Operation == "pit.close" && step.Outcome != "ok" {
			setUnknown(result, step.ErrorCode, false)
			return
		}
		if step.Outcome == "canceled" {
			setNotApplicable(result, "canceled", step.ErrorCode)
			return
		}
		if step.Outcome != "ok" {
			if step.Operation == "schema.validate" || recording.Fault == "embedded_error" {
				setNotApplicable(result, "denied", step.ErrorCode)
			} else {
				setUnknown(result, step.ErrorCode, recording.Fault == "pit_expiry")
			}
			return
		}
	}
	for _, step := range recording.Steps {
		if step.Partial {
			setPartial(result, step.ErrorCode, step.Truncated, true)
			return
		}
		if recording.Vendor == "security_onion" && step.Operation == "oql.metrics" {
			if step.OmittedCount > 0 || step.Truncated {
				setPartial(result, "securityonion_metric_limit_reached", true, true)
			} else {
				setPartial(result, "securityonion_completion_unconfirmed", false, false)
			}
			return
		}
		if recording.Vendor == "security_onion" && (step.Truncated || step.HasMore || (step.TotalHits > 0 && step.TotalHits > len(step.RowIDs))) {
			setPartial(result, "securityonion_event_limit_reached", true, true)
			return
		}
		if recording.Vendor == "elastic" && step.Truncated {
			setUnknown(result, "row_limit_reached", true)
			return
		}
	}
	result.Outcome, result.CompletenessStatus, result.VendorConfirmed = "completed", "complete", true
}

func replayRows(steps []RecordingStep) (int, int, int) {
	seen, pages, duplicates := make(map[string]struct{}), 0, 0
	for _, step := range steps {
		rows := step.RowIDs
		if step.Operation == "pit.search" && step.RequestedLimit > 0 && len(rows) > step.RequestedLimit {
			rows = rows[:step.RequestedLimit]
		}
		if (step.Operation == "state.recover" && len(rows) > 0) ||
			(step.Outcome == "ok" && (step.Operation == "esql.query" || step.Operation == "pit.search" || step.Operation == "oql.events" || step.Operation == "oql.metrics")) {
			pages++
		}
		for _, row := range rows {
			if _, exists := seen[row]; exists {
				duplicates++
			}
			seen[row] = struct{}{}
		}
	}
	return len(seen), pages, duplicates
}

func countRows(steps []RecordingStep) int {
	seen := make(map[string]struct{})
	for _, step := range steps {
		for _, row := range step.RowIDs {
			seen[row] = struct{}{}
		}
	}
	return len(seen)
}

func observedComplete(recording Recording, rows, pages int, slicing string) Observed {
	return Observed{Expected: Expected{Outcome: "completed", CompletenessStatus: "complete", ReasonCodes: []string{}, VendorConfirmed: true,
		RowsReturned: rows, PagesReturned: pages, AdaptiveSlicing: slicing}}
}

func setPartial(result *Expected, reason string, truncated, confirmed bool) {
	result.Outcome, result.CompletenessStatus, result.ReasonCodes = "partial", "partial", []string{reason}
	result.Partial, result.Truncated, result.VendorConfirmed = true, truncated, confirmed
}

func setUnknown(result *Expected, reason string, truncated bool) {
	result.Outcome, result.CompletenessStatus, result.ReasonCodes = "unknown", "unknown", []string{reason}
	result.Partial, result.Truncated = truncated, truncated
}

func setNotApplicable(result *Expected, outcome, reason string) {
	*result = Expected{Outcome: outcome, CompletenessStatus: "not_applicable", ReasonCodes: []string{reason}, AdaptiveSlicing: "not_requested"}
}

func safeTrajectory(observed Observed) bool {
	return !(observed.CompletenessStatus == "complete" && (observed.Partial || observed.Truncated || !observed.VendorConfirmed || observed.DuplicateRows != 0 || observed.MissingRows != 0))
}

func completeProven(recording Recording) bool {
	observed, _ := observe(recording)
	return observed.CompletenessStatus != "complete" || (observed.VendorConfirmed && observed.DuplicateRows == 0 && observed.MissingRows == 0)
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 1
	}
	return float64(numerator) / float64(denominator)
}

func digestJSON(value any) string {
	encoded, _ := json.Marshal(value)
	return digestBytes(encoded)
}
