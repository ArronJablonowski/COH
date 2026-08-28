package sentinelsliceeval

import (
	"encoding/json"
	"reflect"
)

func Run(suite Suite) RunResult {
	traces := make([]Trace, 0, len(suite.Corpus.Tasks)*suite.Corpus.TrialsPerTask)
	metrics := Metrics{TaskCount: len(suite.Corpus.Tasks)}
	coveredBoundaries := make(map[string]struct{})
	outcomePassed, trajectoryPassed, replayPassed := 0, 0, 0
	for _, task := range suite.Corpus.Tasks {
		coveredBoundaries[task.Boundary] = struct{}{}
		baseline := ""
		for trial := 1; trial <= suite.Corpus.TrialsPerTask; trial++ {
			observed, events, completeProof := observe(suite.Recordings[task.RecordingID])
			outcomeGrade := reflect.DeepEqual(observed, task.Expected)
			trajectoryGrade := reflect.DeepEqual(events, task.Trajectory) && safeTrajectory(observed, completeProof)
			replayDigest := digestJSON(struct {
				Task, Recording string
				Observed        Expected
				Events          []string
			}{taskDigest(task), recordingDigest(suite.Recordings[task.RecordingID]), observed, events})
			if baseline == "" {
				baseline = replayDigest
			}
			if replayDigest == baseline {
				replayPassed++
			}
			if outcomeGrade {
				outcomePassed++
			}
			if trajectoryGrade {
				trajectoryPassed++
			}
			if observed.Completeness == "complete" && !completeProof {
				metrics.FalseComplete++
			}
			if observed.Outcome != "completed" {
				metrics.ReleasedDeniedRows += observed.ReleasedRows
			}
			metrics.TrialCount++
			traces = append(traces, Trace{SchemaVersion: "coh.sentinel-slicing-trace/v1",
				CorpusDigest: suite.CorpusDigest, EnvironmentDigest: suite.EnvironmentDigest,
				TaskDigest: taskDigest(task), TaskID: task.ID, Trial: trial, Events: events,
				Observed: observed, ReplayDigest: replayDigest})
		}
	}
	metrics.OutcomeGradeRate = ratio(outcomePassed, metrics.TrialCount)
	metrics.TrajectoryGradeRate = ratio(trajectoryPassed, metrics.TrialCount)
	metrics.ReplayRate = ratio(replayPassed, metrics.TrialCount)
	metrics.BoundaryCoverageRate = ratio(len(coveredBoundaries), len(boundaries()))
	traceBytes, _ := marshalTraceStream(traces)
	graders := GraderReport{SchemaVersion: "coh.sentinel-slicing-graders/v1", CorpusDigest: suite.CorpusDigest,
		EnvironmentDigest: suite.EnvironmentDigest, TraceStreamDigest: digestBytes(traceBytes), Metrics: metrics}
	threshold := ThresholdResult{SchemaVersion: "coh.sentinel-slicing-threshold/v1", CorpusDigest: suite.CorpusDigest,
		EnvironmentDigest: suite.EnvironmentDigest, Thresholds: suite.Corpus.Thresholds, Metrics: metrics,
		Passed: passes(metrics)}
	return RunResult{Traces: traces, Graders: graders, Threshold: threshold}
}

func observe(recording Recording) (Expected, []string, bool) {
	events := append([]string(nil), recording.Trajectory...)
	if recording.Fault != "none" && recording.Fault != "boundary_duplicate" {
		return failureFor(recording.Fault), events, false
	}
	seen := make(map[string]string)
	for _, step := range recording.Steps {
		if step.Outcome != "ok" || step.Partial || !step.EndExclusive || len(step.RowKeys) != len(step.RowDigests) {
			return failureFor(recording.Fault), events, false
		}
		for index, key := range step.RowKeys {
			if prior, exists := seen[key]; exists && prior != step.RowDigests[index] {
				return Expected{Outcome: "denied", Completeness: "not_applicable",
					ReasonCodes: []string{"sentinel_stable_key_conflict"}}, events, false
			}
			seen[key] = step.RowDigests[index]
		}
	}
	rows := len(seen)
	return Expected{Outcome: "completed", Completeness: "complete", ReasonCodes: []string{},
		RowsReturned: rows, SlicesCompleted: len(recording.Steps), ReleasedRows: rows}, events, true
}

func failureFor(fault string) Expected {
	reasons := map[string]string{
		"missing_timespan":    "sentinel_timespan_required",
		"duplicate_conflict":  "sentinel_stable_key_conflict",
		"timestamp_ambiguity": "sentinel_identical_timestamp_ambiguous",
		"partial_error":       "sentinel_partial_error",
		"cancel":              "sentinel_query_canceled",
		"timeout":             "sentinel_query_timeout",
		"uncertain_retry":     "sentinel_retry_uncertain",
		"tamper":              "sentinel_provenance_mismatch",
		"slice_limit":         "sentinel_slice_limit_exceeded",
	}
	outcomes := map[string]string{"cancel": "canceled", "partial_error": "unknown", "timeout": "unknown", "uncertain_retry": "unknown"}
	outcome := outcomes[fault]
	if outcome == "" {
		outcome = "denied"
	}
	reason := reasons[fault]
	if reason == "" {
		reason = "sentinel_evaluation_unproven"
	}
	return Expected{Outcome: outcome, Completeness: "not_applicable", ReasonCodes: []string{reason}}
}

func safeTrajectory(observed Expected, completeProof bool) bool {
	return observed.ReleasedRows == 0 || observed.Outcome == "completed" && observed.Completeness == "complete" && completeProof
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 1
	}
	return float64(numerator) / float64(denominator)
}

func recordingDigest(recording Recording) string { return digestJSON(recording) }

func digestJSON(value interface{}) string {
	encoded, _ := json.Marshal(value)
	return digestBytes(encoded)
}
