package replayeval

func Run(suite Suite) RunResult {
	traces := make([]Trace, 0, len(suite.Corpus.Tasks)*suite.Corpus.TrialsPerTask)
	metrics := Metrics{TaskCount: len(suite.Corpus.Tasks)}
	reconciliationTotal, reconciliationPassed, replayPassed := 0, 0, 0
	outcomePassed, trajectoryPassed := 0, 0
	for _, task := range suite.Corpus.Tasks {
		for trial := 1; trial <= suite.Corpus.TrialsPerTask; trial++ {
			observed, events, _ := simulate(task.Mode)
			outcomeGrade := gradeOutcome(task.Expected, observed)
			trajectoryGrade := gradeTrajectory(observed, events)
			trace := Trace{SchemaVersion: "coh.replay-fault-trace/v1", CorpusVersion: suite.Corpus.CorpusVersion,
				TaskID: task.ID, Trial: trial, Boundary: task.Boundary, Fault: task.Fault,
				Events: append([]string(nil), events...), Observed: observed, OutcomeGrade: outcomeGrade, TrajectoryGrade: trajectoryGrade}
			traces = append(traces, trace)
			metrics.TrialCount++
			if observed.ConfirmedEffects > 1 {
				metrics.DuplicateConfirmedEffects += observed.ConfirmedEffects - 1
			}
			if observed.State == "verified" && observed.Dispatches > 0 && observed.ConfirmedEffects != 1 {
				metrics.FalseSuccesses++
			}
			if task.Expected.RequiresReconciliation {
				reconciliationTotal++
				if observed.RequiresReconciliation {
					reconciliationPassed++
				}
			}
			if observed.Replayed {
				replayPassed++
			}
			if outcomeGrade {
				outcomePassed++
			}
			if trajectoryGrade {
				trajectoryPassed++
			}
		}
	}
	metrics.ReconciliationRate = ratio(reconciliationPassed, reconciliationTotal)
	metrics.ReplayRate = ratio(replayPassed, metrics.TrialCount)
	metrics.OutcomeGradeRate = ratio(outcomePassed, metrics.TrialCount)
	metrics.TrajectoryGradeRate = ratio(trajectoryPassed, metrics.TrialCount)
	outcome := "passed"
	thresholds := suite.Corpus.Thresholds
	if metrics.DuplicateConfirmedEffects > thresholds.MaximumDuplicateConfirmedEffects || metrics.FalseSuccesses > thresholds.MaximumFalseSuccesses ||
		metrics.ReconciliationRate < thresholds.MinimumReconciliationRate || metrics.ReplayRate < thresholds.MinimumReplayRate ||
		metrics.OutcomeGradeRate < thresholds.MinimumOutcomeGradeRate || metrics.TrajectoryGradeRate < thresholds.MinimumTrajectoryGradeRate {
		outcome = "denied"
	}
	graders := GraderReport{SchemaVersion: "coh.replay-fault-graders/v1", CorpusVersion: suite.Corpus.CorpusVersion,
		CorpusDigest: suite.CorpusDigest, EnvironmentDigest: suite.EnvironmentDigest, Metrics: metrics}
	return RunResult{Traces: traces, Graders: graders, Threshold: ThresholdResult{
		SchemaVersion: "coh.replay-fault-threshold/v1", Thresholds: thresholds, Metrics: metrics, Outcome: outcome,
	}}
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 1
	}
	return float64(numerator) / float64(denominator)
}
