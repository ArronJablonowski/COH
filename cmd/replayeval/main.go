package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArronJablonowski/COH/internal/workflow/replayeval"
)

func main() {
	root := flag.String("root", "", "absolute repository root")
	output := flag.String("output", "", "absolute artifact directory")
	flag.Parse()
	if flag.NArg() != 0 || *root == "" || !filepath.IsAbs(*root) || filepath.Clean(*root) != *root {
		fmt.Fprintln(os.Stderr, "replayeval: absolute clean -root and -output are required")
		os.Exit(64)
	}
	suite, err := replayeval.Load(
		filepath.Join(*root, "contracts/evaluation/v1/replay-fault-corpus.json"),
		filepath.Join(*root, "contracts/evaluation/v1/replay-environment.json"),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "replayeval: contract denied:", err)
		os.Exit(2)
	}
	if err := replayeval.ValidateRuntime(suite.Environment); err != nil {
		fmt.Fprintln(os.Stderr, "replayeval: environment denied:", err)
		os.Exit(2)
	}
	result := replayeval.Run(suite)
	if err := replayeval.WriteArtifacts(*output, suite, result); err != nil {
		fmt.Fprintln(os.Stderr, "replayeval: artifact failure:", err)
		os.Exit(1)
	}
	if result.Threshold.Outcome != "passed" {
		fmt.Fprintln(os.Stderr, "replayeval: release thresholds denied")
		os.Exit(2)
	}
	fmt.Printf("replay-eval summary: tasks=%d trials=%d duplicate_confirmed=%d false_success=%d reconciliation=%.2f replay=%.2f outcome_grade=%.2f trajectory_grade=%.2f outcome=%s\n",
		result.Graders.Metrics.TaskCount, result.Graders.Metrics.TrialCount,
		result.Graders.Metrics.DuplicateConfirmedEffects, result.Graders.Metrics.FalseSuccesses,
		result.Graders.Metrics.ReconciliationRate, result.Graders.Metrics.ReplayRate,
		result.Graders.Metrics.OutcomeGradeRate, result.Graders.Metrics.TrajectoryGradeRate,
		result.Threshold.Outcome)
}
