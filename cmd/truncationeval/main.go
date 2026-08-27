package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArronJablonowski/COH/internal/workflow/truncationeval"
)

func main() {
	output := flag.String("output", "", "absolute artifact output directory")
	flag.Parse()
	if flag.NArg() != 0 || *output == "" {
		fatal("usage: truncationeval --output /absolute/path")
	}
	root, err := os.Getwd()
	if err != nil {
		fatal(err.Error())
	}
	root, err = filepath.Abs(root)
	if err != nil {
		fatal(err.Error())
	}
	suite, err := truncationeval.Load(root,
		filepath.Join(root, "contracts/evaluation/truncation/v1/connector-truncation-corpus.json"),
		filepath.Join(root, "contracts/evaluation/truncation/v1/connector-truncation-environment.json"))
	if err != nil {
		fatal(err.Error())
	}
	if err := truncationeval.ValidateRuntime(suite.Environment); err != nil {
		fatal(err.Error())
	}
	result := truncationeval.Run(suite)
	if err := truncationeval.WriteArtifacts(*output, suite, result); err != nil {
		fatal(err.Error())
	}
	if err := truncationeval.VerifyArtifacts(*output); err != nil {
		fatal(err.Error())
	}
	if result.Threshold.Outcome != "passed" {
		fatal("connector truncation threshold denied")
	}
	fmt.Printf("connector truncation evaluation passed: tasks=%d trials=%d corpus=%s environment=%s output=%s\n",
		result.Graders.Metrics.TaskCount, result.Graders.Metrics.TrialCount, suite.CorpusDigest, suite.EnvironmentDigest, *output)
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
