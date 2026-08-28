package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ArronJablonowski/COH/internal/workflow/sentinelsliceeval"
)

func main() {
	output := flag.String("output", "", "absolute artifact output directory")
	flag.Parse()
	if *output == "" || flag.NArg() != 0 {
		fatal("usage: sentinelsliceeval --output /absolute/path")
	}
	root, err := os.Getwd()
	if err != nil {
		fatal(err.Error())
	}
	root, err = filepath.Abs(root)
	if err != nil {
		fatal(err.Error())
	}
	suite, err := sentinelsliceeval.Load(root,
		filepath.Join(root, "contracts/evaluation/sentinel-slicing/v1/sentinel-slicing-corpus.json"),
		filepath.Join(root, "contracts/evaluation/sentinel-slicing/v1/sentinel-slicing-environment.json"))
	if err != nil {
		fatal(err.Error())
	}
	if err := sentinelsliceeval.ValidateRuntime(suite.Environment); err != nil {
		fatal(err.Error())
	}
	result := sentinelsliceeval.Run(suite)
	if !result.Threshold.Passed {
		fatal("evaluation threshold denied")
	}
	if err := sentinelsliceeval.WriteArtifacts(*output, suite, result); err != nil {
		fatal(err.Error())
	}
	if err := sentinelsliceeval.VerifyArtifacts(*output); err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
