// coh-agent executes one bounded, validator-guided production agent run.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/agentphase"
)

const version = "0.1.0"

type options struct {
	model        string
	modelDigest  string
	workspace    string
	contractPath string
	timeout      time.Duration
}

type resultEnvelope struct {
	SchemaVersion          string                  `json:"schema_version"`
	HarnessVersion         string                  `json:"harness_version"`
	Model                  string                  `json:"model"`
	ModelDigest            string                  `json:"model_digest"`
	TaskContractDigest     string                  `json:"task_contract_digest"`
	ExecutionProfileDigest string                  `json:"execution_profile_digest"`
	Result                 agentphase.RepairResult `json:"result"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	flags := flag.NewFlagSet("coh-agent", flag.ContinueOnError)
	showVersion := flags.Bool("version", false, "print version")
	option := options{}
	flags.StringVar(&option.model, "model", "", "exact installed Ollama model tag")
	flags.StringVar(&option.modelDigest, "model-digest", "", "exact sha256 Ollama model digest")
	flags.StringVar(&option.workspace, "workspace", "", "absolute isolated workspace")
	flags.StringVar(&option.contractPath, "task-contract", "", "task contract JSON")
	flags.DurationVar(&option.timeout, "timeout", 2*time.Hour, "run deadline")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	if option.model == "" || option.modelDigest == "" || option.workspace == "" || option.contractPath == "" ||
		option.timeout < time.Second || option.timeout > 4*time.Hour || flags.NArg() != 0 {
		return errors.New("model, model-digest, workspace, task-contract, and a timeout up to four hours are required")
	}
	workspace, err := filepath.Abs(option.workspace)
	if err != nil || filepath.Clean(workspace) != workspace {
		return errors.New("workspace must resolve to an absolute clean path")
	}
	contract, err := loadContract(option.contractPath)
	if err != nil {
		return err
	}
	if contract.Workspace != workspace {
		return errors.New("task contract workspace does not match the command boundary")
	}
	ctx, cancel := context.WithTimeout(context.Background(), option.timeout)
	defer cancel()
	generator, profile, err := newOllamaGenerator(ctx, option.model, option.modelDigest, workspace, option.timeout)
	if err != nil {
		return err
	}
	validator, err := agentphase.NewValidatorRegistry().Resolve(contract.ValidatorProfile)
	if err != nil {
		return err
	}
	controller, err := agentphase.NewRepairController(generator, validator)
	if err != nil {
		return err
	}
	result, err := controller.Run(ctx, contract, profile)
	if err != nil {
		return err
	}
	envelope := resultEnvelope{SchemaVersion: "coh.agent-result/v1", HarnessVersion: version,
		Model: option.model, ModelDigest: option.modelDigest, TaskContractDigest: contract.Digest(),
		ExecutionProfileDigest: profile.Digest(), Result: result}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(envelope)
}

func loadContract(path string) (agentphase.TaskContract, error) {
	stream, err := os.Open(path)
	if err != nil {
		return agentphase.TaskContract{}, err
	}
	defer stream.Close()
	decoder := json.NewDecoder(stream)
	decoder.DisallowUnknownFields()
	value := agentphase.TaskContract{}
	if err = decoder.Decode(&value); err != nil {
		return agentphase.TaskContract{}, fmt.Errorf("decode task contract: %w", err)
	}
	var trailing any
	if trailingErr := decoder.Decode(&trailing); trailingErr != io.EOF {
		return agentphase.TaskContract{}, errors.New("task contract contains trailing or invalid data")
	}
	if err = value.Validate(); err != nil {
		return agentphase.TaskContract{}, err
	}
	return value, nil
}
