// Command qualitygate runs the provider-neutral COH CI quality contract.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/quality"
)

const (
	defaultPolicy   = "ci/quality-policy.json"
	defaultToolLock = "ci/tools.lock.json"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("qualitygate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	mode := flags.String("mode", "run", "operation: run, file-size, sbom, provenance, digest, or tool verification")
	root := flags.String("root", ".", "repository root")
	policyPath := flags.String("policy", defaultPolicy, "quality policy path")
	toolLockPath := flags.String("tool-lock", defaultToolLock, "tool lock path")
	vulnLockPath := flags.String("vulndb-lock", "ci/govulndb.lock.json", "vulnerability database lock")
	lane := flags.String("lane", "baseline", "quality lane")
	artifactDirectory := flags.String("artifact-dir", "", "fresh external artifact directory")
	output := flags.String("output", "", "atomic output path")
	input := flags.String("input", "", "bounded input path for digest mode")
	toolBin := flags.String("tool-bin", "", "private tool directory for verification")
	vulnDB := flags.String("vulndb", "", "canonical local vulnerability database URL")
	manifest := flags.String("manifest", "", "vulnerability database manifest")
	manifestSHA := flags.String("manifest-sha256", "", "locked raw manifest digest")
	fuzzTarget := flags.String("fuzz-target", "", "fuzz target for execution-trace verification")
	timeout := flags.Duration("timeout", 30*time.Minute, "overall deadline")
	if err := flags.Parse(arguments); err != nil {
		return 64
	}
	if flags.NArg() != 0 || *timeout <= 0 || !supportedMode(*mode) {
		fmt.Fprintln(stderr, "invalid arguments: use -h for supported flags")
		return 64
	}
	rootPath, err := filepath.Abs(*root)
	if err != nil {
		printError(stderr, qualityInputError("root", err))
		return 64
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, *timeout)
	defer cancel()

	switch *mode {
	case "file-size":
		return runFileSizeMode(ctx, rootPath, *artifactDirectory, *input, *output, stdout, stderr)
	case "extract-vulndb", "generate-vulndb-manifest", "verify-vulndb", "verify-govuln-sarif":
		lock, lockErr := readVulnDBLock(rootPath, *vulnLockPath)
		if lockErr != nil {
			printError(stderr, lockErr)
			return exitCode(lockErr)
		}
		var operationErr error
		switch *mode {
		case "extract-vulndb":
			if err := validateOutput(rootPath, "", filepath.Join(*output, ".extract-target"), ".extract-target", true); err != nil {
				operationErr = err
			} else {
				operationErr = quality.ExtractVulnDBArchive(*input, *output, lock)
			}
		case "generate-vulndb-manifest":
			if err := validateOutput(rootPath, "", *output, "govulndb-manifest.json", false); err != nil {
				operationErr = err
			} else {
				operationErr = quality.GenerateVulnDBManifest(*vulnDB, *output, lock)
			}
		case "verify-vulndb":
			if err := validateOutput(rootPath, *artifactDirectory, *output, "govulndb-verification.json", false); err != nil {
				operationErr = err
			} else if verification, err := quality.VerifyVulnDB(*vulnDB, *manifest, *manifestSHA, lock); err != nil {
				operationErr = err
			} else {
				operationErr = quality.WriteVulnDBVerification(*output, verification)
			}
		case "verify-govuln-sarif":
			operationErr = quality.VerifyGovulnSARIF(*input, *vulnDB, lock.DatabaseModified)
		}
		if operationErr != nil {
			printError(stderr, operationErr)
			return exitCode(operationErr)
		}
		fmt.Fprintln(stdout, *mode+": passed")
		return 0
	case "verify-tools", "verify-tool-sources":
		lockData, err := readBounded(filepath.Join(rootPath, *toolLockPath))
		if err != nil {
			printError(stderr, err)
			return exitCode(err)
		}
		lock, _, err := quality.DecodeToolLock(lockData)
		if err == nil {
			_, err = quality.SelectLane(mustReadPolicy(rootPath, *policyPath), *lane)
		}
		if err == nil && *mode == "verify-tools" {
			err = quality.VerifyTools(lock, *toolBin, *lane)
		}
		if err == nil && *mode == "verify-tool-sources" {
			err = quality.VerifyToolSources(ctx, lock, os.Getenv("COH_GO_BIN"), *lane)
		}
		if err != nil {
			printError(stderr, err)
			return exitCode(err)
		}
		fmt.Fprintln(stdout, *mode+": passed")
		return 0
	case "verify-fuzz-manifest":
		targets, verifyErr := quality.VerifyFuzzManifest(ctx, rootPath, *input)
		if verifyErr != nil {
			printError(stderr, verifyErr)
			return exitCode(verifyErr)
		}
		for _, target := range targets {
			if _, writeErr := fmt.Fprintf(stdout, "%s %s\n", target.Package, target.Name); writeErr != nil {
				return 1
			}
		}
		return 0
	case "verify-fuzz-execution":
		seedCount, verifyErr := quality.VerifyFuzzExecution(ctx, *input, *fuzzTarget)
		if verifyErr != nil {
			printError(stderr, verifyErr)
			return exitCode(verifyErr)
		}
		fmt.Fprintf(stdout, "verify-fuzz-execution: target=%s seeds=%d passed\n", *fuzzTarget, seedCount)
		return 0
	case "verify-publication":
		if *artifactDirectory == "" {
			fmt.Fprintln(stderr, "verify-publication requires -artifact-dir")
			return 64
		}
		directory, absoluteErr := filepath.Abs(*artifactDirectory)
		if absoluteErr != nil {
			printError(stderr, qualityInputError("artifact_dir", absoluteErr))
			return 64
		}
		if verifyErr := quality.VerifyPublicationManifest(directory, filepath.Join(directory, "publication-manifest.json")); verifyErr != nil {
			printError(stderr, verifyErr)
			return exitCode(verifyErr)
		}
		fmt.Fprintln(stdout, "verify-publication: passed")
		return 0
	case "digest":
		digest, err := quality.DigestFile(*input)
		if err != nil {
			printError(stderr, err)
			return exitCode(err)
		}
		if _, err := fmt.Fprintln(stdout, digest); err != nil {
			return 1
		}
		return 0
	case "sbom":
		if err := validateOutput(rootPath, "", *output, "coh.cdx.json", false); err != nil {
			printError(stderr, err)
			return exitCode(err)
		}
		if err := quality.GenerateSBOM(ctx, rootPath, *output); err != nil {
			printError(stderr, err)
			return exitCode(err)
		}
		return 0
	case "provenance":
		if err := validateOutput(rootPath, *artifactDirectory, *output, "ci-provenance.json", false); err != nil {
			printError(stderr, err)
			return exitCode(err)
		}
		if err := quality.GenerateProvenance(ctx, rootPath, *artifactDirectory, *output); err != nil {
			printError(stderr, err)
			return exitCode(err)
		}
		return 0
	}

	if *artifactDirectory == "" || *output == "" {
		fmt.Fprintln(stderr, "run mode requires -artifact-dir and -output")
		return 64
	}
	if err := validateOutput(rootPath, *artifactDirectory, *output, "quality-report.json", true); err != nil {
		printError(stderr, err)
		return exitCode(err)
	}
	policyData, err := readBounded(filepath.Join(rootPath, *policyPath))
	if err != nil {
		printError(stderr, err)
		return exitCode(err)
	}
	policy, err := quality.DecodePolicy(policyData)
	if err != nil {
		printError(stderr, err)
		return exitCode(err)
	}
	lockData, err := readBounded(filepath.Join(rootPath, *toolLockPath))
	if err != nil {
		printError(stderr, err)
		return exitCode(err)
	}
	lock, lockDigest, err := quality.DecodeToolLock(lockData)
	if err != nil {
		printError(stderr, err)
		return exitCode(err)
	}
	if _, err := quality.SelectLane(policy, *lane); err != nil {
		printError(stderr, err)
		return exitCode(err)
	}
	if err := quality.VerifyTools(lock, os.Getenv("GOBIN"), *lane); err != nil {
		printError(stderr, err)
		return exitCode(err)
	}
	report, runErr := (quality.Runner{Executor: quality.LocalExecutor{}}).Run(
		ctx, policy, *lane, rootPath, *artifactDirectory, lockDigest,
	)
	if report.SchemaVersion == "" {
		printError(stderr, runErr)
		return exitCode(runErr)
	}
	finalizeErr := finalizeRunEvidence(ctx, rootPath, *artifactDirectory, *output, &report, runErr)
	if _, statErr := os.Lstat(*output); statErr == nil {
		if _, writeErr := fmt.Fprintf(stdout, "%s\n", *output); writeErr != nil {
			printError(stderr, writeErr)
			return 1
		}
	}
	if finalizeErr != nil {
		printError(stderr, finalizeErr)
		printGitHubStageFailure(stderr, report)
		return exitCode(finalizeErr)
	}
	return 0
}

func supportedMode(mode string) bool {
	switch mode {
	case "run", "file-size", "sbom", "provenance", "digest", "verify-tools", "verify-tool-sources", "verify-fuzz-manifest", "verify-fuzz-execution", "verify-publication",
		"extract-vulndb", "generate-vulndb-manifest", "verify-vulndb", "verify-govuln-sarif":
		return true
	default:
		return false
	}
}

func readVulnDBLock(root, relative string) (quality.VulnDBLock, error) {
	data, err := readBounded(filepath.Join(root, relative))
	if err != nil {
		return quality.VulnDBLock{}, err
	}
	return quality.DecodeVulnDBLock(data)
}

func mustReadPolicy(root, relative string) quality.Policy {
	data, err := readBounded(filepath.Join(root, relative))
	if err != nil {
		return quality.Policy{}
	}
	policy, _ := quality.DecodePolicy(data)
	return policy
}

func validateOutput(root, artifactDirectory, output, expectedName string, requireFresh bool) error {
	if output == "" {
		return qualityInputError("output", errors.New("output is required"))
	}
	outputPath, err := filepath.Abs(output)
	if err != nil {
		return qualityInputError("output", err)
	}
	if filepath.Base(outputPath) != expectedName {
		return &quality.Error{Code: quality.CodeDenied, Field: "output", Detail: "output name is reserved by mode"}
	}
	if _, err := os.Lstat(outputPath); !errors.Is(err, os.ErrNotExist) {
		return &quality.Error{Code: quality.CodeDenied, Field: "output", Detail: "output must not already exist", Cause: err}
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return qualityInputError("root", err)
	}
	directory := filepath.Dir(outputPath)
	if artifactDirectory != "" {
		directory, err = filepath.Abs(artifactDirectory)
		if err != nil {
			return qualityInputError("artifact_dir", err)
		}
		if filepath.Dir(outputPath) != directory {
			return &quality.Error{Code: quality.CodeDenied, Field: "output", Detail: "output must be directly inside the artifact directory"}
		}
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return &quality.Error{Code: quality.CodeDenied, Field: "artifact_dir", Detail: "artifact directory must be a real directory", Cause: err}
	}
	realDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return qualityInputError("artifact_dir", err)
	}
	rootPrefix := realRoot + string(filepath.Separator)
	if realDirectory == realRoot || strings.HasPrefix(realDirectory, rootPrefix) {
		return &quality.Error{Code: quality.CodeDenied, Field: "output", Detail: "CI artifacts must remain outside the repository"}
	}
	if requireFresh {
		entries, err := os.ReadDir(realDirectory)
		if err != nil || len(entries) != 0 {
			return &quality.Error{Code: quality.CodeDenied, Field: "artifact_dir", Detail: "run artifact directory must be fresh and empty", Cause: err}
		}
	}
	return nil
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, qualityInputError("input", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, quality.MaximumPolicySize+1))
	if err != nil || len(data) > quality.MaximumPolicySize {
		return nil, qualityInputError("input", errors.New("input cannot be read within limit"))
	}
	return data, nil
}

func qualityInputError(field string, cause error) error {
	return &quality.Error{Code: quality.CodeInvalidInput, Field: field, Detail: "invalid input", Cause: cause}
}

func printError(writer io.Writer, err error) {
	var qualityErr *quality.Error
	if errors.As(err, &qualityErr) {
		fmt.Fprintf(writer, "qualitygate: %s\n", qualityErr.Error())
		printGitHubError(writer, string(qualityErr.Code), qualityErr.Field)
		return
	}
	fmt.Fprintln(writer, "qualitygate: internal failure")
	printGitHubError(writer, string(quality.CodeToolFailure), "unknown")
}

func printGitHubError(writer io.Writer, code, field string) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		return
	}
	fmt.Fprintf(writer, "::error file=cmd/qualitygate/main.go,title=COH quality gate failure::code=%s field=%s\n",
		annotationToken(code, "tool_failure"), annotationToken(field, "redacted"))
}

func annotationToken(value, fallback string) string {
	if value == "" || len(value) > 128 {
		return fallback
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return fallback
		}
	}
	return value
}

func printGitHubStageFailure(writer io.Writer, report quality.Report) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || len(report.Stages) == 0 {
		return
	}
	stage := report.Stages[len(report.Stages)-1]
	if stage.FailureEvidence == nil {
		return
	}
	fmt.Fprintf(writer, "::error file=cmd/qualitygate/main.go,title=COH failed stage evidence::stage=%s exit_code=%d\n",
		annotationToken(stage.ID, "redacted"), stage.FailureEvidence.ExitCode)
}

func exitCode(err error) int {
	switch quality.CodeOf(err) {
	case quality.CodeInvalidInput:
		return 64
	case quality.CodeDenied:
		return 2
	case quality.CodeTimeout:
		return 124
	case quality.CodeCanceled:
		return 130
	default:
		return 1
	}
}
