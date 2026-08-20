// Command archcheck validates the COH Go workspace dependency graph.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/architecture"
)

const defaultContract = "contracts/architecture/v1/workspace-contract.json"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("archcheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	contractPath := flags.String("contract", defaultContract, "workspace contract path")
	root := flags.String("root", ".", "Go workspace root")
	goBinary := flags.String("go", "go", "Go executable")
	format := flags.String("format", "text", "report format: text or json")
	mode := flags.String("mode", "check", "operation: check or canonical")
	buildTagsRaw := flags.String("tags", "", "comma-separated Go build tags")
	timeout := flags.Duration("timeout", 60*time.Second, "architecture check deadline")
	if err := flags.Parse(arguments); err != nil {
		return 64
	}
	if flags.NArg() != 0 || (*format != "text" && *format != "json") || (*mode != "check" && *mode != "canonical") || *timeout <= 0 {
		fmt.Fprintln(stderr, "invalid arguments: use -h for supported flags")
		return 64
	}

	contractData, err := readBounded(*contractPath)
	if err != nil {
		printError(stderr, err)
		return 1
	}
	contract, err := architecture.DecodeContract(contractData)
	if err != nil {
		printError(stderr, err)
		return 1
	}
	buildTags, err := architecture.ParseBuildTags(*buildTagsRaw)
	if err != nil {
		printError(stderr, err)
		return 1
	}
	if *mode == "canonical" {
		canonical, canonicalErr := architecture.CanonicalBytes(contract)
		if canonicalErr != nil {
			printError(stderr, canonicalErr)
			return 1
		}
		if _, err := stdout.Write(canonical); err != nil {
			printError(stderr, &architecture.ContractError{
				Code: architecture.CodeToolFailure, Field: "output", Detail: "cannot write canonical contract", Cause: err,
			})
			return 1
		}
		return 0
	}

	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, *timeout)
	defer cancel()
	provenance := architecture.RuntimeProvenance(buildTags)
	architecture.AddVCSProvenance(ctx, *root, &provenance)
	baseReport, err := architecture.NewReport(contract, provenance)
	if err != nil {
		printError(stderr, err)
		return 1
	}
	if err := architecture.ValidateWorkspaceLayout(ctx, *root); err != nil {
		return emitFailure(stdout, stderr, *format, baseReport, err)
	}
	manifests, err := architecture.ValidateWorkspaceManifests(ctx, *root)
	if err != nil {
		return emitFailure(stdout, stderr, *format, baseReport, err)
	}
	scanned, err := architecture.ScanSourcePackages(ctx, *root, contract.Module)
	if err != nil {
		return emitFailure(stdout, stderr, *format, baseReport, err)
	}
	listed, err := architecture.ListPackages(ctx, *goBinary, *root, buildTags)
	if err != nil {
		return emitFailure(stdout, stderr, *format, baseReport, err)
	}
	packages := architecture.MergePackages(listed, scanned)
	provenance.SourceDigest, provenance.SourceFileCount, err = architecture.DigestSources(
		ctx, packages, architecture.WorkspaceSnapshot{},
	)
	if err != nil {
		return emitFailure(stdout, stderr, *format, baseReport, err)
	}
	provenance.InputDigest, provenance.InputFileCount, err = architecture.DigestSources(ctx, packages, manifests)
	if err != nil {
		return emitFailure(stdout, stderr, *format, baseReport, err)
	}
	report, checkErr := architecture.Evaluate(ctx, contract, packages, provenance)
	if verifyErr := architecture.VerifyWorkspaceSnapshot(ctx, *root, contract.Module, packages, manifests); verifyErr != nil {
		return emitFailure(stdout, stderr, *format, report, verifyErr)
	}
	if layoutErr := architecture.ValidateWorkspaceLayout(ctx, *root); layoutErr != nil {
		return emitFailure(stdout, stderr, *format, report, layoutErr)
	}
	if err := writeReport(stdout, *format, report); err != nil {
		printError(stderr, err)
		return 1
	}
	if checkErr != nil {
		printError(stderr, checkErr)
		return exitCode(checkErr)
	}
	return 0
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, &architecture.ContractError{Code: architecture.CodeInvalidInput, Field: "contract", Detail: "cannot open contract", Cause: err}
	}
	defer file.Close()
	reader := io.LimitReader(file, architecture.MaximumContractSize+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, &architecture.ContractError{Code: architecture.CodeInvalidInput, Field: "contract", Detail: "cannot read contract", Cause: err}
	}
	if len(data) > architecture.MaximumContractSize {
		return nil, &architecture.ContractError{Code: architecture.CodeInvalidInput, Field: "contract", Detail: "contract exceeds 1 MiB"}
	}
	return data, nil
}

func writeReport(writer io.Writer, format string, report architecture.Report) error {
	if format == "json" {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	}
	_, err := fmt.Fprintf(writer, "architecture %s: %d packages, %d violations, contract sha256:%s\n",
		report.Outcome, report.PackageCount, report.ViolationCount, report.ContractDigest)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "provenance graph sha256:%s source sha256:%s input sha256:%s vcs:%s modified:%t go:%s target:%s/%s tags:%v\n",
		report.GraphDigest, report.Provenance.SourceDigest, report.Provenance.InputDigest, report.Provenance.VCSRevision,
		report.Provenance.VCSModified, report.Provenance.GoVersion, report.Provenance.GOOS,
		report.Provenance.GOARCH, report.Provenance.BuildTags); err != nil {
		return err
	}
	for _, violation := range report.Violations {
		if _, err := fmt.Fprintf(writer, "%s %s (%s) -> %s (%s): %s\n",
			violation.Rule, violation.Package, violation.Boundary,
			violation.Import, violation.ImportBoundary, violation.Detail); err != nil {
			return err
		}
	}
	return nil
}

func emitFailure(stdout, stderr io.Writer, format string, report architecture.Report, err error) int {
	report.FailureCode = errorCode(err)
	switch report.FailureCode {
	case architecture.CodeCanceled:
		report.Outcome = "canceled"
	case architecture.CodeDenied:
		report.Outcome = "denied"
	default:
		report.Outcome = "error"
	}
	if writeErr := writeReport(stdout, format, report); writeErr != nil {
		printError(stderr, &architecture.ContractError{
			Code: architecture.CodeToolFailure, Field: "output", Detail: "cannot write failure report", Cause: writeErr,
		})
		return 1
	}
	printError(stderr, err)
	return exitCode(err)
}

func errorCode(err error) architecture.ErrorCode {
	var contractErr *architecture.ContractError
	if errors.As(err, &contractErr) {
		return contractErr.Code
	}
	return architecture.CodeToolFailure
}

func printError(writer io.Writer, err error) {
	var contractErr *architecture.ContractError
	if errors.As(err, &contractErr) {
		fmt.Fprintf(writer, "archcheck: %s\n", contractErr.Error())
		return
	}
	fmt.Fprintln(writer, "archcheck: internal failure")
}

func exitCode(err error) int {
	var contractErr *architecture.ContractError
	if errors.As(err, &contractErr) {
		switch contractErr.Code {
		case architecture.CodeDenied:
			return 2
		case architecture.CodeCanceled:
			return 130
		}
	}
	return 1
}
