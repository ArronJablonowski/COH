package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ArronJablonowski/COH/internal/helper/filesize"
)

func runFileSizeMode(ctx context.Context, root, artifactDirectory, policyPath, output string, stdout, stderr io.Writer) int {
	if policyPath == "" || artifactDirectory == "" {
		fmt.Fprintln(stderr, "file-size mode requires -input, -artifact-dir, and -output")
		return 64
	}
	if err := validateOutput(root, artifactDirectory, output, "file-size-report.json", false); err != nil {
		printError(stderr, err)
		return exitCode(err)
	}
	policyData, err := readFileSizePolicy(root, policyPath)
	if err != nil {
		printFileSizeError(stderr, err)
		return fileSizeExitCode(err)
	}
	policy, err := filesize.DecodePolicy(policyData)
	if err != nil {
		printFileSizeError(stderr, err)
		return fileSizeExitCode(err)
	}
	report, checkErr := filesize.NewChecker(filesize.OSSource{}).Check(ctx, filesize.Request{Root: root, Policy: policy})
	if report.SchemaVersion != "" {
		if writeErr := filesize.WriteReportAtomic(output, &report); writeErr != nil {
			printFileSizeError(stderr, writeErr)
			return fileSizeExitCode(writeErr)
		}
		if _, writeErr := fmt.Fprintln(stdout, output); writeErr != nil {
			return 1
		}
	}
	if checkErr != nil {
		printFileSizeError(stderr, checkErr)
		return fileSizeExitCode(checkErr)
	}
	return 0
}

func readFileSizePolicy(root, path string) ([]byte, error) {
	return readFileSizePolicyStable(root, path, nil)
}

func readFileSizePolicyStable(root, path string, afterOpen func() error) ([]byte, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, fileSizeInputError("policy", err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fileSizeInputError("policy", errors.New("repository root must be a real directory"))
	}
	absolute := path
	if !filepath.IsAbs(absolute) {
		absolute = filepath.Join(root, absolute)
	}
	absolute, err = filepath.Abs(absolute)
	if err != nil {
		return nil, fileSizeInputError("policy", err)
	}
	relative, err := filepath.Rel(root, absolute)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fileSizeInputError("policy", errors.New("policy must be inside the repository"))
	}
	parent, err := realPolicyParent(root, relative)
	if err != nil {
		return nil, err
	}
	before, err := os.Lstat(absolute)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() > filesize.MaximumPolicySize {
		return nil, fileSizeInputError("policy", errors.New("policy must be a bounded regular file"))
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, fileSizeInputError("policy", errors.New("policy cannot be opened"))
	}
	if afterOpen != nil {
		if err := afterOpen(); err != nil {
			_ = file.Close()
			return nil, fileSizeInputError("policy", err)
		}
	}
	data, readErr := io.ReadAll(io.LimitReader(file, filesize.MaximumPolicySize+1))
	opened, statErr := file.Stat()
	closeErr := file.Close()
	final, finalErr := os.Lstat(absolute)
	finalParent, parentErr := realPolicyParent(root, relative)
	if readErr != nil || statErr != nil || closeErr != nil || finalErr != nil || parentErr != nil ||
		parent != finalParent || !os.SameFile(before, opened) || !os.SameFile(opened, final) ||
		before.Mode() != opened.Mode() || opened.Mode() != final.Mode() ||
		before.Size() != opened.Size() || opened.Size() != final.Size() ||
		!before.ModTime().Equal(opened.ModTime()) || !opened.ModTime().Equal(final.ModTime()) ||
		len(data) > filesize.MaximumPolicySize || int64(len(data)) != final.Size() {
		return nil, fileSizeInputError("policy", errors.New("policy cannot be read completely"))
	}
	return data, nil
}

func realPolicyParent(root, relative string) (string, error) {
	current := root
	parent := filepath.Dir(relative)
	if parent == "." {
		return current, nil
	}
	for _, component := range strings.Split(parent, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fileSizeInputError("policy", errors.New("policy parent must contain only real directories"))
		}
	}
	return current, nil
}

func fileSizeInputError(field string, cause error) error {
	return &filesize.ContractError{Code: filesize.CodeInvalidInput, Field: field, Detail: "invalid input", Cause: cause}
}

func printFileSizeError(writer io.Writer, err error) {
	var contractErr *filesize.ContractError
	if errors.As(err, &contractErr) {
		fmt.Fprintf(writer, "qualitygate: %s\n", contractErr.Error())
		return
	}
	fmt.Fprintln(writer, "qualitygate: internal failure")
}

func fileSizeExitCode(err error) int {
	switch filesize.CodeOf(err) {
	case filesize.CodeInvalidInput:
		return 64
	case filesize.CodeDenied:
		return 2
	case filesize.CodeTimeout:
		return 124
	case filesize.CodeCanceled:
		return 130
	default:
		return 1
	}
}
