//go:build darwin || linux

package nativeexecutor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"
)

type ProcessSandbox struct {
	helperPath   string
	helperDigest string
	artifacts    ArtifactPreparer
	root         string
}

func NewProcessSandbox(helperPath, helperDigest, root string,
	artifacts ArtifactPreparer) (*ProcessSandbox, error) {
	if artifacts == nil || !filepath.IsAbs(helperPath) || filepath.Clean(helperPath) != helperPath ||
		!digestPattern.MatchString(helperDigest) || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, NewError(InvalidInput, "sandbox_configuration")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return nil, NewError(Denied, "sandbox_root")
	}
	return &ProcessSandbox{helperPath: helperPath, helperDigest: helperDigest, artifacts: artifacts, root: root}, nil
}

func (sandbox *ProcessSandbox) Execute(ctx context.Context, plan Plan) (result SandboxResult, resultErr error) {
	if sandbox == nil || sandbox.artifacts == nil {
		return SandboxResult{}, NewError(Unavailable, "sandbox_unavailable")
	}
	if err := contextError(ctx); err != nil {
		return SandboxResult{}, err
	}
	if err := validateSandboxPlan(plan); err != nil {
		return SandboxResult{}, err
	}
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(plan.Limits.WallTimeMilliseconds)*time.Millisecond)
	defer cancel()
	ctx = runCtx
	rootInfo, rootErr := os.Lstat(sandbox.root)
	if rootErr != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm()&0o022 != 0 {
		return SandboxResult{}, NewError(Denied, "sandbox_root")
	}
	helper, err := sandbox.artifacts.Prepare(ctx, sandbox.helperPath, sandbox.helperDigest, maximumArtifactBytes)
	if err != nil {
		return SandboxResult{}, err
	}
	if helper.Cleanup == nil || helper.Path == "" || helper.Digest != sandbox.helperDigest {
		if helper.Cleanup != nil {
			_ = helper.Cleanup()
		}
		return SandboxResult{}, NewError(Denied, "sandbox_helper_binding")
	}
	defer func() {
		if err := helper.Cleanup(); err != nil {
			resultErr = NewError(Unavailable, "sandbox_cleanup_failed")
		}
	}()
	workingDirectory, err := os.MkdirTemp(sandbox.root, "coh-native-work-")
	if err != nil {
		return SandboxResult{}, NewError(Unavailable, "sandbox_working_directory")
	}
	defer func() {
		if err := os.RemoveAll(workingDirectory); err != nil {
			resultErr = NewError(Unavailable, "sandbox_cleanup_failed")
		}
	}()
	encoded, err := json.Marshal(helperPlan{ExecutablePath: plan.ExecutablePath, Arguments: plan.Arguments,
		Environment: plan.Environment, WorkingDirectory: workingDirectory, Limits: plan.Limits})
	if err != nil || len(encoded) > MaximumInputBytes {
		return SandboxResult{}, NewError(InvalidInput, "sandbox_plan")
	}
	planFile, err := os.CreateTemp(workingDirectory, "plan-")
	if err != nil {
		return SandboxResult{}, NewError(Unavailable, "sandbox_plan")
	}
	planPath := planFile.Name()
	defer planFile.Close()
	defer os.Remove(planPath)
	if err := planFile.Chmod(0o400); err != nil {
		return SandboxResult{}, NewError(Unavailable, "sandbox_plan")
	}
	if _, err := planFile.Write(encoded); err != nil {
		return SandboxResult{}, NewError(Unavailable, "sandbox_plan")
	}
	if _, err := planFile.Seek(0, io.SeekStart); err != nil {
		return SandboxResult{}, NewError(Unavailable, "sandbox_plan")
	}
	command := sandboxCommand(ctx, helper.Path, workingDirectory)
	command.Dir = workingDirectory
	command.Env = []string{}
	command.Stdin = bytes.NewReader(plan.Input)
	command.ExtraFiles = []*os.File{planFile}
	output := newBoundedOutput(plan.Limits.OutputBytes)
	command.Stdout, command.Stderr = output.writer(false), output.writer(true)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return killProcessGroup(command.Process) }
	command.WaitDelay = 250 * time.Millisecond
	if err := command.Start(); err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return SandboxResult{ExitCode: -1}, contextErr
		}
		return SandboxResult{}, NewError(Unavailable, "process_start_failed")
	}
	_ = planFile.Close()
	_ = os.Remove(planPath)
	storageExceeded := make(chan struct{}, 1)
	monitorDone := make(chan struct{})
	memoryExceeded := make(chan struct{}, 1)
	processExceeded := make(chan struct{}, 1)
	monitorFailed := make(chan struct{}, 1)
	var monitors sync.WaitGroup
	monitors.Add(3)
	go func() {
		defer monitors.Done()
		monitorStorage(ctx, workingDirectory, plan.Limits.EphemeralStorageBytes, command.Process,
			storageExceeded, monitorFailed, monitorDone)
	}()
	go func() {
		defer monitors.Done()
		monitorMemory(ctx, command.Process, plan.Limits.MemoryBytes, memoryExceeded, monitorFailed, monitorDone)
	}()
	go func() {
		defer monitors.Done()
		monitorProcessCount(ctx, command.Process, plan.Limits.ProcessCount, processExceeded, monitorFailed, monitorDone)
	}()
	waitErr := command.Wait()
	close(monitorDone)
	monitors.Wait()
	result = output.result(command.ProcessState)
	select {
	case <-monitorFailed:
		return result, NewError(Unavailable, "resource_monitor_unavailable")
	default:
	}
	select {
	case <-storageExceeded:
		return result, NewError(Denied, "ephemeral_storage_limit")
	default:
	}
	select {
	case <-memoryExceeded:
		return result, NewError(Denied, "memory_limit")
	default:
	}
	select {
	case <-processExceeded:
		return result, NewError(Denied, "process_limit")
	default:
	}
	if output.exceeded() {
		return result, NewError(Denied, "output_limit")
	}
	if contextErr := contextError(ctx); contextErr != nil {
		return result, contextErr
	}
	var exitErr *exec.ExitError
	if waitErr == nil || errors.As(waitErr, &exitErr) {
		return result, nil
	}
	return result, NewError(Unavailable, "process_wait_failed")
}

func validateSandboxPlan(plan Plan) error {
	if !filepath.IsAbs(plan.ExecutablePath) || filepath.Clean(plan.ExecutablePath) != plan.ExecutablePath ||
		!digestPattern.MatchString(plan.ArtifactDigest) || len(plan.Input) > MaximumInputBytes || !validLimits(plan.Limits) ||
		plan.Network.Mode != "none" || plan.Network.DNSMode != "none" || len(plan.Network.Protocols) != 0 ||
		plan.Network.PublicInternetAllowed || plan.Network.MetadataAllowed || plan.Network.MaximumConnections != 0 {
		return NewError(Denied, "sandbox_plan")
	}
	info, err := os.Lstat(plan.ExecutablePath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 ||
		digestFile(plan.ExecutablePath) != plan.ArtifactDigest {
		return NewError(Denied, "sandbox_artifact")
	}
	return validateHelperPlan(helperPlan{ExecutablePath: plan.ExecutablePath, Arguments: plan.Arguments,
		Environment: plan.Environment, WorkingDirectory: filepath.Dir(plan.ExecutablePath), Limits: plan.Limits})
}

func digestFile(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maximumArtifactBytes+1)); err != nil {
		return ""
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

func sandboxCommand(ctx context.Context, helperPath, workingDirectory string) *exec.Cmd {
	if runtime.GOOS == "darwin" {
		profile := fmt.Sprintf(`(version 1)(allow default)(deny network*)(deny file-write* (require-not (subpath %q)))`, workingDirectory)
		return exec.CommandContext(ctx, "/usr/bin/sandbox-exec", "-p", profile, helperPath)
	}
	return exec.CommandContext(ctx, "/usr/bin/unshare", "--net", "--", helperPath)
}

func killProcessGroup(process *os.Process) error {
	if process == nil {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
