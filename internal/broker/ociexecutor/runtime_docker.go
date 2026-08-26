package ociexecutor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

const (
	maximumRuntimeBytes = 256 << 20
	controlOutputBytes  = 64 << 10
	controlTimeout      = 10 * time.Second
	healthTimeout       = 5 * time.Second
)

type DockerRuntimeConfig struct {
	BinaryPath   string
	BinaryDigest string
	StateRoot    string
	EngineSocket string
}

// DockerRuntime invokes one digest-bound Docker-compatible CLI over one
// trusted local Unix socket. It never passes a shell command, host mount,
// device, credential, floating image reference, or ambient environment.
type DockerRuntime struct {
	binaryPath   string
	binaryDigest string
	stateRoot    string
	engineSocket string
}

func NewDockerRuntime(config DockerRuntimeConfig) (*DockerRuntime, error) {
	if !filepath.IsAbs(config.BinaryPath) || filepath.Clean(config.BinaryPath) != config.BinaryPath ||
		!digestPattern.MatchString(config.BinaryDigest) || !filepath.IsAbs(config.StateRoot) ||
		filepath.Clean(config.StateRoot) != config.StateRoot || !filepath.IsAbs(config.EngineSocket) ||
		filepath.Clean(config.EngineSocket) != config.EngineSocket {
		return nil, NewError(InvalidInput, "runtime_configuration")
	}
	if err := privateDirectory(config.StateRoot); err != nil {
		return nil, err
	}
	if err := verifySocket(config.EngineSocket); err != nil {
		return nil, err
	}
	stagedBinary, err := stageRuntimeFile(config.BinaryPath, config.BinaryDigest, config.StateRoot)
	if err != nil {
		return nil, err
	}
	return &DockerRuntime{binaryPath: stagedBinary, binaryDigest: config.BinaryDigest,
		stateRoot: config.StateRoot, engineSocket: config.EngineSocket}, nil
}

func (runtime *DockerRuntime) Execute(ctx context.Context, plan ContainerPlan) (RuntimeResult, error) {
	if runtime == nil || runtime.binaryPath == "" {
		return RuntimeResult{}, NewError(Unavailable, "runtime_unavailable")
	}
	result := RuntimeResult{ExitCode: -1, CleanupComplete: true,
		ContainerSpecDigest: digestBytes(canonicalBytes(plan)),
		HealthCommandDigest: digestBytes(canonicalBytes(plan.HealthArguments)), RuntimeDigest: runtime.binaryDigest}
	if err := contextError(ctx); err != nil {
		return result, err
	}
	if err := validateContainerPlan(plan); err != nil {
		return result, err
	}
	if err := verifyStagedRuntime(runtime.binaryPath, runtime.binaryDigest); err != nil {
		return result, err
	}
	if err := verifySocket(runtime.engineSocket); err != nil {
		return result, err
	}
	if err := runtime.verifyImage(ctx, plan.ImageReference); err != nil {
		return result, err
	}
	result.ResolvedImageDigest = plan.ImageDigest
	healthCtx, cancelHealth := context.WithTimeout(ctx, healthTimeoutFor(plan.Limits.WallTimeMilliseconds))
	health, healthErr := runtime.runContainer(healthCtx, plan, containerName(plan.AttemptID, "health"),
		plan.HealthArguments, nil, minUint64(plan.Limits.OutputBytes, controlOutputBytes))
	cancelHealth()
	if !health.CleanupComplete {
		result.CleanupComplete = false
		return result, NewError(Unavailable, "health_cleanup_failed")
	}
	if healthErr != nil || health.ExitCode != 0 {
		result.CleanupComplete = true
		if ctx.Err() != nil {
			result.HealthOutcome = "canceled"
			return result, ctx.Err()
		}
		result.HealthOutcome = "unhealthy"
		return result, NewError(Denied, "health_check_failed")
	}
	result.HealthOutcome = "healthy"
	execution, runErr := runtime.runContainer(ctx, plan, containerName(plan.AttemptID, "run"),
		plan.Arguments, plan.Input, plan.Limits.OutputBytes)
	result.ExitCode = execution.ExitCode
	result.TerminationSignal = execution.TerminationSignal
	result.StandardOutput = execution.StandardOutput
	result.StandardError = execution.StandardError
	result.OutputTruncated = execution.OutputTruncated
	result.CleanupComplete = execution.CleanupComplete
	if runErr != nil {
		return result, runErr
	}
	return result, nil
}

type containerExecution struct {
	ExitCode          int
	TerminationSignal string
	StandardOutput    []byte
	StandardError     []byte
	OutputTruncated   bool
	CleanupComplete   bool
}

func (runtime *DockerRuntime) runContainer(ctx context.Context, plan ContainerPlan, name string,
	arguments []string, input []byte, outputLimit uint64) (containerExecution, error) {
	result := containerExecution{ExitCode: -1, CleanupComplete: true}
	createArguments := append([]string{"create"}, dockerCreateArguments(plan, name, arguments)...)
	if _, _, err := runtime.control(ctx, createArguments, nil); err != nil {
		return result, err
	}
	created := true
	cleanup := func() bool {
		if !created {
			return true
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), controlTimeout)
		defer cancel()
		_, _, err := runtime.control(cleanupCtx, []string{"rm", "--force", name}, nil)
		created = false
		return err == nil
	}
	output := newBoundedOutput(outputLimit)
	if err := verifyStagedRuntime(runtime.binaryPath, runtime.binaryDigest); err != nil {
		result.CleanupComplete = cleanup()
		return result, err
	}
	if err := verifySocket(runtime.engineSocket); err != nil {
		result.CleanupComplete = cleanup()
		return result, err
	}
	command := exec.Command(runtime.binaryPath, "start", "--attach", "--interactive", name)
	command.Env = runtime.environment()
	command.Dir = runtime.stateRoot
	command.Stdin = bytes.NewReader(input)
	command.Stdout = output.stdout
	command.Stderr = output.stderr
	if err := command.Start(); err != nil {
		result.CleanupComplete = cleanup()
		return result, NewError(Unavailable, "container_start_failed")
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		result.TerminationSignal = "KILL"
		_ = runtime.kill(name)
		waitErr = boundedCommandWait(command, done)
	case <-output.exceeded:
		result.TerminationSignal = "KILL"
		_ = runtime.kill(name)
		waitErr = boundedCommandWait(command, done)
	}
	result.StandardOutput, result.StandardError, result.OutputTruncated = output.snapshot()
	exitCode, oomKilled, inspectErr := runtime.inspectExit(name)
	result.CleanupComplete = cleanup()
	if !result.CleanupComplete {
		return result, NewError(Unavailable, "container_cleanup_failed")
	}
	if inspectErr != nil {
		return result, inspectErr
	}
	result.ExitCode = exitCode
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if result.OutputTruncated {
		return result, NewError(Denied, "output_limit")
	}
	if oomKilled {
		return result, NewError(Denied, "memory_limit")
	}
	if waitErr != nil && exitCode == 0 {
		return result, NewError(Unavailable, "container_wait_failed")
	}
	return result, nil
}

func dockerCreateArguments(plan ContainerPlan, name string, arguments []string) []string {
	period := uint64(100_000)
	quota, _ := dockerCPUQuota(plan.Limits)
	values := []string{"--name", name, "--pull", "never", "--user",
		fmt.Sprintf("%d:%d", plan.RunAsUser, plan.RunAsGroup), "--read-only", "--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true", "--network", plan.EngineNetwork, "--pids-limit",
		strconv.FormatUint(uint64(plan.Limits.ProcessCount), 10), "--memory", strconv.FormatUint(plan.Limits.MemoryBytes, 10),
		"--memory-swap", strconv.FormatUint(plan.Limits.MemoryBytes, 10), "--cpu-period", strconv.FormatUint(period, 10),
		"--cpu-quota", strconv.FormatUint(quota, 10), "--ulimit",
		fmt.Sprintf("nofile=%d:%d", plan.Limits.OpenFileCount, plan.Limits.OpenFileCount),
		"--workdir", plan.WorkingDirectory, "--log-driver", "none", "--stop-timeout", "1"}
	environment := slices.Clone(plan.Environment)
	slices.Sort(environment)
	for _, entry := range environment {
		values = append(values, "--env", entry)
	}
	mounts := slices.Clone(plan.WritableMounts)
	slices.SortFunc(mounts, func(left, right WritableMount) int { return strings.Compare(left.Destination, right.Destination) })
	for _, mount := range mounts {
		values = append(values, "--tmpfs", fmt.Sprintf("%s:rw,noexec,nosuid,nodev,size=%d", mount.Destination, mount.Bytes))
	}
	values = append(values, "--entrypoint", plan.Entrypoint, plan.ImageReference)
	return append(values, arguments...)
}

func validateContainerPlan(plan ContainerPlan) error {
	if !uuidPattern.MatchString(plan.AttemptID) || !digestPattern.MatchString(plan.ImageDigest) ||
		plan.ImageReference == "" || plan.ImageReference != strings.TrimSuffix(plan.ImageReference, "@"+plan.ImageDigest)+"@"+plan.ImageDigest ||
		!repositoryPattern.MatchString(strings.TrimSuffix(plan.ImageReference, "@"+plan.ImageDigest)) ||
		!validContainerPath(plan.Entrypoint) || plan.RunAsUser == 0 || plan.RunAsGroup == 0 ||
		plan.WorkingDirectory != "/work" || !validLimits(plan.Limits) || !validNetworkPolicy(plan.Network) ||
		plan.NetworkPolicyHash != digestBytes(canonicalBytes(plan.Network)) {
		return NewError(Denied, "container_plan")
	}
	if _, supported := dockerCPUQuota(plan.Limits); !supported {
		return NewError(Denied, "cpu_limit_unsupported")
	}
	if plan.Network.Mode == "none" && plan.EngineNetwork != "none" ||
		plan.Network.Mode != "none" && !tokenPattern.MatchString(plan.EngineNetwork) {
		return NewError(Denied, "container_network")
	}
	if err := validateArguments(plan.Arguments, false); err != nil {
		return NewError(Denied, "container_arguments")
	}
	if err := validateArguments(plan.HealthArguments, true); err != nil {
		return NewError(Denied, "container_health")
	}
	if len(plan.Input) > MaximumInputBytes {
		return NewError(Denied, "container_input")
	}
	if err := validateMounts(plan.WritableMounts); err != nil {
		return NewError(Denied, "container_mounts")
	}
	if err := validateMountBudget(plan.WritableMounts, plan.Limits.EphemeralStorageBytes); err != nil {
		return err
	}
	if !slices.IsSorted(plan.Environment) {
		return NewError(Denied, "container_environment")
	}
	seenEnvironment := make(map[string]struct{}, len(plan.Environment))
	for _, entry := range plan.Environment {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 || !allowedEnvironment[parts[0]] || sensitiveEnvironment(parts[0]) ||
			len(parts[1]) > MaximumArgumentBytes || strings.IndexByte(parts[1], 0) >= 0 {
			return NewError(Denied, "container_environment")
		}
		if _, duplicate := seenEnvironment[parts[0]]; duplicate {
			return NewError(Denied, "container_environment")
		}
		seenEnvironment[parts[0]] = struct{}{}
	}
	return nil
}

func dockerCPUQuota(limits toolregistry.ResourceLimits) (uint64, bool) {
	const period = uint64(100_000)
	quota := limits.CPUMilliseconds * period / limits.WallTimeMilliseconds
	if quota < 1_000 {
		return 0, false
	}
	maximumQuota := uint64(limits.ProcessCount) * period
	if quota > maximumQuota {
		quota = maximumQuota
	}
	return quota, true
}

func (runtime *DockerRuntime) verifyImage(ctx context.Context, reference string) error {
	stdout, _, err := runtime.control(ctx, []string{"image", "inspect", "--format", "{{json .RepoDigests}}", reference}, nil)
	if err != nil {
		return NewError(Unavailable, "image_unavailable")
	}
	var digests []string
	if json.Unmarshal(bytes.TrimSpace(stdout), &digests) != nil || !slices.Contains(digests, reference) {
		return NewError(Denied, "image_digest_mismatch")
	}
	return nil
}

func (runtime *DockerRuntime) inspectExit(name string) (int, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()
	stdout, _, err := runtime.control(ctx, []string{"inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", name}, nil)
	if err != nil {
		return -1, false, NewError(Unavailable, "container_inspect_failed")
	}
	fields := strings.Fields(string(stdout))
	if len(fields) != 2 {
		return -1, false, NewError(Unavailable, "container_inspect_failed")
	}
	exitCode, parseErr := strconv.Atoi(fields[0])
	oomKilled, boolErr := strconv.ParseBool(fields[1])
	if parseErr != nil || boolErr != nil || exitCode < 0 || exitCode > 255 {
		return -1, false, NewError(Unavailable, "container_inspect_failed")
	}
	return exitCode, oomKilled, nil
}

func (runtime *DockerRuntime) kill(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), controlTimeout)
	defer cancel()
	_, _, err := runtime.control(ctx, []string{"kill", "--signal", "KILL", name}, nil)
	return err
}

func boundedCommandWait(command *exec.Cmd, done <-chan error) error {
	timer := time.NewTimer(controlTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		return <-done
	}
}

func (runtime *DockerRuntime) control(parent context.Context, arguments []string, input []byte) ([]byte, []byte, error) {
	if err := verifyStagedRuntime(runtime.binaryPath, runtime.binaryDigest); err != nil {
		return nil, nil, err
	}
	if err := verifySocket(runtime.engineSocket); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(parent, controlTimeout)
	defer cancel()
	output := newBoundedOutput(controlOutputBytes)
	command := exec.CommandContext(ctx, runtime.binaryPath, arguments...)
	command.Env = runtime.environment()
	command.Dir = runtime.stateRoot
	command.Stdin = bytes.NewReader(input)
	command.Stdout, command.Stderr = output.stdout, output.stderr
	err := command.Run()
	stdout, stderr, truncated := output.snapshot()
	if truncated {
		return stdout, stderr, NewError(Denied, "control_output_limit")
	}
	if err != nil {
		if ctx.Err() != nil {
			return stdout, stderr, ctx.Err()
		}
		return stdout, stderr, NewError(Unavailable, "runtime_control_failed")
	}
	return stdout, stderr, nil
}

func (runtime *DockerRuntime) environment() []string {
	return []string{"DOCKER_HOST=unix://" + runtime.engineSocket, "DOCKER_CONFIG=" + filepath.Join(runtime.stateRoot, "config"),
		"HOME=" + runtime.stateRoot, "LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin"}
}

func healthTimeoutFor(wallMilliseconds uint64) time.Duration {
	wall := time.Duration(wallMilliseconds) * time.Millisecond
	if wall < healthTimeout {
		return wall
	}
	return healthTimeout
}

func minUint64(left, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}
