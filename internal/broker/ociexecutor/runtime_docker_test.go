package ociexecutor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestDockerCreateArgumentsAreLeastPrivilegeAndDeterministic(t *testing.T) {
	plan := testContainerPlan()
	arguments := dockerCreateArguments(plan, containerName(plan.AttemptID, "run"), plan.Arguments)
	requiredPairs := [][]string{{"--pull", "never"}, {"--user", "65532:65532"}, {"--cap-drop", "ALL"},
		{"--security-opt", "no-new-privileges:true"}, {"--network", "none"}, {"--log-driver", "none"},
		{"--entrypoint", "/usr/local/bin/fixture"}, {"--workdir", "/work"}}
	for _, pair := range requiredPairs {
		if !containsPair(arguments, pair[0], pair[1]) {
			t.Fatalf("missing %v in %v", pair, arguments)
		}
	}
	for _, required := range []string{"--read-only", "--pids-limit", "--memory", "--memory-swap", "--cpu-period",
		"--cpu-quota", "--ulimit", "--tmpfs"} {
		if !slices.Contains(arguments, required) {
			t.Fatalf("missing %s", required)
		}
	}
	joined := strings.Join(arguments, " ")
	for _, forbidden := range []string{"docker.sock", "--privileged", "--volume", "--mount", "--device", "--pid=host",
		"--network host", "--ipc=host", "--env TOKEN", ":latest"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("forbidden %q in %s", forbidden, joined)
		}
	}
	first := strings.Join(arguments, "\x00")
	second := strings.Join(dockerCreateArguments(plan, containerName(plan.AttemptID, "run"), plan.Arguments), "\x00")
	if first != second {
		t.Fatalf("arguments are not deterministic")
	}
}

func TestDockerRuntimeExecutesHealthInputBoundsCancellationAndCleanup(t *testing.T) {
	runtime := buildFakeDockerRuntime(t)
	t.Run("success", func(t *testing.T) {
		plan := testContainerPlan()
		result, err := runtime.Execute(context.Background(), plan)
		if err != nil || string(result.StandardOutput) != `{"message":"hello"}` || result.ExitCode != 0 ||
			result.HealthOutcome != "healthy" || !result.CleanupComplete || result.RuntimeDigest == "" {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
	t.Run("pre-canceled creates nothing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := runtime.Execute(ctx, testContainerPlan())
		if Code(err) != Canceled || !result.CleanupComplete || result.ContainerSpecDigest == "" {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
	t.Run("output bounded", func(t *testing.T) {
		plan := testContainerPlan()
		plan.Arguments = []string{"output"}
		plan.Limits.OutputBytes = 16
		result, err := runtime.Execute(context.Background(), plan)
		if Code(err) != Denied || Reason(err) != "output_limit" || len(result.StandardOutput) != 16 ||
			!result.OutputTruncated || !result.CleanupComplete {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
	t.Run("cancellation kills and cleans", func(t *testing.T) {
		plan := testContainerPlan()
		plan.Arguments = []string{"sleep"}
		ctx, cancel := context.WithCancel(context.Background())
		type executionResponse struct {
			result RuntimeResult
			err    error
		}
		done := make(chan executionResponse, 1)
		go func() {
			result, err := runtime.Execute(ctx, plan)
			done <- executionResponse{result: result, err: err}
		}()
		started := filepath.Join(runtime.stateRoot, containerName(plan.AttemptID, "run")+".started")
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := os.Stat(started); err == nil {
				break
			}
			if time.Now().After(deadline) {
				cancel()
				t.Fatal("container did not start")
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		completed := <-done
		if Code(completed.err) != Canceled || completed.result.ExitCode != 137 || completed.result.TerminationSignal != "KILL" || !completed.result.CleanupComplete {
			result, err := completed.result, completed.err
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
}

func TestDockerRuntimeRejectsBinaryDigestAndSocketDrift(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := buildFakeDocker(t, root)
	socket, closeSocket := unixSocket(t, root)
	defer closeSocket()
	if _, err := NewDockerRuntime(DockerRuntimeConfig{BinaryPath: binary, BinaryDigest: testDecisionDigest,
		StateRoot: root, EngineSocket: socket}); Code(err) != Denied || Reason(err) != "runtime_binary_digest" {
		t.Fatalf("digest error=%v", err)
	}
	digest := fileDigest(t, binary)
	runtime, err := NewDockerRuntime(DockerRuntimeConfig{BinaryPath: binary, BinaryDigest: digest,
		StateRoot: root, EngineSocket: socket})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtime.binaryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(runtime.binaryPath, append(mustRead(t, runtime.binaryPath), 'x'), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runtime.binaryPath, 0o500); err != nil {
		t.Fatal(err)
	}
	result, err := runtime.Execute(context.Background(), testContainerPlan())
	if Code(err) != Denied || Reason(err) != "runtime_binary_digest" || !result.CleanupComplete {
		t.Fatalf("result=%+v error=%v", result, err)
	}
}

func buildFakeDockerRuntime(t *testing.T) *DockerRuntime {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	binary := buildFakeDocker(t, root)
	socket, closeSocket := unixSocket(t, root)
	t.Cleanup(closeSocket)
	runtime, err := NewDockerRuntime(DockerRuntimeConfig{BinaryPath: binary, BinaryDigest: fileDigest(t, binary),
		StateRoot: root, EngineSocket: socket})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func buildFakeDocker(t *testing.T, root string) string {
	t.Helper()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "fake-docker")
	command := exec.Command(goBinary, "build", "-trimpath", "-o", binary, "./testdata/fake_docker")
	command.Dir = "."
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build fake Docker runtime: %v: %s", err, output)
	}
	if err := os.Chmod(binary, 0o500); err != nil {
		t.Fatal(err)
	}
	return binary
}

func unixSocket(t *testing.T, _ string) (string, func()) {
	t.Helper()
	directory, err := os.MkdirTemp("", "coh-oci-socket-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "engine.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		_ = os.RemoveAll(directory)
		t.Fatal(err)
	}
	return path, func() {
		_ = listener.Close()
		_ = os.RemoveAll(directory)
	}
}

func testContainerPlan() ContainerPlan {
	registration := testRegistration()
	policy := noNetwork()
	return ContainerPlan{AttemptID: testRequest().AttemptID,
		ImageReference: registration.ImageRepository + "@" + registration.ImageDigest, ImageDigest: registration.ImageDigest,
		Entrypoint: registration.Entrypoint, Arguments: []string{"echo"}, HealthArguments: registration.HealthArguments,
		Environment: []string{"LANG=C"}, Input: []byte(`{"message":"hello"}`), RunAsUser: registration.RunAsUser,
		RunAsGroup: registration.RunAsGroup, WorkingDirectory: "/work", WritableMounts: registration.WritableMounts,
		Limits: testLimits(), Network: policy, EngineNetwork: "none", NetworkPolicyHash: digestBytes(canonicalBytes(policy))}
}

func containsPair(values []string, left, right string) bool {
	for index := 0; index+1 < len(values); index++ {
		if values[index] == left && values[index+1] == right {
			return true
		}
	}
	return false
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	data := mustRead(t, path)
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
