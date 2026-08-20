package quality

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const maximumStageOutput = 8 << 20

type StageRequest struct {
	ID          string
	Root        string
	ArtifactDir string
	Lane        string
}

type Execution struct {
	ExitCode int
	Output   []byte
}

// Executor is the narrow process boundary used by the quality runner.
type Executor interface {
	Execute(context.Context, StageRequest) (Execution, error)
}

// LocalExecutor invokes only the repository's fixed, default-deny dispatcher.
type LocalExecutor struct {
	verifyTools func(string, string) error
}

func (executor LocalExecutor) Execute(ctx context.Context, request StageRequest) (Execution, error) {
	if !IsRequiredStage(request.ID) {
		return Execution{}, qualityError(CodeDenied, "stage", "stage is not allowlisted", nil)
	}
	verifier := executor.verifyTools
	if verifier == nil {
		verifier = VerifyLockedTools
	}
	if err := verifier(os.Getenv("GOBIN"), request.Lane); err != nil {
		return Execution{}, err
	}
	script := filepath.Join(request.Root, "scripts", "ci_stage.sh")
	self, selfDigest, err := trustedSelf()
	if err != nil {
		return Execution{}, err
	}
	command := exec.CommandContext(ctx, "/bin/bash", script, request.ID)
	command.Dir = request.Root
	environment, err := stageEnvironment(request, self)
	if err != nil {
		return Execution{}, err
	}
	command.Env = environment
	command.WaitDelay = time.Second
	configureProcess(command)
	var output boundedBuffer
	output.remaining = maximumStageOutput
	command.Stdout = &output
	command.Stderr = &output
	err = command.Run()
	reapProcessGroup(command)
	if toolErr := verifier(os.Getenv("GOBIN"), request.Lane); toolErr != nil {
		return Execution{}, toolErr
	}
	if _, afterDigest, verifyErr := trustedSelf(); verifyErr != nil || afterDigest != selfDigest {
		reapProcessGroup(command)
		return Execution{}, qualityError(CodeDenied, "executor", "quality executable changed during dispatch", verifyErr)
	}
	result := Execution{ExitCode: 0, Output: bytes.Clone(output.Bytes())}
	if err == nil {
		return result, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return result, contextQualityError(ctxErr, "stage."+request.ID)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	return result, qualityError(CodeToolFailure, "stage."+request.ID, "stage process failed", err)
}

func trustedSelf() (string, string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", "", qualityError(CodeToolFailure, "executor", "cannot resolve quality executable", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", "", qualityError(CodeDenied, "executor", "quality executable must be a regular file", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", qualityError(CodeToolFailure, "executor", "cannot verify quality executable", err)
	}
	sum := sha256.Sum256(data)
	return path, hex.EncodeToString(sum[:]), nil
}

func stageEnvironment(request StageRequest, self string) ([]string, error) {
	goRoot := os.Getenv("COH_GO_ROOT")
	goBin := os.Getenv("COH_GO_BIN")
	toolBin := os.Getenv("GOBIN")
	toolchainRoot := os.Getenv("COH_TOOLCHAIN_ROOT")
	for name, value := range map[string]string{"COH_GO_ROOT": goRoot, "COH_GO_BIN": goBin, "GOBIN": toolBin, "COH_TOOLCHAIN_ROOT": toolchainRoot} {
		if !filepath.IsAbs(value) || strings.Contains(value, "\n") {
			return nil, qualityError(CodeInvalidInput, "environment."+name, "trusted absolute path is required", nil)
		}
	}
	if filepath.Clean(goBin) != filepath.Join(filepath.Clean(goRoot), "bin", "go") {
		return nil, qualityError(CodeDenied, "environment.COH_GO_BIN", "Go executable must belong to the selected root", nil)
	}
	for name, value := range map[string]string{
		"GOBIN": toolBin, "GOCACHE": os.Getenv("GOCACHE"), "GOMODCACHE": os.Getenv("GOMODCACHE"),
		"GOPATH": os.Getenv("GOPATH"), "GOTMPDIR": os.Getenv("GOTMPDIR"),
		"XDG_CONFIG_HOME": os.Getenv("XDG_CONFIG_HOME"), "XDG_CACHE_HOME": os.Getenv("XDG_CACHE_HOME"),
		"STATICCHECK_CACHE": os.Getenv("STATICCHECK_CACHE"),
	} {
		if !pathWithin(toolchainRoot, value) {
			return nil, qualityError(CodeDenied, "environment."+name, "mutable path must remain under the toolchain root", nil)
		}
	}
	artifactRoot := toolchainRoot
	if os.Getenv("CI") == "true" {
		artifactRoot = os.Getenv("RUNNER_TEMP")
		if !filepath.IsAbs(artifactRoot) {
			return nil, qualityError(CodeInvalidInput, "environment.RUNNER_TEMP", "hosted runner temporary root is required", nil)
		}
	}
	if !pathWithin(artifactRoot, request.ArtifactDir) {
		return nil, qualityError(CodeDenied, "environment.COH_CI_ARTIFACT_DIR", "artifact path must remain under approved mutable storage", nil)
	}
	xdgConfig := os.Getenv("XDG_CONFIG_HOME")
	xdgCache := os.Getenv("XDG_CACHE_HOME")
	staticcheckCache := os.Getenv("STATICCHECK_CACHE")
	values := map[string]string{
		"PATH": goRoot + "/bin:/usr/bin:/bin", "TMPDIR": os.Getenv("GOTMPDIR"),
		"GOCACHE": os.Getenv("GOCACHE"), "GOMODCACHE": os.Getenv("GOMODCACHE"), "GOPATH": os.Getenv("GOPATH"), "GOTMPDIR": os.Getenv("GOTMPDIR"),
		"GOBIN": toolBin, "GOROOT": goRoot, "GOTOOLCHAIN": "local", "GOENV": "off", "GOTELEMETRY": "off", "GOFLAGS": "-mod=readonly", "GOWORK": filepath.Join(request.Root, "go.work"),
		"GOPROXY": "off", "GOSUMDB": "off", "GOPRIVATE": "", "GONOPROXY": "", "GONOSUMDB": "",
		"COH_GO_ROOT": goRoot, "COH_GO_BIN": goBin, "COH_TOOLCHAIN_ROOT": toolchainRoot,
		"COH_CI_ARTIFACT_DIR": request.ArtifactDir, "COH_CI_LANE": request.Lane, "COH_QUALITYGATE_BIN": self,
		"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_COUNT": "0", "LANG": "C", "LC_ALL": "C",
		"XDG_CONFIG_HOME": xdgConfig, "XDG_CACHE_HOME": xdgCache,
		"STATICCHECK_CACHE": staticcheckCache,
	}
	if nativeStorageRoot := os.Getenv("COH_NATIVE_STORAGE_ROOT"); nativeStorageRoot != "" {
		if !pathWithin(nativeStorageRoot, toolchainRoot) {
			return nil, qualityError(CodeDenied, "environment.COH_NATIVE_STORAGE_ROOT", "toolchain must remain under the native storage root", nil)
		}
		values["COH_NATIVE_STORAGE_ROOT"] = nativeStorageRoot
	}
	for _, name := range []string{"CI", "RUNNER_TEMP", "COH_CI_OFFLINE", "COH_GOVULNDB", "COH_GOVULNDB_MANIFEST", "COH_GOVULNDB_MANIFEST_SHA256"} {
		if value := os.Getenv(name); value != "" {
			values[name] = value
		}
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	slices.Sort(names)
	result := make([]string, 0, len(names))
	for _, name := range names {
		result = append(result, name+"="+values[name])
	}
	return result, nil
}

func pathWithin(root, candidate string) bool {
	if !filepath.IsAbs(root) || !filepath.IsAbs(candidate) || strings.Contains(candidate, "\n") {
		return false
	}
	realRoot, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return false
	}
	realCandidate, err := filepath.EvalSymlinks(filepath.Clean(candidate))
	if err != nil {
		return false
	}
	relative, err := filepath.Rel(realRoot, realCandidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func commandDigest(stageID string) string {
	canonical, _ := json.Marshal([]string{"scripts/ci_stage.sh", stageID})
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func IsRequiredStage(id string) bool {
	for _, required := range requiredStages {
		if id == required {
			return true
		}
	}
	return false
}
