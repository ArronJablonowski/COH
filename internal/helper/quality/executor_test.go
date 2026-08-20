package quality

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLocalExecutorScrubsBashEnvironment(t *testing.T) {
	root, artifacts := executorWorkspace(t)
	malicious := filepath.Join(t.TempDir(), "malicious.sh")
	pwned := filepath.Join(root, "pwned")
	if err := os.WriteFile(malicious, []byte("touch \""+pwned+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BASH_ENV", malicious)
	result, err := (LocalExecutor{verifyTools: acceptTestTools}).Execute(context.Background(), StageRequest{ID: "format", Root: root, ArtifactDir: artifacts, Lane: "baseline"})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("Execute() result=%+v err=%v output=%s", result, err, result.Output)
	}
	if _, err := os.Stat(pwned); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("BASH_ENV executed inside fixed dispatcher")
	}
}

func TestLocalExecutorReapsSuccessfulBackgroundChild(t *testing.T) {
	root, artifacts := executorWorkspace(t)
	pidFile := filepath.Join(root, "child.pid")
	script := "#!/usr/bin/env bash\nset -e\nsh -c 'trap \"\" TERM; while :; do sleep 1; done' </dev/null >/dev/null 2>&1 &\nchild=$!\nprintf '%s\\n' \"$child\" > \"" + pidFile + "\"\nprintf passed > \"$COH_CI_ARTIFACT_DIR/format.log\"\n"
	if err := os.WriteFile(filepath.Join(root, "scripts", "ci_stage.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	result, err := (LocalExecutor{verifyTools: acceptTestTools}).Execute(context.Background(), StageRequest{ID: "format", Root: root, ArtifactDir: artifacts, Lane: "baseline"})
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("Execute() result=%+v err=%v", result, err)
	}
	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("background child %d survived successful stage", pid)
}

func TestLocalExecutorRejectsToolMutationAfterStage(t *testing.T) {
	root, artifacts := executorWorkspace(t)
	checks := 0
	verifier := func(string, string) error {
		checks++
		if checks > 1 {
			return qualityError(CodeDenied, "tools", "tool changed", nil)
		}
		return nil
	}
	_, err := (LocalExecutor{verifyTools: verifier}).Execute(context.Background(), StageRequest{ID: "format", Root: root, ArtifactDir: artifacts, Lane: "baseline"})
	if CodeOf(err) != CodeDenied || checks != 2 {
		t.Fatalf("checks=%d code=%q err=%v", checks, CodeOf(err), err)
	}
}

func acceptTestTools(string, string) error { return nil }

func executorWorkspace(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/usr/bin/env bash\nset -e\nprintf passed > \"$COH_CI_ARTIFACT_DIR/format.log\"\n"
	if err := os.WriteFile(filepath.Join(root, "scripts", "ci_stage.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	toolchain := t.TempDir()
	artifacts := filepath.Join(toolchain, "artifacts")
	if err := os.MkdirAll(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	goRootBytes, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	goRoot := strings.TrimSpace(string(goRootBytes))
	t.Setenv("COH_GO_ROOT", goRoot)
	t.Setenv("COH_GO_BIN", filepath.Join(goRoot, "bin", "go"))
	t.Setenv("COH_TOOLCHAIN_ROOT", toolchain)
	toolBin := filepath.Join(toolchain, "bin")
	if err := os.MkdirAll(toolBin, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOBIN", toolBin)
	for _, name := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "GOTMPDIR"} {
		path := filepath.Join(toolchain, strings.ToLower(name))
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name, path)
	}
	for name, path := range map[string]string{
		"XDG_CONFIG_HOME":   filepath.Join(toolchain, "ci-xdg", "config"),
		"XDG_CACHE_HOME":    filepath.Join(toolchain, "ci-xdg", "cache"),
		"STATICCHECK_CACHE": filepath.Join(toolchain, "staticcheck-cache", "baseline"),
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Setenv(name, path)
	}
	return root, artifacts
}

func TestPathWithinRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	if pathWithin(root, link) {
		t.Fatal("symlink escape was accepted as contained")
	}
	inside := filepath.Join(root, "inside")
	if err := os.Mkdir(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	if !pathWithin(root, inside) {
		t.Fatal("real child directory was rejected")
	}
}

func TestStageEnvironmentRejectsMutableCacheSymlinkEscapes(t *testing.T) {
	for _, name := range []string{"ci-xdg", "staticcheck-cache"} {
		t.Run(name, func(t *testing.T) {
			root, artifacts := executorWorkspace(t)
			toolchain := os.Getenv("COH_TOOLCHAIN_ROOT")
			outside := t.TempDir()
			path := filepath.Join(toolchain, name)
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
			if _, err := stageEnvironment(StageRequest{
				ID: "format", Root: root, ArtifactDir: artifacts, Lane: "baseline",
			}, filepath.Join(root, "qualitygate")); CodeOf(err) != CodeDenied {
				t.Fatalf("escape code=%q err=%v", CodeOf(err), err)
			}
			if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
				t.Fatalf("escape wrote outside: entries=%v err=%v", entries, err)
			}
		})
	}
}

func TestStageEnvironmentBindsExplicitNativeStorageRoot(t *testing.T) {
	root, artifacts := executorWorkspace(t)
	storageRoot := filepath.Dir(os.Getenv("COH_TOOLCHAIN_ROOT"))
	t.Setenv("COH_NATIVE_STORAGE_ROOT", storageRoot)
	environment, err := stageEnvironment(StageRequest{
		ID: "format", Root: root, ArtifactDir: artifacts, Lane: "baseline",
	}, filepath.Join(root, "qualitygate"))
	if err != nil {
		t.Fatalf("stageEnvironment() error=%v", err)
	}
	want := "COH_NATIVE_STORAGE_ROOT=" + storageRoot
	found := false
	for _, value := range environment {
		found = found || value == want
	}
	if !found {
		t.Fatal("native storage root was not forwarded to the fixed stage environment")
	}
	t.Setenv("COH_NATIVE_STORAGE_ROOT", t.TempDir())
	if _, err := stageEnvironment(StageRequest{
		ID: "format", Root: root, ArtifactDir: artifacts, Lane: "baseline",
	}, filepath.Join(root, "qualitygate")); CodeOf(err) != CodeDenied {
		t.Fatalf("unrelated native storage root code=%q err=%v", CodeOf(err), err)
	}
}
