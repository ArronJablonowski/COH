package architecture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	maximumGoListOutput = 32 << 20
	maximumStderrOutput = 64 << 10
)

// ListPackages executes a bounded `go list` under the caller's context.
func ListPackages(ctx context.Context, goBinary, root string, buildTags []string) ([]Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, contractError(CodeCanceled, "go", "package discovery canceled", err)
	}
	if goBinary == "" {
		return nil, contractError(CodeInvalidInput, "go", "Go executable is required", nil)
	}
	if root == "" {
		return nil, contractError(CodeInvalidInput, "root", "workspace root is required", nil)
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, contractError(CodeInvalidInput, "root", "cannot resolve workspace root", err)
	}

	var stdout limitedBuffer
	stdout.remaining = maximumGoListOutput
	var stderr limitedBuffer
	stderr.remaining = maximumStderrOutput
	arguments := []string{"list", "-json"}
	if len(buildTags) > 0 {
		arguments = append(arguments, "-tags", strings.Join(buildTags, ","))
	}
	arguments = append(arguments, "./...")
	command := exec.CommandContext(ctx, goBinary, arguments...)
	command.Dir = absRoot
	command.Env = controlledGoEnvironment(absRoot)
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, contractError(CodeCanceled, "go", "package discovery canceled", ctxErr)
		}
		return nil, contractError(CodeToolFailure, "go", "go list failed: "+safeToolError(stderr.String()), err)
	}

	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	packages := make([]Package, 0, 32)
	for {
		var pkg Package
		err := decoder.Decode(&pkg)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, contractError(CodeToolFailure, "go", "invalid go list output", err)
		}
		if pkg.ImportPath == "" {
			return nil, contractError(CodeToolFailure, "go", "go list returned an empty import path", nil)
		}
		packages = append(packages, pkg)
	}
	if len(packages) == 0 {
		return nil, contractError(CodeToolFailure, "go", "go list returned no packages", nil)
	}
	return packages, nil
}

func controlledGoEnvironment(root string) []string {
	controlled := map[string]string{
		"GOARCH": runtime.GOARCH, "GOENV": "off", "GOFLAGS": "-mod=readonly",
		"GOOS": runtime.GOOS, "GOTELEMETRY": "off", "GOTOOLCHAIN": "local",
		"GOWORK": filepath.Join(root, "go.work"),
	}
	environment := make([]string, 0, len(os.Environ())+len(controlled))
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if _, replaced := controlled[name]; !found || replaced {
			continue
		}
		environment = append(environment, entry)
	}
	for name, value := range controlled {
		environment = append(environment, name+"="+value)
	}
	return environment
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	remaining int
}

func (w *limitedBuffer) Write(data []byte) (int, error) {
	if len(data) > w.remaining {
		return 0, fmt.Errorf("output exceeds configured limit")
	}
	w.remaining -= len(data)
	return w.buffer.Write(data)
}

func (w *limitedBuffer) Bytes() []byte  { return w.buffer.Bytes() }
func (w *limitedBuffer) String() string { return w.buffer.String() }

func safeToolError(message string) string {
	if len(message) > 512 {
		message = message[:512]
	}
	if message == "" {
		return "no diagnostic"
	}
	return message
}
