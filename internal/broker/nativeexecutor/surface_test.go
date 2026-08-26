package nativeexecutor

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionSurfaceHasNoGenericExecutionOrNetworkPrimitive(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[string]bool{"net": true, "net/http": true, "plugin": true}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), "_test.go") || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(".", entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if forbidden[path] {
				t.Fatalf("production file %s imports forbidden generic primitive %s", entry.Name(), path)
			}
			if path == "os/exec" && entry.Name() != "sandbox_unix.go" && entry.Name() != "sandbox_monitor_unix.go" {
				t.Fatalf("production file %s imports process execution outside the bounded sandbox", entry.Name())
			}
		}
		ast.Inspect(file, func(ast.Node) bool { return true })
		data, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, forbiddenText := range []string{"/bin/sh", "bash", "docker.sock", "http.Client"} {
			if strings.Contains(string(data), forbiddenText) {
				t.Fatalf("production file %s contains forbidden generic surface %q", entry.Name(), forbiddenText)
			}
		}
	}
}
