package secretresolver

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const secretResolverImport = "github.com/ArronJablonowski/COH/internal/broker/secretresolver"

func TestSecretResolverHasNoNetworkProcessOrLoggingSurface(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	denied := map[string]bool{
		"log": true, "log/slog": true, "net": true, "net/http": true,
		"os/exec": true, "runtime": true, "syscall": true,
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		for _, imported := range importsOf(t, entry.Name()) {
			if denied[imported] {
				t.Errorf("%s imports forbidden credential-boundary package %q", entry.Name(), imported)
			}
		}
	}
}

func TestOnlyBrokerProductionCodeImportsSecretResolver(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		for _, imported := range importsOf(t, path) {
			if imported != secretResolverImport {
				continue
			}
			relative, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			if !strings.HasPrefix(filepath.ToSlash(relative), "internal/broker/") {
				t.Errorf("non-broker production file imports secret resolver: %s", relative)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func importsOf(t *testing.T, path string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	imports := make([]string, 0, len(file.Imports))
	for _, imported := range file.Imports {
		value, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			t.Fatal(unquoteErr)
		}
		imports = append(imports, value)
	}
	return imports
}
