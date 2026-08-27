package evidencepackage

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestImportWorkerPortsExposeOnlyOpaqueForwardStreams(t *testing.T) {
	ports := []struct {
		value   any
		methods []string
	}{
		{(*InputStore)(nil), []string{"OpenInput"}},
		{(*ArtifactSink)(nil), []string{"StageArtifact"}},
		{(*ProofVerifier)(nil), []string{"VerifyExportProof"}},
		{(*Clock)(nil), []string{"Now"}},
	}
	for _, port := range ports {
		typeOf := reflect.TypeOf(port.value).Elem()
		actual := make([]string, typeOf.NumMethod())
		for index := range actual {
			actual[index] = typeOf.Method(index).Name
		}
		sort.Strings(port.methods)
		if !reflect.DeepEqual(actual, port.methods) {
			t.Fatalf("%s methods=%v want=%v", typeOf, actual, port.methods)
		}
	}
}

func TestImportWorkerHasNoWebPathArchiveNetworkOrExecutionImports(t *testing.T) {
	root := packageDirectory(t)
	forbidden := []string{"archive/", "compress/", "net", "net/", "net/http", "os", "os/exec",
		"path", "path/filepath", "plugin", "syscall"}
	checkProductionImports(t, root, func(file, imported string) {
		for _, candidate := range forbidden {
			if imported == candidate || strings.HasPrefix(imported, candidate) {
				t.Errorf("%s imports forbidden worker capability %q", file, imported)
			}
		}
	})
}

func TestWebAndCommandPackagesCannotParseEvidencePackages(t *testing.T) {
	repository := filepath.Clean(filepath.Join(packageDirectory(t), "..", "..", ".."))
	for _, directory := range []string{"internal/transport", "internal/command"} {
		checkProductionImports(t, filepath.Join(repository, directory), func(file, imported string) {
			if strings.HasSuffix(imported, "/internal/workflow/evidencepackage") {
				t.Errorf("%s imports isolated package parser %q", file, imported)
			}
		})
	}
}

func checkProductionImports(t *testing.T, root string, check func(string, string)) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, spec := range parsed.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			check(path, imported)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func packageDirectory(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("worker package location unavailable")
	}
	return filepath.Dir(file)
}
