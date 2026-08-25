package credentiallease

import (
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestCredentialLeaseHasNoNetworkProcessOrLoggingSurface(t *testing.T) {
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
		for _, imported := range leaseImportsOf(t, entry.Name()) {
			if denied[imported] {
				t.Errorf("%s imports forbidden lease-boundary package %q", entry.Name(), imported)
			}
		}
	}
}

func TestCapabilityMaterialHasNoExportedOrSerializableField(t *testing.T) {
	handle := reflect.TypeFor[Handle]()
	for index := range handle.NumField() {
		field := handle.Field(index)
		if field.IsExported() && field.Name != "LeaseID" {
			t.Errorf("Handle exports capability field %q", field.Name)
		}
	}
	record := reflect.TypeFor[Record]()
	for index := range record.NumField() {
		field := record.Field(index)
		if field.IsExported() && strings.Contains(strings.ToLower(field.Name), "token") {
			t.Errorf("Record exports capability field %q", field.Name)
		}
	}
}

func leaseImportsOf(t *testing.T, path string) []string {
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
