package openairesponses

import (
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	provider "github.com/ArronJablonowski/COH/internal/provider"
)

var _ provider.QualifiedAdapter = (*Adapter)(nil)

func TestAdapterHasNoBrokerActionProcessOrLoggingSurface(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"internal/broker", "internal/connector", "internal/transport", "os/exec", "log", "log/slog", "plugin"}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasSuffix(entry.Name(), "_test.go") || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			for _, denied := range forbidden {
				if path == denied || strings.Contains(path, "/"+denied+"/") {
					t.Fatalf("%s imports action-capable package %s", entry.Name(), path)
				}
			}
		}
	}
	adapter := reflect.TypeFor[*Adapter]()
	for _, name := range []string{"Execute", "Dispatch", "RunTool", "SubmitAction"} {
		if _, exists := adapter.MethodByName(name); exists {
			t.Fatalf("adapter exposes action method %s", name)
		}
	}
}

func TestCredentialMaterialIsPrivatelyOwned(t *testing.T) {
	typeOfCredential := reflect.TypeFor[Credential]()
	for index := range typeOfCredential.NumField() {
		if typeOfCredential.Field(index).IsExported() {
			t.Fatalf("credential exports field %s", typeOfCredential.Field(index).Name)
		}
	}
	credential := NewCredential([]byte(strings.Repeat("x", 32)))
	credential.destroy()
	if len(credential.value) != 0 {
		t.Fatal("credential was not destroyed")
	}
}
