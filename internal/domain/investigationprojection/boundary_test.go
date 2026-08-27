package investigationprojection

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProjectionPortsExposeOnlyNarrowDigestBoundRecords(t *testing.T) {
	ports := []any{(*AuthorityVerifier)(nil), (*FactStore)(nil), (*CheckpointStore)(nil), (*EvidenceBuilder)(nil)}
	seen := make(map[reflect.Type]struct{})
	for _, port := range ports {
		value := reflect.TypeOf(port).Elem()
		if value.NumMethod() == 0 || value.NumMethod() > 3 {
			t.Fatalf("%s method count=%d", value.Name(), value.NumMethod())
		}
		inspectProjectionType(t, value, seen)
	}
}

func inspectProjectionType(t *testing.T, value reflect.Type, seen map[reflect.Type]struct{}) {
	t.Helper()
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		value = value.Elem()
	}
	if value.Kind() == reflect.Func {
		for index := 0; index < value.NumIn(); index++ {
			inspectProjectionType(t, value.In(index), seen)
		}
		for index := 0; index < value.NumOut(); index++ {
			inspectProjectionType(t, value.Out(index), seen)
		}
		return
	}
	if value.PkgPath() != "github.com/ArronJablonowski/COH/internal/domain/investigationprojection" {
		return
	}
	if _, exists := seen[value]; exists {
		return
	}
	seen[value] = struct{}{}
	switch value.Kind() {
	case reflect.Interface:
		for index := 0; index < value.NumMethod(); index++ {
			inspectProjectionType(t, value.Method(index).Type, seen)
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			name := strings.ToLower(field.Name)
			for _, forbidden := range []string{"raw", "bytes", "content", "credential", "secret", "policysource", "grant",
				"filesystem", "url", "sql", "http", "network", "connector", "executor", "shell", "callback", "model"} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("%s exposes forbidden field %s", value.Name(), field.Name)
				}
			}
			fieldType := field.Type
			for fieldType.Kind() == reflect.Pointer || fieldType.Kind() == reflect.Slice || fieldType.Kind() == reflect.Array {
				fieldType = fieldType.Elem()
			}
			for _, forbiddenKind := range []reflect.Kind{reflect.Interface, reflect.Func, reflect.Chan, reflect.UnsafePointer} {
				if fieldType.Kind() == forbiddenKind {
					t.Fatalf("%s exposes forbidden field kind %s", value.Name(), fieldType.Kind())
				}
			}
			inspectProjectionType(t, field.Type, seen)
		}
	}
}

func TestProjectionProductionImportsNoAuthorityOrDirectIO(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"bytes": true, "context": true, "crypto/sha256": true, "encoding/hex": true,
		"encoding/json": true, "errors": true, "fmt": true, "io": true, "math": true, "reflect": true,
		"regexp": true, "slices": true, "strings": true, "sync": true, "time": true,
		"github.com/ArronJablonowski/COH/internal/helper/domaincontract": true}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range parsed.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if !allowed[path] {
				t.Fatalf("%s imports %s", entry.Name(), path)
			}
		}
		if ast.IsGenerated(parsed) {
			t.Fatalf("production boundary file must be reviewed, not generated: %s", entry.Name())
		}
	}
}
