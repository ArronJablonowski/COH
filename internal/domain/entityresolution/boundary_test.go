package entityresolution

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

func TestNarrowPortsExposeNoUnsafeSurface(t *testing.T) {
	ports := []any{(*EvidenceVerifier)(nil), (*MatchVerifier)(nil), (*AuthorizationVerifier)(nil),
		(*ObservationStore)(nil), (*EntityStore)(nil), (*CandidateStore)(nil), (*DurableStore)(nil), (*AuditBuilder)(nil),
		(*ProvenanceBuilder)(nil), (*Clock)(nil)}
	seen := make(map[reflect.Type]struct{})
	for _, port := range ports {
		typeOf := reflect.TypeOf(port).Elem()
		if typeOf.NumMethod() == 0 || typeOf.NumMethod() > 5 {
			t.Fatalf("%s method count=%d", typeOf.Name(), typeOf.NumMethod())
		}
		inspectType(t, typeOf, seen)
	}
}

func inspectType(t *testing.T, value reflect.Type, seen map[reflect.Type]struct{}) {
	t.Helper()
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		value = value.Elem()
	}
	if value.Kind() == reflect.Func {
		for index := 0; index < value.NumIn(); index++ {
			inspectType(t, value.In(index), seen)
		}
		for index := 0; index < value.NumOut(); index++ {
			inspectType(t, value.Out(index), seen)
		}
		return
	}
	if value.PkgPath() != "github.com/ArronJablonowski/COH/internal/domain/entityresolution" {
		return
	}
	if _, exists := seen[value]; exists {
		return
	}
	seen[value] = struct{}{}
	switch value.Kind() {
	case reflect.Interface:
		for index := 0; index < value.NumMethod(); index++ {
			inspectType(t, value.Method(index).Type, seen)
		}
	case reflect.Struct:
		for index := 0; index < value.NumField(); index++ {
			field := value.Field(index)
			name := strings.ToLower(field.Name)
			for _, forbidden := range []string{"rawidentifier", "identifiertext", "identifierbytes", "evidencebytes",
				"content", "credential", "secret", "policysource", "filesystem", "url", "sql", "http",
				"networkclient", "connector", "executor", "shell", "callback", "model"} {
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
			inspectType(t, field.Type, seen)
		}
	}
}

func TestProductionPackageImportsNoAuthorityOrDirectIO(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Clean(entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		allowed := map[string]bool{
			"bytes": true, "context": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true,
			"errors": true, "fmt": true, "io": true, "math": true, "reflect": true, "regexp": true, "slices": true, "strconv": true, "strings": true, "time": true,
			"github.com/ArronJablonowski/COH/internal/domain/mappingregistry": true,
			"github.com/ArronJablonowski/COH/internal/helper/domaincontract":  true,
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
