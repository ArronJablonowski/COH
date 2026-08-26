package evidenceingest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"
)

func TestPublishedIngestionSchemaIsStrictAndVersioned(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(source), "..", "..", "..", "contracts", "evidence", "v1",
		"immutable-cas-ingestion.schema.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err = json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatal("schema draft changed")
	}
	oneOf, ok := schema["oneOf"].([]any)
	if !ok || len(oneOf) != 6 {
		t.Fatalf("published record count=%d", len(oneOf))
	}
	definitions, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema definitions missing")
	}
	for _, name := range []string{"case", "artifact", "observed_time", "source_range", "source", "component",
		"transport", "command", "authorization_request", "decision", "artifact_manifest", "encrypted_object",
		"published_object", "receipt"} {
		object, objectOK := definitions[name].(map[string]any)
		if !objectOK || object["type"] != "object" || object["additionalProperties"] != false {
			t.Fatalf("definition %s is not a closed object", name)
		}
		properties, propertiesOK := object["properties"].(map[string]any)
		required, requiredOK := object["required"].([]any)
		if !propertiesOK || !requiredOK || len(properties) != len(required) {
			t.Fatalf("definition %s does not require every field", name)
		}
	}
	assertSchemaEnum(t, definitions, "status", []string{"staged", "verified", "published"})
	assertSchemaEnum(t, definitions, "transport_mode", []string{"in_process", "mtls"})
	assertSchemaEnum(t, definitions, "source_kind", []string{"upload", "connector", "query", "tool", "model", "derived", "import"})
	assertSchemaEnum(t, definitions, "component_kind", []string{"tool", "query", "model"})
}

func TestIngestionPortsAndRecordsExposeNoExecutionOrSecretSurface(t *testing.T) {
	for _, value := range []any{TransportContext{}, SourceInput{}, ComponentVersion{}, Command{},
		AuthorizationRequest{}, Decision{}, ArtifactManifest{}, EncryptedObject{}, PublishedObject{}, Receipt{}, Result{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			if field.Type.Kind() == reflect.Func || field.Type.Kind() == reflect.Interface {
				t.Fatalf("executable record field %s.%s", typeOf.Name(), field.Name)
			}
		}
	}
	ports := []struct {
		value reflect.Type
		want  []string
	}{
		{reflect.TypeOf((*Authority)(nil)).Elem(), []string{"AuthorizeIngestion"}},
		{reflect.TypeOf((*TransportVerifier)(nil)).Elem(), []string{"VerifyTransport"}},
		{reflect.TypeOf((*EncryptedCAS)(nil)).Elem(), []string{"Abandon", "Publish", "Resolve", "Stage", "Verify"}},
		{reflect.TypeOf((*ManifestStore)(nil)).Elem(), []string{"Commit", "Recover"}},
		{reflect.TypeOf((*Auditor)(nil)).Elem(), []string{"AppendAuditEvent"}},
		{reflect.TypeOf((*Clock)(nil)).Elem(), []string{"Now"}},
	}
	for _, port := range ports {
		if port.value.NumMethod() != len(port.want) {
			t.Fatalf("port %s methods=%d", port.value.Name(), port.value.NumMethod())
		}
		for index, name := range port.want {
			if port.value.Method(index).Name != name {
				t.Fatalf("port %s method[%d]=%s", port.value.Name(), index, port.value.Method(index).Name)
			}
		}
	}
}

func assertSchemaEnum(t *testing.T, definitions map[string]any, name string, want []string) {
	t.Helper()
	definition, ok := definitions[name].(map[string]any)
	if !ok {
		t.Fatalf("enum %s missing", name)
	}
	values, ok := definition["enum"].([]any)
	if !ok || len(values) != len(want) {
		t.Fatalf("enum %s invalid", name)
	}
	got := make([]string, 0, len(values))
	for _, value := range values {
		text, textOK := value.(string)
		if !textOK {
			t.Fatalf("enum %s has non-string value", name)
		}
		got = append(got, text)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("enum %s=%v want=%v", name, got, want)
	}
}
