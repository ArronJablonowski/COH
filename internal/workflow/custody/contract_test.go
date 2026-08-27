package custody

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"testing"
)

func TestPublishedCustodySchemaIsStrictAndVersioned(t *testing.T) {
	definitions := custodySchemaDefinitions(t)
	for _, name := range []string{"case", "artifact", "evidence_reference", "head", "command",
		"authorization_request", "decision", "record", "receipt", "verification_report"} {
		object, ok := definitions[name].(map[string]any)
		if !ok || object["type"] != "object" || object["additionalProperties"] != false {
			t.Fatalf("definition %s is not a closed object", name)
		}
		properties, propertiesOK := object["properties"].(map[string]any)
		required, requiredOK := object["required"].([]any)
		if !propertiesOK || !requiredOK || len(properties) != len(required) {
			t.Fatalf("definition %s does not require every field", name)
		}
	}
	assertCustodyEnum(t, definitions, "operation", []string{"acquire", "access", "transform", "redact",
		"transfer", "export", "place_hold", "release_hold", "delete"})
	assertCustodyEnum(t, definitions, "phase", []string{"authorized", "completed"})
	assertCustodyEnum(t, definitions, "decision_outcome", []string{"allow", "deny"})
}

func TestCustodyPortsAndRecordsExposeNoExecutionOrSensitiveSurface(t *testing.T) {
	for _, value := range []any{EvidenceReference{}, Head{}, Command{}, CaseSnapshot{}, LifecycleReceiptSnapshot{},
		VerifiedEvidence{}, AuthorizationRequest{}, Decision{}, Record{}, Receipt{}, AuditProof{}, Result{},
		VerificationReport{}} {
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
		{reflect.TypeOf((*Authority)(nil)).Elem(), []string{"AuthorizeCustody"}},
		{reflect.TypeOf((*CaseStore)(nil)).Elem(), []string{"LoadCase", "ResolveLifecycleReceipt"}},
		{reflect.TypeOf((*EvidenceResolver)(nil)).Elem(), []string{"ResolveEvidence"}},
		{reflect.TypeOf((*Ledger)(nil)).Elem(), []string{"Append", "LoadHead", "Read", "Recover"}},
		{reflect.TypeOf((*Auditor)(nil)).Elem(), []string{"AppendCustodyEvent", "VerifyCustodyEvent"}},
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

func custodySchemaDefinitions(t *testing.T) map[string]any {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(source), "..", "..", "..", "contracts", "custody", "v1",
		"chain-of-custody.schema.json")
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
	return definitions
}

func assertCustodyEnum(t *testing.T, definitions map[string]any, name string, want []string) {
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
