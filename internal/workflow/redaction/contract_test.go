package redaction

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestPublishedRedactionSchemaIsStrictAndVersioned(t *testing.T) {
	path := filepath.Join("..", "..", "..", "contracts", "redaction", "v1", "governed-redaction.schema.json")
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err = json.Unmarshal(input, &document); err != nil {
		t.Fatal(err)
	}
	definitions, ok := document["$defs"].(map[string]any)
	if !ok || document["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatal("redaction schema version or definitions missing")
	}
	for _, name := range []string{"command", "rule_set", "approved_plan", "mapping",
		"authorization_request", "decision", "record", "receipt"} {
		definition, found := definitions[name].(map[string]any)
		if !found || definition["additionalProperties"] != false {
			t.Fatalf("%s is not closed", name)
		}
	}
	assertRedactionEnum(t, definitions, "replacement_mode", []string{"remove", "mask", "token"})
	assertRedactionEnum(t, definitions, "decision_outcome", []string{"allow", "deny"})
}

func TestRedactionPortsAndRecordsExposeNoAuthorityOrSensitiveSurface(t *testing.T) {
	ports := []struct {
		typeOf  reflect.Type
		methods []string
	}{
		{reflect.TypeOf((*Authority)(nil)).Elem(), []string{"AuthorizeRedaction"}},
		{reflect.TypeOf((*ApprovalStore)(nil)).Elem(), []string{"AuthorizeUse", "VerifyUse"}},
		{reflect.TypeOf((*CaseStore)(nil)).Elem(), []string{"LoadCase"}},
		{reflect.TypeOf((*PlanStore)(nil)).Elem(), []string{"ResolvePlan", "ResolveRule"}},
		{reflect.TypeOf((*SourceResolver)(nil)).Elem(), []string{"ResolveSource"}},
		{reflect.TypeOf((*DerivedSource)(nil)).Elem(), []string{"ReadContext"}},
		{reflect.TypeOf((*Transformer)(nil)).Elem(), []string{"Derive"}},
		{reflect.TypeOf((*Publisher)(nil)).Elem(), []string{"Publish"}},
		{reflect.TypeOf((*CustodyRecorder)(nil)).Elem(), []string{"LoadCustodyHead", "RecordRedaction", "VerifyRedaction"}},
		{reflect.TypeOf((*Store)(nil)).Elem(), []string{"Advance", "Commit", "LoadProgress", "Recover"}},
		{reflect.TypeOf((*Auditor)(nil)).Elem(), []string{"AppendRedactionEvent", "VerifyRedactionEvent"}},
		{reflect.TypeOf((*Clock)(nil)).Elem(), []string{"Now"}},
	}
	for _, port := range ports {
		actual := make([]string, port.typeOf.NumMethod())
		for index := range actual {
			actual[index] = port.typeOf.Method(index).Name
		}
		sort.Strings(port.methods)
		if !reflect.DeepEqual(actual, port.methods) {
			t.Fatalf("%s methods=%v want=%v", port.typeOf, actual, port.methods)
		}
	}
	for _, value := range []any{Command{}, RuleSet{}, ApprovedPlan{}, Mapping{}, ApprovalUseRequest{}, ApprovalUseProof{},
		AuthorizationRequest{}, Decision{}, Record{}, Receipt{}, Progress{}, DerivationRequest{},
		Derivation{}, PublicationRequest{}, PublishedEvidence{}, CustodyRequest{}, CustodyProof{}} {
		assertSafeRedactionType(t, reflect.TypeOf(value), map[reflect.Type]bool{})
	}
}

func assertRedactionEnum(t *testing.T, definitions map[string]any, name string, want []string) {
	t.Helper()
	definition := definitions[name].(map[string]any)
	values := definition["enum"].([]any)
	actual := make([]string, len(values))
	for index := range values {
		actual[index] = values[index].(string)
	}
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("%s=%v want=%v", name, actual, want)
	}
}

func assertSafeRedactionType(t *testing.T, value reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	if value == nil || seen[value] {
		return
	}
	seen[value] = true
	for value.Kind() == reflect.Pointer || value.Kind() == reflect.Slice || value.Kind() == reflect.Array {
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return
	}
	for index := 0; index < value.NumField(); index++ {
		field := value.Field(index)
		name := strings.ToLower(field.Name)
		for _, forbidden := range []string{"credential", "secret", "policysource", "connector", "executor",
			"provider", "callback", "client", "path", "url", "commandline", "selectedtext", "replacementvalue"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("%s.%s exposes forbidden surface", value, field.Name)
			}
		}
		if field.Type.Kind() == reflect.Func || field.Type.Kind() == reflect.Chan || field.Type.Kind() == reflect.Map ||
			field.Type.Kind() == reflect.Interface {
			t.Fatalf("%s.%s exposes executable or generic surface", value, field.Name)
		}
		assertSafeRedactionType(t, field.Type, seen)
	}
}
