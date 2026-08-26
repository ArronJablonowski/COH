package subagentdag

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestPublishedSubagentDAGSchemaIsStrictAndFrozen(t *testing.T) {
	schema := loadDAGSchema(t)
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema dialect=%v", schema["$schema"])
	}
	definitions, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema definitions missing")
	}
	objectDefinitions := []string{"case", "artifact", "limits", "claim", "finding", "structured_result",
		"cancellation_ack", "cancellation_record", "task", "edge", "receipt", "graph", "decision"}
	for _, name := range objectDefinitions {
		definition, valid := definitions[name].(map[string]any)
		if !valid || definition["type"] != "object" || definition["additionalProperties"] != false {
			t.Fatalf("definition %s is not a closed object: %+v", name, definition)
		}
	}
	assertDAGSchemaConst(t, definitions, "graph", "schema_version", SchemaVersion)
	assertDAGSchemaConst(t, definitions, "decision", "schema_version", DecisionSchemaVersion)
	assertDAGSchemaConst(t, definitions, "graph", "contract_version", ContractVersion)
	assertDAGSchemaConst(t, definitions, "decision", "contract_version", ContractVersion)

	wantRoles := []string{string(CoordinatorRole), string(AlertTriageRole), string(SIEMQueryRole),
		string(TimelineCorrelationRole), string(HuntingRole), string(CTIAttackRole), string(DetectionRole),
		string(VulnerabilityRole), string(ValidationRole), string(IRPlannerRole), string(ReviewerRole),
		string(ReportWriterRole)}
	assertDAGSchemaEnum(t, definitions["role"], wantRoles)
	wantOperations := []string{string(CreateGraph), string(Delegate), string(Execute), string(Cancel), string(Recover)}
	for _, definition := range []string{"receipt", "decision"} {
		properties := definitions[definition].(map[string]any)["properties"].(map[string]any)
		assertDAGSchemaEnum(t, properties["operation"], wantOperations)
	}
	result := definitions["structured_result"].(map[string]any)
	if _, ok = result["anyOf"].([]any); !ok {
		t.Fatal("structured result must require at least one claim or finding")
	}
}

func TestCanonicalWireFieldsExactlyMatchPublishedSubagentDAGSchema(t *testing.T) {
	definitions := loadDAGSchema(t)["$defs"].(map[string]any)
	values := map[string]any{
		"case": caseWire{}, "artifact": artifactWire{}, "limits": Limits{}, "claim": Claim{},
		"finding": Finding{}, "structured_result": structuredResultWire{},
		"cancellation_ack": CancellationAck{}, "cancellation_record": cancellationWire{},
		"task": taskWire{}, "edge": Edge{}, "receipt": Receipt{}, "graph": graphWire{},
		"decision": decisionWire{},
	}
	for name, value := range values {
		properties := definitions[name].(map[string]any)["properties"].(map[string]any)
		want := dagMapKeys(properties)
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]any
		if err = json.Unmarshal(encoded, &object); err != nil {
			t.Fatal(err)
		}
		if got := dagMapKeys(object); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s fields got=%v want=%v", name, got, want)
		}
	}
}

func loadDAGSchema(t *testing.T) map[string]any {
	t.Helper()
	input, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "workflow", "v1", "subagent-dag.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err = json.Unmarshal(input, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func assertDAGSchemaConst(t *testing.T, definitions map[string]any, definition, property string, want any) {
	t.Helper()
	properties := definitions[definition].(map[string]any)["properties"].(map[string]any)
	if got := properties[property].(map[string]any)["const"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("%s.%s const=%v want=%v", definition, property, got, want)
	}
}

func assertDAGSchemaEnum(t *testing.T, raw any, want []string) {
	t.Helper()
	values := raw.(map[string]any)["enum"].([]any)
	got := make([]string, len(values))
	for index, value := range values {
		got[index] = value.(string)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enum=%v want=%v", got, want)
	}
}

func dagMapKeys(value map[string]any) []string {
	result := make([]string, 0, len(value))
	for key := range value {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
