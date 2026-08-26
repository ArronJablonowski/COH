package retrievalguard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestPublishedSchemaIsStrictAndMatchesFrozenContract(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "workflow", "v1", "retrieval-inspection.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err = json.Unmarshal(input, &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema dialect=%v", schema["$schema"])
	}
	definitions, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema definitions missing")
	}
	for _, name := range []string{"case", "artifact", "source", "profile", "request", "decision", "finding", "inspection", "record"} {
		definition, ok := definitions[name].(map[string]any)
		if !ok || definition["type"] != "object" || definition["additionalProperties"] != false {
			t.Fatalf("definition %s is not a closed object: %+v", name, definition)
		}
	}
	assertSchemaConst(t, definitions, "request", "schema_version", RequestSchemaVersion)
	assertSchemaConst(t, definitions, "decision", "schema_version", DecisionSchemaVersion)
	assertSchemaConst(t, definitions, "record", "schema_version", RecordSchemaVersion)
	for _, name := range []string{"request", "decision", "record"} {
		assertSchemaConst(t, definitions, name, "contract_version", ContractVersion)
	}
	assertSchemaConst(t, definitions, "source", "trust", string(UntrustedContent))
	assertSchemaConst(t, definitions, "inspection", "trust", string(UntrustedContent))
	assertSchemaConst(t, definitions, "inspection", "complete", true)

	wantKinds := []string{string(LogSource), string(DocumentSource), string(FeedSource), string(QueryOutputSource), string(ToolOutputSource), string(ToolErrorSource), string(MemorySource), string(ReportSource), string(AttachmentSource)}
	wantFindings := []string{string(InstructionLike), string(ScopeChangeAttempt), string(AuthorizationForgery), string(CredentialRequest), string(ToolDirective), string(ExfiltrationAttempt), string(ActiveContent), string(EncodedPayload), string(SecretRedacted)}
	assertSchemaEnum(t, definitions, "source_kind", wantKinds)
	finding := definitions["finding"].(map[string]any)
	properties := finding["properties"].(map[string]any)
	assertRawEnum(t, "finding.code", properties["code"], wantFindings)
}

func TestCanonicalWireFieldsMatchPublishedSchema(t *testing.T) {
	request := validRequest(testNow)
	inspection := validInspection(request)
	decision := Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		DecisionID: testDecision, DecisionDigest: digest("decision", nil), RequestDigest: digest("request", nil),
		Case: request.Case, TaskID: request.TaskID, ActorID: request.ActorID, ActorRevision: request.ActorRevision,
		PolicyDigest: request.PolicyDigest, RevocationDigest: digest("revocation", nil), Outcome: "allow",
		ReasonCode: "inspection_allowed", Revision: 1, IssuedAt: testNow, ExpiresAt: testNow.Add(1)}
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion, Request: request,
		IntentDigest: digest("intent", nil), IdempotencyDigest: digest("idempotency", nil),
		DecisionDigest: decision.DecisionDigest, RevocationDigest: decision.RevocationDigest,
		Inspection: inspection, AuditEventDigest: digest("audit", nil), PreviousProvenanceDigest: request.Source.ProvenanceDigest,
		ProvenanceDigest: digest("provenance", nil), CreatedAt: testNow, Revision: 1}

	for name, value := range map[string]any{
		"request": requestToWire(request), "decision": decisionToWire(decision),
		"inspection": inspectionToWire(inspection), "record": recordToWire(record),
	} {
		assertWireFields(t, name, value)
	}
}

func assertWireFields(t *testing.T, definition string, value any) {
	t.Helper()
	input, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "workflow", "v1", "retrieval-inspection.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err = json.Unmarshal(input, &schema); err != nil {
		t.Fatal(err)
	}
	definitions := schema["$defs"].(map[string]any)
	want := mapKeys(definitions[definition].(map[string]any)["properties"].(map[string]any))
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err = json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	got := mapKeys(object)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s fields got=%v want=%v", definition, got, want)
	}
}

func assertSchemaConst(t *testing.T, definitions map[string]any, definition, property string, want any) {
	t.Helper()
	object := definitions[definition].(map[string]any)
	properties := object["properties"].(map[string]any)
	got := properties[property].(map[string]any)["const"]
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s.%s const=%v want=%v", definition, property, got, want)
	}
}

func assertSchemaEnum(t *testing.T, definitions map[string]any, definition string, want []string) {
	t.Helper()
	assertRawEnum(t, definition, definitions[definition], want)
}

func assertRawEnum(t *testing.T, name string, raw any, want []string) {
	t.Helper()
	values := raw.(map[string]any)["enum"].([]any)
	got := make([]string, len(values))
	for index, value := range values {
		got[index] = value.(string)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s enum=%v want=%v", name, got, want)
	}
}

func mapKeys(value map[string]any) []string {
	result := make([]string, 0, len(value))
	for key := range value {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
