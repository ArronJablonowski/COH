package skilldiscovery

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestFrozenDiscoverySchemaDefinesEveryBoundaryRecord(t *testing.T) {
	path := filepath.Join("..", "..", "..", "contracts", "skill", "v1", "skill-discovery.schema.json")
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(input, &schema); err != nil ||
		schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("discovery schema invalid: %v", err)
	}
	definitions, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema definitions missing")
	}
	for _, name := range []string{"search_request", "detail_request", "resource_request", "decision",
		"search_result", "detail_result", "resource_result", "record", "catalog_snapshot"} {
		definition, ok := definitions[name].(map[string]any)
		if !ok || definition["additionalProperties"] != false {
			t.Fatalf("%s is not a closed object", name)
		}
		required, ok := definition["required"].([]any)
		properties, propertiesOK := definition["properties"].(map[string]any)
		if !ok || !propertiesOK || len(required) != len(properties) {
			t.Fatalf("%s does not require every field", name)
		}
	}
}

func TestCanonicalIntentsAndDecisionsUseFrozenScopeAndTimestampWire(t *testing.T) {
	fixture := newTestFixture(t)
	request := fixture.search()
	canonical, err := canonicalValue(searchIntentWire{SchemaVersion: request.SchemaVersion,
		ContractVersion: request.ContractVersion, RequestID: request.RequestID,
		IdempotencyKey: request.IdempotencyKey, Case: caseToWire(request.Case), TaskID: request.TaskID,
		ActorID: request.ActorID, PolicyDigest: request.PolicyDigest,
		RequiredPermission: request.RequiredPermission, Query: request.Query, Limit: request.Limit,
		Cursor: request.Cursor, ExpectedSnapshotDigest: request.ExpectedSnapshotDigest,
		Deadline: formatTime(request.Deadline)})
	if err != nil || !bytes.Contains(canonical, []byte(`"organization_id"`)) ||
		bytes.Contains(canonical, []byte(`"OrganizationID"`)) ||
		!bytes.Contains(canonical, []byte(`.000000000Z`)) {
		t.Fatalf("canonical search wire drifted: %s %v", canonical, err)
	}
	first, err := intentDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	request.TaskID = testRequest2
	second, _ := intentDigest(request)
	if first == second {
		t.Fatal("intent digest did not bind task identity")
	}
}

func TestPublicDiscoveryRecordsMatchFrozenJSONFieldNames(t *testing.T) {
	assertJSONFields(t, reflect.TypeOf(SearchRequest{}), []string{"schema_version", "contract_version",
		"request_id", "idempotency_key", "case", "task_id", "actor_id", "policy_digest",
		"required_permission", "query", "limit", "cursor", "expected_snapshot_digest", "deadline"})
	assertJSONFields(t, reflect.TypeOf(DetailRequest{}), []string{"schema_version", "contract_version",
		"request_id", "idempotency_key", "case", "task_id", "actor_id", "policy_digest",
		"required_permission", "skill_name", "expected_manifest_digest", "search_idempotency_key",
		"expected_search_result_digest", "deadline"})
	assertJSONFields(t, reflect.TypeOf(ResourceRequest{}), []string{"schema_version", "contract_version",
		"request_id", "idempotency_key", "case", "task_id", "actor_id", "policy_digest",
		"required_permission", "skill_name", "expected_manifest_digest", "resource_name",
		"resource_digest", "detail_idempotency_key", "expected_detail_result_digest", "deadline"})
}

func TestCompactResultCannotCarryDetailsResourcesOrCapabilities(t *testing.T) {
	for _, value := range []any{CompactSkill{}, SearchResult{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			lower := strings.ToLower(field.Name)
			if strings.Contains(lower, "content") || strings.Contains(lower, "resource") ||
				strings.Contains(lower, "path") || strings.Contains(lower, "url") ||
				strings.Contains(lower, "secret") || strings.Contains(lower, "executor") ||
				field.Type.Kind() == reflect.Func || field.Type.Kind() == reflect.Interface {
				t.Fatalf("compact surface exposes %s", field.Name)
			}
		}
	}
}

func assertJSONFields(t *testing.T, typeOf reflect.Type, expected []string) {
	t.Helper()
	actual := make([]string, 0, typeOf.NumField())
	for index := 0; index < typeOf.NumField(); index++ {
		actual = append(actual, strings.Split(typeOf.Field(index).Tag.Get("json"), ",")[0])
	}
	slices.Sort(actual)
	wanted := slices.Clone(expected)
	slices.Sort(wanted)
	if !slices.Equal(actual, wanted) {
		t.Fatalf("%s fields = %v, want %v", typeOf.Name(), actual, wanted)
	}
}
