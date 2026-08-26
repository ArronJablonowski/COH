package memorynamespace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFrozenMemorySchemaDefinesClosedBoundaryRecords(t *testing.T) {
	path := filepath.Join("..", "..", "..", "contracts", "workflow", "v1", "memory-namespace.schema.json")
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err = json.Unmarshal(input, &schema); err != nil || schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema invalid: %v", err)
	}
	definitions, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("definitions missing")
	}
	for _, name := range []string{"scope", "artifact", "retention", "review", "put_request", "get_request", "access_request", "access_decision", "review_request", "review_decision", "record"} {
		definition, ok := definitions[name].(map[string]any)
		if !ok || definition["additionalProperties"] != false {
			t.Fatalf("%s is not closed", name)
		}
		required, requiredOK := definition["required"].([]any)
		properties, propertiesOK := definition["properties"].(map[string]any)
		if !requiredOK || !propertiesOK || len(required) != len(properties) {
			t.Fatalf("%s does not require every field", name)
		}
	}
}

func TestCanonicalDigestsBindScopeRetentionAndDeadline(t *testing.T) {
	request := validPut(SessionMemory, testNow)
	retention, _ := retentionDigest(request.Retention)
	access := AccessRequest{SchemaVersion: AccessSchemaVersion, ContractVersion: ContractVersion,
		RequestID: request.RequestID, ActorID: request.ActorID, Operation: Write,
		Namespace: request.Namespace, Scope: request.Scope, Key: request.Key, ValueDigest: request.Value.Digest,
		RetentionDigest: retention, PolicyDigest: request.PolicyDigest, Deadline: request.Deadline}
	first, err := AccessDigest(access)
	if err != nil {
		t.Fatal(err)
	}
	access.Scope.CaseID = testReviewer
	second, _ := AccessDigest(access)
	if first == second {
		t.Fatal("scope was not bound")
	}
	access.Scope = request.Scope
	access.Deadline = access.Deadline.Add(time.Second)
	third, _ := AccessDigest(access)
	if first == third {
		t.Fatal("deadline was not bound")
	}
	valueOne, _ := memoryValueDigest(artifactToWire(request.Value), request.ValueType)
	request.Value.Length++
	valueTwo, _ := memoryValueDigest(artifactToWire(request.Value), request.ValueType)
	if valueOne == valueTwo {
		t.Fatal("artifact metadata was not bound into the memory value digest")
	}
}
