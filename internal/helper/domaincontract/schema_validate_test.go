package domaincontract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

func TestValidatorAcceptsEveryRegisteredPositiveFixture(t *testing.T) {
	validator := loadTrackedValidator(t)
	files := []string{
		"workflow-payloads.valid.json",
		"evidence-analysis-payloads.valid.json",
		"authority-payloads.valid.json",
		"capability-risk-payloads.valid.json",
	}
	validated := make(map[string]struct{})
	for _, name := range files {
		var fixtures []json.RawMessage
		if err := json.Unmarshal(readFixture(t, name), &fixtures); err != nil {
			t.Fatal(err)
		}
		for _, fixture := range fixtures {
			document := wrapPayload(t, fixture)
			canonical, err := validator.Validate(context.Background(), document)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			value, _ := DecodeUnique(canonical)
			kind := value.(map[string]any)["kind"].(string)
			validated[kind] = struct{}{}
			if recovered, err := validator.Validate(context.Background(), canonical); err != nil || string(recovered) != string(canonical) {
				t.Fatalf("%s recovery changed canonical bytes: %v", kind, err)
			}
		}
	}
	if len(validated) != 16 {
		t.Fatalf("validated %d kinds, want 16", len(validated))
	}
}

func TestValidatorDeniesPayloadViolations(t *testing.T) {
	validator := loadTrackedValidator(t)
	var fixtures []json.RawMessage
	if err := json.Unmarshal(readFixture(t, "workflow-payloads.valid.json"), &fixtures); err != nil {
		t.Fatal(err)
	}
	var casePayload map[string]any
	if err := json.Unmarshal(fixtures[1], &casePayload); err != nil {
		t.Fatal(err)
	}
	data := casePayload["data"].(map[string]any)
	mutations := []func(map[string]any){
		func(value map[string]any) { value["extra"] = true },
		func(value map[string]any) { value["classification"] = "BAD TOKEN" },
		func(value map[string]any) { value["retention_policy_id"] = "0198d6c4-2222-6222-8222-222222222222" },
		func(value map[string]any) { value["state"] = "invalid" },
		func(value map[string]any) { delete(value, "state") },
	}
	for index, mutate := range mutations {
		copy := make(map[string]any, len(data))
		for name, value := range data {
			copy[name] = value
		}
		mutate(copy)
		payload, err := json.Marshal(map[string]any{"kind": "case", "data": copy})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validator.Validate(context.Background(), wrapPayload(t, payload)); !errors.Is(err, ErrDenied) {
			t.Fatalf("case %d err=%v", index, err)
		}
	}
}

func TestValidatorDeniesTrackedPayloadExamples(t *testing.T) {
	validator := loadTrackedValidator(t)
	positives := loadPositivePayloads(t)
	value, err := DecodeUnique(readFixture(t, "payload-denials.json"))
	if err != nil {
		t.Fatal(err)
	}
	denials := value.([]any)
	seen := make(map[string]struct{}, len(denials))
	for _, rawDenial := range denials {
		denial := rawDenial.(map[string]any)
		name := denial["name"].(string)
		kind := denial["kind"].(string)
		positive, exists := positives[kind]
		if !exists {
			t.Fatalf("%s: positive fixture missing", kind)
		}
		payload := cloneObject(t, positive)
		data := payload["data"].(map[string]any)
		property := denial["property"].(string)
		switch denial["operation"] {
		case "add", "replace":
			data[property] = denial["value"]
		case "remove":
			delete(data, property)
		default:
			t.Fatalf("%s: unsupported fixture operation", name)
		}
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validator.Validate(context.Background(), wrapPayload(t, encoded)); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s: err=%v", name, err)
		}
		seen[kind] = struct{}{}
	}
	if len(denials) != 16 || len(seen) != 16 {
		t.Fatalf("denials=%d kinds=%d, want 16 each", len(denials), len(seen))
	}
}

func TestValidatorPreservesCancellation(t *testing.T) {
	validator := loadTrackedValidator(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := validator.Validate(ctx, readFixture(t, "envelope.valid.json")); !errors.Is(err, ErrCancelled) {
		t.Fatalf("Validate() err=%v", err)
	}
}

func TestLoadValidatorRejectsUnknownSchemaSemantics(t *testing.T) {
	registry, err := os.ReadFile("../../../contracts/domain/v1/contract-registry.json")
	if err != nil {
		t.Fatal(err)
	}
	schema, err := os.ReadFile("../../../contracts/domain/v1/workflow-payloads.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	schema = []byte(strings.Replace(string(schema), `"type": "object"`, `"type": "object", "format": "opaque"`, 1))
	fileSystem := fstest.MapFS{
		"contract-registry.json":                 {Data: registry},
		"workflow-payloads.schema.json":          {Data: schema},
		"evidence-analysis-payloads.schema.json": {Data: readContractFile(t, "evidence-analysis-payloads.schema.json")},
		"authority-payloads.schema.json":         {Data: readContractFile(t, "authority-payloads.schema.json")},
		"capability-risk-payloads.schema.json":   {Data: readContractFile(t, "capability-risk-payloads.schema.json")},
	}
	if _, err := LoadValidator(fileSystem); !errors.Is(err, ErrInvalidSchema) {
		t.Fatalf("LoadValidator() err=%v", err)
	}
}

func loadTrackedValidator(t *testing.T) *Validator {
	t.Helper()
	validator, err := LoadValidator(os.DirFS("../../../contracts/domain/v1"))
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func readContractFile(t *testing.T, name string) []byte {
	t.Helper()
	input, err := os.ReadFile("../../../contracts/domain/v1/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func loadPositivePayloads(t *testing.T) map[string]map[string]any {
	t.Helper()
	result := make(map[string]map[string]any)
	for _, name := range []string{"workflow-payloads.valid.json", "evidence-analysis-payloads.valid.json", "authority-payloads.valid.json", "capability-risk-payloads.valid.json"} {
		value, err := DecodeUnique(readFixture(t, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, rawPayload := range value.([]any) {
			payload := rawPayload.(map[string]any)
			result[payload["kind"].(string)] = payload
		}
	}
	return result
}

func cloneObject(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeUnique(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded.(map[string]any)
}

func wrapPayload(t *testing.T, payload []byte) []byte {
	t.Helper()
	var fixture struct {
		Kind string          `json:"kind"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatal(err)
	}
	kind, err := json.Marshal(fixture.Kind)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(fmt.Sprintf(`{"schema":"coh.domain/v1","kind":%s,"id":"0198d6c4-7618-7d31-8e0a-9da53cae8ca2","organization_id":"0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e","tenant_id":"0198d6c4-22dc-7b3c-af2c-75c1b8eb4f16","case_id":"0198d6c4-7618-7d31-8e0a-9da53cae8ca2","revision":1,"created_at":"2026-08-21T20:00:00.000000000Z","data":%s}`, kind, fixture.Data))
}
