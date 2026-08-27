package splunk

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const publicRoot = "../../../contracts/splunk-discovery/v1"

func TestPublishedSplunkContractsDecodeExactly(t *testing.T) {
	config := mustRead(t, "fixtures/config.valid.json")
	if _, err := DecodeConfig(config); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeQualification(mustRead(t, "fixtures/qualification.snapshot.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDenialCorpus(mustRead(t, "fixtures/denial-corpus.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRedactedError(mustRead(t, "fixtures/redacted-error.trace.json")); err != nil {
		t.Fatal(err)
	}

	capability, err := queryconnector.DecodeCapability(context.Background(), mustRead(t, "fixtures/capability.snapshot.json"))
	if err != nil {
		t.Fatal(err)
	}
	value := capability.Value()
	if value.SourceID != "splunk-prod" || !slices.Equal(value.QueryLanguages, []string{"spl"}) ||
		!value.Features.ReadOnly || !value.Features.SchemaDiscovery || !value.Features.Validation ||
		value.Features.Polling || value.Features.Paging || value.Features.Cancellation || value.Features.Statistics {
		t.Fatalf("unexpected capability: %+v", value)
	}

	page, err := queryconnector.DecodeSchemaPage(context.Background(), mustRead(t, "fixtures/schema.page.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := []queryconnector.SchemaEntry{
		{ResourceID: "security-events", Name: "event.time", Type: "timestamp", Nullable: false},
		{ResourceID: "security-events", Name: "source.ip", Type: "ip", Nullable: true},
	}
	if !slices.Equal(page.Value().Entries, want) {
		t.Fatalf("unexpected schema: %+v", page.Value().Entries)
	}
}

func TestPublishedSplunkContractFilesAreBoundedAndSecretFree(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(publicRoot, "**", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	rootFiles, err := filepath.Glob(filepath.Join(publicRoot, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, rootFiles...)
	if len(files) != 10 {
		t.Fatalf("expected 10 JSON contracts and fixtures, got %d", len(files))
	}
	for _, path := range files {
		input, readErr := os.ReadFile(path)
		if readErr != nil || !json.Valid(input) || len(input) > maximumContractBytes {
			t.Fatalf("invalid public JSON %s: %v", path, readErr)
		}
		lower := strings.ToLower(string(input))
		for _, forbidden := range []string{"authorization: bearer", "authorization: splunk", "sessionkey", "auth/login", `"native_text":`, `"result_rows":`, `"vendor_body":`} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("%s exposes forbidden marker %q", path, forbidden)
			}
		}
	}
	for _, name := range []string{"splunk-discovery-config.schema.json", "splunk-qualification.schema.json", "splunk-denials.schema.json", "splunk-redacted-error.schema.json"} {
		var schema map[string]any
		if err := json.Unmarshal(mustRead(t, name), &schema); err != nil || schema["additionalProperties"] != false {
			t.Fatalf("schema %s is not closed: %v", name, err)
		}
	}
}

func TestStrictContractDecoding(t *testing.T) {
	base := mustRead(t, "fixtures/config.valid.json")
	duplicate := append([]byte(`{"schema_version":"coh.splunk-discovery-config/v1","schema_version":"coh.splunk-discovery-config/v1",`), base[1:]...)
	if _, err := DecodeConfig(duplicate); err == nil {
		t.Fatal("duplicate key accepted")
	}
	mutated := mutate(t, base, func(value map[string]any) { value["unexpected"] = true })
	if _, err := DecodeConfig(mutated); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestConfigDenialMutations(t *testing.T) {
	base := mustRead(t, "fixtures/config.valid.json")
	tests := []struct {
		name string
		edit func(map[string]any)
	}{
		{"cloud deployment", func(v map[string]any) { v["deployment"] = "cloud" }},
		{"unsafe internal index", func(v map[string]any) { v["resources"].([]any)[0].(map[string]any)["index"] = "_internal" }},
		{"wildcard index", func(v map[string]any) { v["resources"].([]any)[0].(map[string]any)["index"] = "security*" }},
		{"weakened denylist", func(v map[string]any) { v["denied_capabilities"] = v["denied_capabilities"].([]any)[1:] }},
		{"unsorted fields", func(v map[string]any) { f := v["fields"].([]any); f[0], f[1] = f[1], f[0] }},
		{"redirect-shaped endpoint", func(v map[string]any) { v["endpoint"] = "https://splunk.example.invalid/redirect" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeConfig(mutate(t, base, test.edit)); err == nil {
				t.Fatal("unsafe mutation accepted")
			}
		})
	}
}

func TestQualificationDenialMutations(t *testing.T) {
	base := mustRead(t, "fixtures/qualification.snapshot.json")
	for _, capability := range []string{"admin_all_objects", "indexes_edit", "output_file"} {
		t.Run(capability, func(t *testing.T) {
			input := mutate(t, base, func(v map[string]any) { v["capabilities"] = []any{capability, "search"} })
			if _, err := DecodeQualification(input); err == nil {
				t.Fatal("dangerous capability accepted")
			}
		})
	}
}

func TestEvidenceDenialMutations(t *testing.T) {
	errorFixture := mustRead(t, "fixtures/redacted-error.trace.json")
	if _, err := DecodeRedactedError(mutate(t, errorFixture, func(v map[string]any) { v["bearer_exposed"] = true })); err == nil {
		t.Fatal("secret exposure accepted")
	}
	denials := mustRead(t, "fixtures/denial-corpus.json")
	if _, err := DecodeDenialCorpus(mutate(t, denials, func(v map[string]any) { v["cases"] = v["cases"].([]any)[:1] })); err == nil {
		t.Fatal("undersized denial corpus accepted")
	}
}

func mustRead(t *testing.T, relative string) []byte {
	t.Helper()
	value, err := os.ReadFile(filepath.Join(publicRoot, relative))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mutate(t *testing.T, input []byte, edit func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	edit(value)
	output, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return output
}
