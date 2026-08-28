package sentinel

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const contractRoot = "../../../contracts/sentinel-discovery/v1"

func TestPublishedContractsDecodeExactly(t *testing.T) {
	config := readFixture(t, "config.valid.json")
	if _, err := DecodeConfig(config); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeMetadata(readFixture(t, "metadata.snapshot.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeQualification(readFixture(t, "qualification.snapshot.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeDenialCorpus(readFixture(t, "denial-corpus.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRedactedError(readFixture(t, "redacted-error.trace.json")); err != nil {
		t.Fatal(err)
	}
	capability, err := queryconnector.DecodeCapability(context.Background(), readFixture(t, "capability.snapshot.json"))
	if err != nil || !capability.Value().Features.ReadOnly || !capability.Value().Features.SchemaDiscovery ||
		!capability.Value().Features.Validation || capability.Value().Features.Polling || capability.Value().Features.Paging ||
		capability.Value().Features.Cancellation || capability.Value().Features.Statistics {
		t.Fatalf("capability=%+v err=%v", capability.Value(), err)
	}
	page, err := queryconnector.DecodeSchemaPage(context.Background(), readFixture(t, "schema.page.json"))
	if err != nil || !page.Value().Complete || len(page.Value().Entries) != 4 {
		t.Fatalf("page=%+v err=%v", page.Value(), err)
	}
}

func TestPublishedSnapshotDigestsAreExact(t *testing.T) {
	var metadata Metadata
	if err := json.Unmarshal(readFixture(t, "metadata.snapshot.json"), &metadata); err != nil {
		t.Fatal(err)
	}
	if want := metadataDigest(metadata); metadata.Digest != want {
		t.Fatalf("metadata digest=%s want=%s", metadata.Digest, want)
	}
	var qualification Qualification
	if err := json.Unmarshal(readFixture(t, "qualification.snapshot.json"), &qualification); err != nil {
		t.Fatal(err)
	}
	if want := qualificationDigest(qualification); qualification.Digest != want {
		t.Fatalf("qualification digest=%s want=%s", qualification.Digest, want)
	}
}

func TestContractsRejectUnknownDuplicateAndUnsafeValues(t *testing.T) {
	config := readFixture(t, "config.valid.json")
	if _, err := DecodeConfig(append([]byte(`{"schema_version":"coh.sentinel-discovery-config/v1",`), config[1:]...)); err == nil {
		t.Fatal("duplicate key accepted")
	}
	mutations := []func(map[string]any){
		func(value map[string]any) { value["unexpected"] = true },
		func(value map[string]any) { value["endpoint"] = "https://management.azure.com" },
		func(value map[string]any) { value["token_audience"] = "https://management.azure.com/.default" },
		func(value map[string]any) { value["workspace_id"] = "../../other" },
	}
	for _, mutate := range mutations {
		if _, err := DecodeConfig(mutateJSON(t, config, mutate)); err == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
	metadata := readFixture(t, "metadata.snapshot.json")
	if _, err := DecodeMetadata(mutateJSON(t, metadata, func(value map[string]any) {
		value["tables"].([]any)[0].(map[string]any)["timespan_column"] = "Missing"
	})); err == nil {
		t.Fatal("missing timespan column accepted")
	}
	errorTrace := readFixture(t, "redacted-error.trace.json")
	if _, err := DecodeRedactedError(mutateJSON(t, errorTrace, func(value map[string]any) {
		value["bearer_exposed"] = true
	})); err == nil {
		t.Fatal("bearer exposure accepted")
	}
}

func TestContractFilesAreBoundedStrictAndSecretFree(t *testing.T) {
	fixtures, err := filepath.Glob(filepath.Join(contractRoot, "fixtures", "*.json"))
	if err != nil || len(fixtures) != 7 {
		t.Fatalf("fixtures=%d err=%v", len(fixtures), err)
	}
	schemas, err := filepath.Glob(filepath.Join(contractRoot, "*.schema.json"))
	if err != nil || len(schemas) != 5 {
		t.Fatalf("schemas=%d err=%v", len(schemas), err)
	}
	for _, path := range append(fixtures, schemas...) {
		input, readErr := os.ReadFile(path)
		if readErr != nil || !json.Valid(input) || len(input) > maximumContractBytes {
			t.Fatalf("invalid contract %s: %v", path, readErr)
		}
		lower := strings.ToLower(string(input))
		for _, secret := range []string{"client_secret", "access_token", "refresh_token", "authorization: bearer", "private_key"} {
			if strings.Contains(lower, secret) {
				t.Fatalf("contract %s exposes %q", path, secret)
			}
		}
	}
	for _, path := range schemas {
		var value map[string]any
		input, _ := os.ReadFile(path)
		if json.Unmarshal(input, &value) != nil || value["additionalProperties"] != false {
			t.Fatalf("schema is not closed: %s", path)
		}
	}
}

func TestDenialCorpusReferencesExecutableTests(t *testing.T) {
	corpus, err := DecodeDenialCorpus(readFixture(t, "denial-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	for _, path := range paths {
		input, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		source.Write(input)
	}
	for _, item := range corpus.Cases {
		if !strings.Contains(source.String(), "func "+item.CoveredBy+"(") {
			t.Errorf("denial %s references missing %s", item.Class, item.CoveredBy)
		}
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	input, err := os.ReadFile(filepath.Join(contractRoot, "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func mutateJSON(t *testing.T, input []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
