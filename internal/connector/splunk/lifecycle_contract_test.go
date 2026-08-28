package splunk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const lifecycleContractRoot = "../../../contracts/splunk-lifecycle/v1"

func TestPublishedLifecycleContractsDecodeExactly(t *testing.T) {
	fixtures := []struct {
		name   string
		decode func([]byte) error
	}{
		{"lifecycle-policy.json", func(input []byte) error { _, err := DecodeLifecyclePolicy(input); return err }},
		{"sid-ownership.json", func(input []byte) error { _, err := DecodeSIDOwnership(input); return err }},
		{"job-status.done.json", func(input []byte) error { _, err := DecodeJobStatus(input); return err }},
		{"result-envelope.json", func(input []byte) error { _, err := DecodeResultEnvelope(input); return err }},
		{"cancellation-proof.json", func(input []byte) error { _, err := DecodeCancellationProof(input); return err }},
		{"denial-corpus.json", func(input []byte) error { _, err := DecodeLifecycleDenialCorpus(input); return err }},
		{"redacted-error.trace.json", func(input []byte) error { _, err := DecodeLifecycleRedactedError(input); return err }},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			if err := fixture.decode(readLifecycleFixture(t, fixture.name)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLifecycleContractsDenyUnknownDuplicateAndUnsafeValues(t *testing.T) {
	policy := readLifecycleFixture(t, "lifecycle-policy.json")
	if _, err := DecodeLifecyclePolicy(append([]byte(`{"schema_version":"coh.splunk-lifecycle-policy/v1",`), policy[1:]...)); err == nil {
		t.Fatal("duplicate key accepted")
	}
	if _, err := DecodeLifecyclePolicy(mutateLifecycle(t, policy, func(value map[string]any) { value["unexpected"] = true })); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := DecodeLifecyclePolicy(mutateLifecycle(t, policy, func(value map[string]any) { value["allow_previews"] = true })); err == nil {
		t.Fatal("preview policy accepted")
	}
	for field, changed := range map[string]any{"maximum_page_rows": 999, "minimum_poll_interval_millis": 499,
		"cancellation_wait_millis": 4999} {
		if _, err := DecodeLifecyclePolicy(mutateLifecycle(t, policy, func(value map[string]any) { value[field] = changed })); err == nil {
			t.Fatalf("mutable lifecycle bound accepted: %s", field)
		}
	}
	status := readLifecycleFixture(t, "job-status.done.json")
	if _, err := DecodeJobStatus(mutateLifecycle(t, status, func(value map[string]any) { value["real_time"] = true })); err == nil {
		t.Fatal("real-time status accepted")
	}
	if _, err := DecodeJobStatus(mutateLifecycle(t, status, func(value map[string]any) { value["state"] = "MYSTERY" })); err == nil {
		t.Fatal("unknown state accepted")
	}
	result := readLifecycleFixture(t, "result-envelope.json")
	if _, err := DecodeResultEnvelope(mutateLifecycle(t, result, func(value map[string]any) { value["truncated"] = true })); err == nil {
		t.Fatal("truncated result accepted")
	}
	ownership := readLifecycleFixture(t, "sid-ownership.json")
	if _, err := DecodeSIDOwnership(mutateLifecycle(t, ownership, func(value map[string]any) { value["sid_exposed"] = true })); err == nil {
		t.Fatal("SID exposure accepted")
	}
}

func TestLifecycleContractFilesAreBoundedAndSecretFree(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(lifecycleContractRoot, "fixtures", "*.json"))
	if err != nil || len(files) != 7 {
		t.Fatalf("fixtures=%d err=%v", len(files), err)
	}
	for _, path := range files {
		input, readErr := os.ReadFile(path)
		if readErr != nil || !json.Valid(input) || len(input) > maximumContractBytes {
			t.Fatalf("invalid fixture %s: %v", path, readErr)
		}
	}
	schemas, err := filepath.Glob(filepath.Join(lifecycleContractRoot, "*.schema.json"))
	if err != nil || len(schemas) != 7 {
		t.Fatalf("schemas=%d err=%v", len(schemas), err)
	}
	for _, path := range schemas {
		var schema map[string]any
		input, readErr := os.ReadFile(path)
		if readErr != nil || json.Unmarshal(input, &schema) != nil || schema["additionalProperties"] != false {
			t.Fatalf("schema is not closed: %s", path)
		}
	}
}

func TestLifecycleDenialCorpusReferencesExecutableTests(t *testing.T) {
	corpus, err := DecodeLifecycleDenialCorpus(readLifecycleFixture(t, "denial-corpus.json"))
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
	for _, denial := range corpus.Cases {
		if !strings.Contains(source.String(), "func "+denial.CoveredBy+"(") {
			t.Errorf("denial %s references missing %s", denial.Class, denial.CoveredBy)
		}
	}
}

func readLifecycleFixture(t *testing.T, name string) []byte {
	t.Helper()
	input, err := os.ReadFile(filepath.Join(lifecycleContractRoot, "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func mutateLifecycle(t *testing.T, input []byte, edit func(map[string]any)) []byte {
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
