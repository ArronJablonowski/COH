package splunkparser

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPublicContractFixtures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		file string
		load func([]byte) error
	}{
		{"definition", "definition.valid.json", func(input []byte) error { _, err := DecodeDefinition(input); return err }},
		{"plan", "plan.snapshot.json", func(input []byte) error { _, err := DecodePlan(input); return err }},
		{"decision", "policy-decision.allowed.json", func(input []byte) error { _, err := DecodePolicyDecision(input); return err }},
		{"registry", "command-registry.json", func(input []byte) error { _, err := DecodeCommandRegistry(input); return err }},
		{"denials", "denial-corpus.json", func(input []byte) error { _, err := DecodeDenialCorpus(input); return err }},
		{"audit", "redacted-audit.json", func(input []byte) error { _, err := DecodeRedactedAudit(input); return err }},
		{"revocation", "revocation.json", func(input []byte) error { _, err := DecodeRevocationEvidence(input); return err }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.load(readFixture(t, test.file)); err != nil {
				t.Fatalf("decode canonical fixture: %v", err)
			}
		})
	}
}

func TestPublicSchemasAreClosedJSONObjects(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(contractRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		count++
		var schema map[string]any
		input, err := os.ReadFile(filepath.Join(contractRoot(t), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(input, &schema); err != nil {
			t.Fatalf("%s is invalid JSON: %v", entry.Name(), err)
		}
		if schema["type"] != "object" || schema["additionalProperties"] != false {
			t.Fatalf("%s must be a closed object schema", entry.Name())
		}
		if _, ok := schema["required"].([]any); !ok {
			t.Fatalf("%s must declare required properties", entry.Name())
		}
	}
	if count != 7 {
		t.Fatalf("schema count = %d, want 7", count)
	}
}

func TestStrictDecoderRejectsUnknownDuplicateAndTrailingData(t *testing.T) {
	t.Parallel()
	base := readFixture(t, "definition.valid.json")
	unknown := strings.Replace(string(base), "{", `{"unknown":true,`, 1)
	duplicate := strings.Replace(string(base), `"source_id": "splunk_security",`, `"source_id":"duplicate","source_id": "splunk_security",`, 1)
	for name, input := range map[string][]byte{
		"unknown":   []byte(unknown),
		"duplicate": []byte(duplicate),
		"trailing":  append(append([]byte(nil), base...), []byte(" true")...),
	} {
		if _, err := DecodeDefinition(input); err == nil {
			t.Fatalf("%s document accepted", name)
		}
	}
}

func TestRegistryCannotBeWeakened(t *testing.T) {
	t.Parallel()
	var registry CommandRegistry
	if err := json.Unmarshal(readFixture(t, "command-registry.json"), &registry); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*CommandRegistry){
		"add command":        func(value *CommandRegistry) { value.AllowedCommands = append(value.AllowedCommands, "collect") },
		"remove prohibition": func(value *CommandRegistry) { value.ProhibitedCommands = value.ProhibitedCommands[1:] },
		"reorder": func(value *CommandRegistry) {
			value.AllowedCommands[0], value.AllowedCommands[1] = value.AllowedCommands[1], value.AllowedCommands[0]
		},
		"enable macros": func(value *CommandRegistry) { value.MacrosAllowed = true },
	}
	for name, mutate := range mutations {
		candidate := registry
		candidate.AllowedCommands = append([]string(nil), registry.AllowedCommands...)
		candidate.ProhibitedCommands = append([]CommandRule(nil), registry.ProhibitedCommands...)
		mutate(&candidate)
		candidate.Digest = RegistryDigest(candidate)
		if _, err := DecodeCommandRegistry(marshal(t, candidate)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestDefinitionRejectsUnsafeMappings(t *testing.T) {
	t.Parallel()
	var definition Definition
	if err := json.Unmarshal(readFixture(t, "definition.valid.json"), &definition); err != nil {
		t.Fatal(err)
	}
	unsafeIndex := definition
	unsafeIndex.Resources = append([]ResourceRule(nil), definition.Resources...)
	unsafeIndex.Resources[0].VendorIndex = "*"
	unsafeField := definition
	unsafeField.Fields = append([]FieldRule(nil), definition.Fields...)
	unsafeField.Fields[0].VendorName = "bad field"
	unsorted := definition
	unsorted.Fields = append([]FieldRule(nil), definition.Fields...)
	unsorted.Fields[0], unsorted.Fields[1] = unsorted.Fields[1], unsorted.Fields[0]
	for name, candidate := range map[string]Definition{"index": unsafeIndex, "field": unsafeField, "order": unsorted} {
		if _, err := DecodeDefinition(marshal(t, candidate)); err == nil {
			t.Fatalf("unsafe %s accepted", name)
		}
	}
}

func TestPlanRejectsUnsafeOrUnboundValues(t *testing.T) {
	t.Parallel()
	var plan Plan
	if err := json.Unmarshal(readFixture(t, "plan.snapshot.json"), &plan); err != nil {
		t.Fatal(err)
	}
	backtick := plan
	backtick.CanonicalSPL += " `macro`"
	unbound := plan
	unbound.Authority.AuthorizationDigest = ""
	oversize := plan
	oversize.MaximumBytes = MaximumDocumentBytes + 1
	for name, candidate := range map[string]Plan{"backtick": backtick, "authority": unbound, "limit": oversize} {
		if _, err := DecodePlan(marshal(t, candidate)); err == nil {
			t.Fatalf("unsafe %s accepted", name)
		}
	}
}

func TestSelfDigestsDetectTampering(t *testing.T) {
	t.Parallel()
	var decision PolicyDecision
	if err := json.Unmarshal(readFixture(t, "policy-decision.allowed.json"), &decision); err != nil {
		t.Fatal(err)
	}
	decision.ActorID = "018f0000-0000-7000-8000-000000000004"
	if _, err := DecodePolicyDecision(marshal(t, decision)); err == nil {
		t.Fatal("tampered decision accepted")
	}
}

func TestZeroExposureAndRevocationAreFailClosed(t *testing.T) {
	t.Parallel()
	var audit RedactedAudit
	if err := json.Unmarshal(readFixture(t, "redacted-audit.json"), &audit); err != nil {
		t.Fatal(err)
	}
	audit.VendorBodyExposed = true
	if _, err := DecodeRedactedAudit(marshal(t, audit)); err == nil {
		t.Fatal("audit exposing vendor body accepted")
	}
	var revocation RevocationEvidence
	if err := json.Unmarshal(readFixture(t, "revocation.json"), &revocation); err != nil {
		t.Fatal(err)
	}
	revocation.ExecutionPermitted = true
	if _, err := DecodeRevocationEvidence(marshal(t, revocation)); err == nil {
		t.Fatal("revoked execution accepted")
	}
}

func TestDenialCorpusRequiresUniqueBoundedCases(t *testing.T) {
	t.Parallel()
	var corpus DenialCorpus
	if err := json.Unmarshal(readFixture(t, "denial-corpus.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	corpus.Cases = corpus.Cases[:23]
	if _, err := DecodeDenialCorpus(marshal(t, corpus)); err == nil {
		t.Fatal("undersized corpus accepted")
	}
}

func TestFixtureDigests(t *testing.T) {
	var registry CommandRegistry
	if err := json.Unmarshal(readFixture(t, "command-registry.json"), &registry); err != nil {
		t.Fatal(err)
	}
	if registry.Digest == "DIGEST_PENDING" {
		t.Fatalf("registry digest pending; expected %s", RegistryDigest(registry))
	}
	var decision PolicyDecision
	if err := json.Unmarshal(readFixture(t, "policy-decision.allowed.json"), &decision); err != nil {
		t.Fatal(err)
	}
	if decision.Digest == "DIGEST_PENDING" {
		t.Fatalf("decision digest pending; expected %s", DecisionDigest(decision))
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	input, err := os.ReadFile(filepath.Join(contractRoot(t), "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func contractRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", "contracts", "splunk-parser", "v1"))
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
