package opaengine

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFrozenPolicyContract(t *testing.T) {
	root := filepath.Join("..", "..", "..", "contracts", "policy", "v1")
	for _, name := range []string{"opa-policy-bundle.schema.json", "signed-opa-policy-bundle.schema.json",
		"policy-input.schema.json", "policy-output.schema.json"} {
		input, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err := json.Unmarshal(input, &schema); err != nil || schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" || schema["additionalProperties"] != false {
			t.Fatalf("%s is not a strict draft 2020-12 schema: %v", name, err)
		}
	}
	bundleInput, err := os.ReadFile(filepath.Join(root, "fixtures", "valid", "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bundle policyBundle
	decoder := json.NewDecoder(bytes.NewReader(bundleInput))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("bundle trailing data: %v", err)
	}
	if err := validateBundle(bundle); err != nil || bundle.PolicyRevision != 7 || len(bundle.Modules) != 1 {
		t.Fatalf("bundle = %+v, err = %v", bundle, err)
	}
	source, err := os.ReadFile(filepath.Join(root, "fixtures", "valid", "authz.rego"))
	if err != nil || strings.TrimSpace(string(source)) != strings.TrimSpace(allowPolicy) {
		t.Fatalf("policy source drift: %v", err)
	}
	if strings.TrimSpace(bundle.Modules[0].Source) != strings.TrimSpace(string(source)) {
		t.Fatal("bundle module differs from readable Rego fixture")
	}
}

func TestFrozenDenialCorpus(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "policy", "v1", "fixtures", "denial-corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		SchemaVersion string `json:"schema_version"`
		Cases         []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(input, &corpus); err != nil || corpus.SchemaVersion != "coh.policy-denial-corpus/v1" || len(corpus.Cases) != 24 {
		t.Fatalf("corpus identity/count: %+v, err = %v", corpus, err)
	}
	seen := make(map[string]bool, len(corpus.Cases))
	for _, test := range corpus.Cases {
		if test.Name == "" || test.Reason == "" || seen[test.Name] {
			t.Fatalf("invalid denial case %+v", test)
		}
		seen[test.Name] = true
	}
}

func TestCapabilitySetExcludesSideEffectsAndNondeterminism(t *testing.T) {
	capabilities := policyCapabilities()
	seen := make(map[string]bool, len(capabilities.Builtins))
	for _, builtin := range capabilities.Builtins {
		seen[builtin.Name] = true
	}
	for _, forbidden := range []string{"http.send", "net.lookup_ip_addr", "time.now_ns", "uuid.rfc4122", "rand.intn", "opa.runtime", "trace", "print"} {
		if seen[forbidden] {
			t.Fatalf("forbidden builtin %q is enabled", forbidden)
		}
	}
	if len(capabilities.AllowNet) != 0 || !seen["eq"] || !seen["internal.member_2"] {
		t.Fatalf("capability profile is not closed and usable: %+v", capabilities)
	}
}
