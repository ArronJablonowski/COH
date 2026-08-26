package approvalfingerprint

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ArronJablonowski/COH/internal/policy"
)

func TestFrozenContractSchemaAndCorpus(t *testing.T) {
	root := filepath.Join("..", "..", "..", "contracts", "approval", "v1")
	schemaInput, err := os.ReadFile(filepath.Join(root, "approval-fingerprint.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaInput, &schema); err != nil ||
		schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" ||
		schema["additionalProperties"] != false {
		t.Fatalf("schema = %+v, err = %v", schema, err)
	}
	var corpus struct {
		SchemaVersion string `json:"schema_version"`
		Cases         []struct {
			Name   string `json:"name"`
			Reason string `json:"reason"`
		} `json:"cases"`
	}
	readJSON(t, filepath.Join(root, "fixtures", "denial-corpus.json"), &corpus)
	if corpus.SchemaVersion != "coh.approval-fingerprint-denial-corpus/v1" || len(corpus.Cases) != 25 {
		t.Fatalf("corpus identity/count = %+v", corpus)
	}
	seen := map[string]bool{}
	for _, test := range corpus.Cases {
		if test.Name == "" || test.Reason == "" || seen[test.Name] {
			t.Fatalf("invalid denial case = %+v", test)
		}
		seen[test.Name] = true
	}
}

func TestDecodeStrictBoundedAndDetached(t *testing.T) {
	path := filepath.Join("..", "..", "..", "contracts", "approval", "v1", "fixtures", "valid", "approval-fingerprint.json")
	input, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(t.Context(), input)
	if err != nil || decoded.FingerprintDigest !=
		"sha256:b28588e9813dfaa8413ba76190afdd78831a332a22a1baa577b3fa840df4d1f3" {
		t.Fatalf("decoded = %+v, err = %v", decoded, err)
	}
	cases := [][]byte{
		bytes.Replace(input, []byte(`"contract_version":"1.0.0"`),
			[]byte(`"contract_version":"1.0.0","contract_version":"1.0.0"`), 1),
		bytes.Replace(input, []byte(`"contract_version":"1.0.0"`),
			[]byte(`"contract_version":"1.0.0","unexpected":true`), 1),
		bytes.Replace(input, []byte(`"maximum_use_count":1`), []byte(`"maximum_use_count":0`), 1),
		[]byte(strings.Repeat("x", maximumInputBytes+1)),
	}
	for index, candidate := range cases {
		if _, err := Decode(t.Context(), candidate); policy.Reason(err) != "fingerprint_contract" {
			t.Fatalf("case %d err = %v", index, err)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Decode(canceled, input); policy.Code(err) != policy.Canceled {
		t.Fatalf("canceled err = %v", err)
	}
}
