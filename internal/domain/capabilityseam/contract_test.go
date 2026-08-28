package capabilityseam

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const fixtureRoot = "../../../contracts/capability-seam/v1/fixtures/"

func TestBundleCanonicalDigestAndOwnedValues(t *testing.T) {
	input := readFixture(t, "bundle.valid.json")
	validated, err := DecodeBundle(context.Background(), input)
	if err != nil {
		t.Fatalf("decode bundle: %v", err)
	}
	const expected = "sha256:45c616f106bfc777c2f78679998f6fc3927473f3740279a0c0f401dab5c9d74b"
	if validated.Digest() != expected {
		t.Fatalf("digest = %s, want %s", validated.Digest(), expected)
	}
	canonicalAgain, err := DecodeBundle(context.Background(), validated.CanonicalBytes())
	if err != nil || canonicalAgain.Digest() != expected {
		t.Fatalf("canonical replay: digest=%s err=%v", canonicalAgain.Digest(), err)
	}
	first := validated.Value()
	first.Definitions[0].Permissions[0] = "mutated"
	first.Providers[0].Qualification.RecordDigest = strings.Repeat("x", 71)
	second := validated.Value()
	if second.Definitions[0].Permissions[0] != "model.infer" ||
		second.Providers[0].Qualification.RecordDigest != "sha256:"+strings.Repeat("4", 64) {
		t.Fatal("validated bundle leaked mutable state")
	}
	bytesCopy := validated.CanonicalBytes()
	bytesCopy[0] = '['
	if validated.CanonicalBytes()[0] != '{' {
		t.Fatal("validated bundle leaked canonical byte storage")
	}
}

func TestGraphCanonicalDigestAndTamperDenial(t *testing.T) {
	input := readFixture(t, "graph.valid.json")
	validated, err := DecodeGraph(context.Background(), input)
	if err != nil {
		t.Fatalf("decode graph: %v", err)
	}
	const expected = "sha256:69ce0b42803ca408b1f84a27e71bc489baf106d98a27aa5eff7da65a8a031e9d"
	if validated.Digest() != expected || validated.Value().GraphDigest != expected {
		t.Fatalf("graph digest mismatch: %s", validated.Digest())
	}
	tampered := mutateDocument(t, input, func(value map[string]any) {
		value["graph_digest"] = "sha256:" + strings.Repeat("8", 64)
	})
	if _, err := DecodeGraph(context.Background(), tampered); Code(err) != Denied || Reason(err) != "graph_digest" {
		t.Fatalf("tampered graph: code=%s reason=%s err=%v", Code(err), Reason(err), err)
	}
}

func TestStrictBundleDenialCorpus(t *testing.T) {
	valid := readFixture(t, "bundle.valid.json")
	tests := []struct {
		name   string
		input  func() []byte
		code   ErrorCode
		reason string
	}{
		{"duplicate_json_member", func() []byte {
			return bytes.Replace(valid, []byte(`  "schema_version":`),
				[]byte(`  "schema_version":"coh.capability-seam-bundle/v1", "schema_version":`), 1)
		}, InvalidInput, "document_decoding"},
		{"missing_required_member", func() []byte {
			return mutateDocument(t, valid, func(value map[string]any) { delete(value, "bundle_id") })
		}, InvalidInput, "document_shape"},
		{"unknown_member", func() []byte {
			return mutateDocument(t, valid, func(value map[string]any) { value["extra"] = true })
		}, InvalidInput, "document_decoding"},
		{"unsupported_contract", func() []byte {
			return mutateDocument(t, valid, func(value map[string]any) { value["contract_version"] = "2.0.0" })
		}, Unsupported, "unsupported_contract"},
		{"unsorted_permissions", func() []byte {
			return mutateDefinition(t, valid, func(value map[string]any) {
				value["permissions"] = []any{"z.read", "a.read"}
			})
		}, InvalidInput, "definition"},
		{"replaceable_authority", func() []byte {
			return mutateDefinition(t, valid, func(value map[string]any) { value["authority_class"] = "authority" })
		}, Denied, "authority_replaceable"},
		{"provider_artifact_drift", func() []byte {
			return mutateProvider(t, valid, func(value map[string]any) {
				qualification := value["qualification"].(map[string]any)
				qualification["provider_artifact_digest"] = "sha256:" + strings.Repeat("8", 64)
			})
		}, InvalidInput, "qualification"},
		{"profile_drift", func() []byte {
			return mutateProvider(t, valid, func(value map[string]any) {
				qualification := value["qualification"].(map[string]any)
				qualification["profile_digest"] = "sha256:" + strings.Repeat("9", 64)
			})
		}, InvalidInput, "qualification"},
		{"revoked_without_revision", func() []byte {
			return mutateProvider(t, valid, func(value map[string]any) {
				qualification := value["qualification"].(map[string]any)
				qualification["status"] = "revoked"
			})
		}, InvalidInput, "qualification"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeBundle(context.Background(), test.input())
			if Code(err) != test.code || Reason(err) != test.reason {
				t.Fatalf("code=%s reason=%s err=%v", Code(err), Reason(err), err)
			}
		})
	}
	assertDenialCorpusNames(t, tests)
}

func TestDecodeHonorsContext(t *testing.T) {
	//lint:ignore SA1012 This is the contract's explicit nil-context denial case.
	if _, err := DecodeBundle(nil, []byte(`{}`)); Code(err) != InvalidInput || Reason(err) != "context_required" {
		t.Fatalf("nil context: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecodeBundle(canceled, readFixture(t, "bundle.valid.json")); Code(err) != Canceled {
		t.Fatalf("canceled context: %v", err)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile(fixtureRoot + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mutateDocument(t *testing.T, input []byte, mutate func(map[string]any)) []byte {
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

func mutateDefinition(t *testing.T, input []byte, mutate func(map[string]any)) []byte {
	return mutateDocument(t, input, func(value map[string]any) {
		mutate(value["definitions"].([]any)[0].(map[string]any))
	})
}

func mutateProvider(t *testing.T, input []byte, mutate func(map[string]any)) []byte {
	return mutateDocument(t, input, func(value map[string]any) {
		mutate(value["providers"].([]any)[0].(map[string]any))
	})
}

func assertDenialCorpusNames(t *testing.T, tests []struct {
	name   string
	input  func() []byte
	code   ErrorCode
	reason string
}) {
	t.Helper()
	var corpus struct {
		Cases []struct {
			Name string `json:"name"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(readFixture(t, "denial-corpus.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	want := make(map[string]bool, len(corpus.Cases))
	for _, item := range corpus.Cases {
		want[item.Name] = true
	}
	for _, test := range tests {
		if !want[test.name] {
			t.Fatalf("executable denial %q is absent from corpus", test.name)
		}
		delete(want, test.name)
	}
	delete(want, "graph_digest_tamper")
	if len(want) != 0 {
		t.Fatalf("denial corpus cases lack executable tests: %v", want)
	}
}
