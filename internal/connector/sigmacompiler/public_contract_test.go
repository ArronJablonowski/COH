package sigmacompiler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestPublicContractFixtures(t *testing.T) {
	request := testRequest()
	response := testResponse(request)
	tests := []struct {
		name string
		file string
		want any
		load func([]byte) (any, error)
	}{
		{"request", "compile-request.json", request, func(input []byte) (any, error) { return DecodeCompileRequest(input) }},
		{"response", "compile-response.compiled.json", response, func(input []byte) (any, error) { return DecodeCompileResponse(input) }},
		{"needs mapping", "compile-response.needs-mapping.json", testNeedsMappingResponse(request), func(input []byte) (any, error) { return DecodeCompileResponse(input) }},
		{"capability", "capability-snapshot.json", testCapability(), func(input []byte) (any, error) { return DecodeCapabilitySnapshot(input) }},
		{"attestation", "helper-attestation.json", testAttestation(request.HelperIdentityExpectation), func(input []byte) (any, error) { return DecodeHelperAttestation(input) }},
		{"provenance", "provenance-receipt.json", testProvenance(request, response), func(input []byte) (any, error) { return DecodeProvenanceReceipt(input) }},
		{"denials", "denial-corpus.json", testDenials(), func(input []byte) (any, error) { return DecodeDenialCorpus(input) }},
		{"trace", "redacted-error-trace.json", testTrace(request.RequestDigest), func(input []byte) (any, error) { return DecodeRedactedTrace(input) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := test.load(readContractFixture(t, test.file))
			if err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("fixture differs from typed canonical value")
			}
		})
	}
}

func TestPublicSchemasAreClosedJSONObjects(t *testing.T) {
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
		input, err := os.ReadFile(filepath.Join(contractRoot(t), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var schema any
		if err := json.Unmarshal(input, &schema); err != nil {
			t.Fatalf("%s invalid JSON: %v", entry.Name(), err)
		}
		assertClosedObjects(t, entry.Name(), schema)
	}
	if count != 7 {
		t.Fatalf("schema count = %d, want 7", count)
	}
}

func TestHelperWireProtocolExcludesAuthorityAndExecutionSurfaces(t *testing.T) {
	for _, file := range []string{"compile-request.json", "compile-response.compiled.json"} {
		var value any
		if err := json.Unmarshal(readContractFixture(t, file), &value); err != nil {
			t.Fatal(err)
		}
		keys := map[string]bool{}
		collectKeys(value, keys)
		for _, forbidden := range []string{"actor", "authorization", "audit", "bearer", "credential", "endpoint", "environment", "executable", "path", "secret"} {
			for key := range keys {
				if strings.Contains(key, forbidden) {
					t.Fatalf("%s exposes forbidden helper key %q", file, key)
				}
			}
		}
	}
}

func collectKeys(value any, keys map[string]bool) {
	switch node := value.(type) {
	case map[string]any:
		for key, child := range node {
			keys[key] = true
			collectKeys(child, keys)
		}
	case []any:
		for _, child := range node {
			collectKeys(child, keys)
		}
	}
}

func assertClosedObjects(t *testing.T, path string, value any) {
	t.Helper()
	switch node := value.(type) {
	case map[string]any:
		if node["type"] == "object" && node["additionalProperties"] != false {
			t.Fatalf("%s contains open object schema", path)
		}
		for key, child := range node {
			assertClosedObjects(t, path+"/"+key, child)
		}
	case []any:
		for _, child := range node {
			assertClosedObjects(t, path, child)
		}
	}
}

func readContractFixture(t *testing.T, name string) []byte {
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
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", "contracts", "pysigma-helper", "v1"))
}
