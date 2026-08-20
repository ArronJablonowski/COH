package architecture

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeCanonicalizeAndDigest(t *testing.T) {
	contract := loadContractFixture(t)
	first, err := CanonicalBytes(contract)
	if err != nil {
		t.Fatalf("CanonicalBytes() error = %v", err)
	}
	reparsed, err := DecodeContract(first)
	if err != nil {
		t.Fatalf("DecodeContract(canonical) error = %v", err)
	}
	second, err := CanonicalBytes(reparsed)
	if err != nil {
		t.Fatalf("CanonicalBytes(reparsed) error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("canonical serialization is not idempotent")
	}
	digest, err := Digest(contract)
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	if len(digest) != 64 {
		t.Fatalf("Digest() length = %d, want 64", len(digest))
	}
}

func TestDecodeContractRejectsNegativeFixtures(t *testing.T) {
	tests := []struct {
		name string
		code ErrorCode
	}{
		{name: "malformed.json", code: CodeInvalidInput},
		{name: "unknown-field.json", code: CodeInvalidInput},
		{name: "unsupported-version.json", code: CodeUnsupportedVersion},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := readFixture(t, "invalid", test.name)
			_, err := DecodeContract(data)
			assertErrorCode(t, err, test.code)
		})
	}
}

func TestValidateContractDeniesPolicyWeakening(t *testing.T) {
	contract := loadContractFixture(t)
	for index := range contract.Boundaries {
		if contract.Boundaries[index].Name == "domain" {
			contract.Boundaries[index].MayImport = append(contract.Boundaries[index].MayImport, "transport")
		}
	}
	err := ValidateContract(contract)
	assertErrorCode(t, err, CodeDenied)
}

func TestValidateContractRejectsNonSemanticVersion(t *testing.T) {
	contract := loadContractFixture(t)
	contract.ContractVersion = "1.0.01"
	err := ValidateContract(contract)
	assertErrorCode(t, err, CodeInvalidInput)
}

func TestValidateContractEnforcesSchemaPurposeLength(t *testing.T) {
	contract := loadContractFixture(t)
	contract.Boundaries[0].Purpose = strings.Repeat("界", 241)
	err := ValidateContract(contract)
	assertErrorCode(t, err, CodeInvalidInput)
}

func TestSchemaBundleIsValidJSON(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixturesRoot(t), "..", "workspace-contract.schema.json"))
	if err != nil {
		t.Fatalf("ReadFile(schema) error = %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("schema is not JSON: %v", err)
	}
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("unexpected schema dialect: %v", schema["$schema"])
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("schema properties object is missing")
	}
	assertSchemaConst(t, properties, "schema_version", SchemaVersion)
	assertSchemaConst(t, properties, "canonicalization", Canonicalization)
	assertSchemaConst(t, properties, "go_baseline", BaselineGoVersion)
	assertSchemaConst(t, properties, "module", ModulePath)
	boundaries, ok := properties["boundaries"].(map[string]any)
	if !ok || boundaries["minItems"] != float64(len(requiredBoundaries)) || boundaries["maxItems"] != float64(len(requiredBoundaries)) {
		t.Fatalf("schema boundary cardinality is not %d: %#v", len(requiredBoundaries), boundaries)
	}
}

func FuzzDecodeContract(f *testing.F) {
	f.Add(readFixture(f, "valid", "workspace-contract.canonical.json"))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not-json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		contract, err := DecodeContract(data)
		if err != nil {
			var contractErr *ContractError
			if !errors.As(err, &contractErr) {
				t.Fatalf("untyped error: %v", err)
			}
			return
		}
		if _, err := CanonicalBytes(contract); err != nil {
			t.Fatalf("accepted contract cannot canonicalize: %v", err)
		}
	})
}

func assertSchemaConst(t *testing.T, properties map[string]any, field string, want any) {
	t.Helper()
	property, ok := properties[field].(map[string]any)
	if !ok || property["const"] != want {
		t.Fatalf("schema %s const = %v, want %v", field, property["const"], want)
	}
}

func loadContractFixture(t *testing.T) Contract {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixturesRoot(t), "..", "workspace-contract.json"))
	if err != nil {
		t.Fatalf("ReadFile(contract) error = %v", err)
	}
	contract, err := DecodeContract(data)
	if err != nil {
		t.Fatalf("DecodeContract() error = %v", err)
	}
	return contract
}

func readFixture(t testing.TB, class, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixturesRoot(t), class, name))
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", name, err)
	}
	return data
}

func fixturesRoot(t testing.TB) string {
	t.Helper()
	root := filepath.Join("..", "..", "..", "contracts", "architecture", "v1", "fixtures")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture root: %v", err)
	}
	return root
}

func assertErrorCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var contractErr *ContractError
	if !errors.As(err, &contractErr) {
		t.Fatalf("error = %v, want *ContractError", err)
	}
	if contractErr.Code != want {
		t.Fatalf("error code = %q, want %q", contractErr.Code, want)
	}
}
