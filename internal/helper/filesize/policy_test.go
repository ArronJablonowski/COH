package filesize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestDecodePolicyCanonicalAndStrict(t *testing.T) {
	data := readPolicyFixture(t, "valid/file-size-policy.canonical.json")
	policy, err := DecodePolicy(data)
	if err != nil {
		t.Fatalf("DecodePolicy() error = %v", err)
	}
	canonical, err := CanonicalPolicy(policy)
	if err != nil {
		t.Fatalf("CanonicalPolicy() error = %v", err)
	}
	if !bytes.Equal(canonical, bytes.TrimSuffix(data, []byte{'\n'})) {
		t.Fatalf("canonical policy differs\n got: %s\nwant: %s", canonical, data)
	}
	if digest, err := PolicyDigest(policy); err != nil || !digestPattern.MatchString(digest) {
		t.Fatalf("PolicyDigest() = %q, %v", digest, err)
	}
}

func TestDecodePolicyRejectsMalformedAndWeakenedInputs(t *testing.T) {
	valid := string(readPolicyFixture(t, "valid/file-size-policy.canonical.json"))
	policyWithGenerator := validPolicy()
	policyWithGenerator.Exceptions = []Exception{validException("contracts/large.schema.json", "schema")}
	withGenerator, err := CanonicalPolicy(policyWithGenerator)
	if err != nil {
		t.Fatalf("CanonicalPolicy() error = %v", err)
	}
	cases := map[string][]byte{
		"empty":           nil,
		"invalid_utf8":    append([]byte(valid), 0xff),
		"duplicate":       []byte(strings.Replace(valid, `"schema_version":`, `"schema_version":"coh.file-size-policy/v1","schema_version":`, 1)),
		"case_variant":    []byte(strings.Replace(valid, `"schema_version"`, `"Schema_Version"`, 1)),
		"trailing":        []byte(valid + `{}`),
		"unknown":         readPolicyFixture(t, "invalid/unknown-field.json"),
		"weakened":        readPolicyFixture(t, "invalid/weakened-threshold.json"),
		"oversize":        bytes.Repeat([]byte{' '}, MaximumPolicySize+1),
		"null_exceptions": []byte(strings.Replace(valid, `"exceptions":[]`, `"exceptions":null`, 1)),
		"null_generator":  bytes.Replace(withGenerator, []byte(`"generator":"coh-test-generator"`), []byte(`"generator":null`), 1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePolicy(input); err == nil {
				t.Fatal("DecodePolicy() accepted invalid input")
			}
		})
	}
}

func TestValidatePolicyExceptionContract(t *testing.T) {
	nullExceptions := validPolicy()
	nullExceptions.Exceptions = nil
	if err := ValidatePolicy(nullExceptions); err == nil {
		t.Fatal("ValidatePolicy() accepted a nil exceptions slice")
	}
	valid := validPolicy()
	valid.Exceptions = []Exception{validException("scripts/legacy.sh", "script")}
	if err := ValidatePolicy(valid); err != nil {
		t.Fatalf("ValidatePolicy(valid exception) error = %v", err)
	}
	cases := map[string]func(*Exception){
		"absolute":        func(value *Exception) { value.Path = "/tmp/leak.sh" },
		"traversal":       func(value *Exception) { value.Path = "scripts/../leak.sh" },
		"backslash":       func(value *Exception) { value.Path = `scripts\leak.sh` },
		"glob":            func(value *Exception) { value.Path = "scripts/*.sh" },
		"newline":         func(value *Exception) { value.Path = "scripts/a\nb.sh" },
		"category":        func(value *Exception) { value.Category = "handwritten" },
		"owner":           func(value *Exception) { value.Owner = " x " },
		"justification":   func(value *Exception) { value.Justification = "too short" },
		"date":            func(value *Exception) { value.ExpiresOn = "2026-02-30" },
		"issue":           func(value *Exception) { value.TrackingIssue = "CYB-0" },
		"uppercase_hash":  func(value *Exception) { value.ContentSHA256 = strings.Repeat("A", 64) },
		"low_max":         func(value *Exception) { value.ApprovedMaxPhysicalLines = 300 },
		"high_max":        func(value *Exception) { value.ApprovedMaxPhysicalLines = MaximumApproved + 1 },
		"script_over_800": func(value *Exception) { value.ApprovedMaxPhysicalLines = 801 },
		"oversize_path":   func(value *Exception) { value.Path = strings.Repeat("p", MaximumPathSize+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			policy := validPolicy()
			exception := validException("scripts/legacy.sh", "script")
			mutate(&exception)
			policy.Exceptions = []Exception{exception}
			if err := ValidatePolicy(policy); err == nil {
				t.Fatal("ValidatePolicy() accepted invalid exception")
			}
		})
	}
}

func TestPolicySchemaMatchesExecutablePathAndExceptionBounds(t *testing.T) {
	data, err := os.ReadFile("../../../contracts/file-size/v1/file-size-policy.schema.json")
	if err != nil {
		t.Fatalf("ReadFile(schema) error = %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("Unmarshal(schema) error = %v", err)
	}
	definitions := schema["$defs"].(map[string]any)
	exception := definitions["exception"].(map[string]any)
	properties := exception["properties"].(map[string]any)
	path := properties["path"].(map[string]any)
	if path["maxLength"] != float64(MaximumPathSize) {
		t.Fatalf("schema path maxLength=%v", path["maxLength"])
	}
	conditions := exception["allOf"].([]any)[0].(map[string]any)
	thenProperties := conditions["then"].(map[string]any)["properties"].(map[string]any)
	approved := thenProperties["approved_max_physical_lines"].(map[string]any)
	if approved["maximum"] != float64(HardLimit) {
		t.Fatalf("schema script maximum=%v", approved["maximum"])
	}
	elseRule := conditions["else"].(map[string]any)
	required := elseRule["required"].([]any)
	if len(required) != 1 || required[0] != "generator" {
		t.Fatalf("schema generator requirement=%v", required)
	}
	if !safePolicyPath(strings.Repeat("p", MaximumPathSize)) || safePolicyPath(strings.Repeat("p", MaximumPathSize+1)) ||
		safePolicyPath("scripts/../escape.sh") {
		t.Fatal("runtime path boundary diverges from the published schema contract")
	}
}

func TestValidatePolicyRejectsOrderDuplicateAndCaseCollision(t *testing.T) {
	for name, exceptions := range map[string][]Exception{
		"order": {
			validException("scripts/z.sh", "script"), validException("scripts/a.sh", "script"),
		},
		"duplicate": {
			validException("scripts/a.sh", "script"), validException("scripts/a.sh", "script"),
		},
		"case_collision": {
			validException("scripts/A.sh", "script"), validException("scripts/a.sh", "script"),
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := validPolicy()
			policy.Exceptions = exceptions
			if err := ValidatePolicy(policy); err == nil {
				t.Fatal("ValidatePolicy() accepted invalid exception ordering")
			}
		})
	}
}

func TestContextErrorCodes(t *testing.T) {
	if code := CodeOf(contextError(context.Canceled, "test")); code != CodeCanceled {
		t.Fatalf("canceled code = %q", code)
	}
	if code := CodeOf(contextError(context.DeadlineExceeded, "test")); code != CodeTimeout {
		t.Fatalf("deadline code = %q", code)
	}
	if code := CodeOf(errors.New("plain")); code != CodeToolFailure {
		t.Fatalf("plain code = %q", code)
	}
}

func TestContractErrorEscapesDynamicField(t *testing.T) {
	message := (&ContractError{Code: CodeDenied, Field: "source.bad\n\x1b[31mFORGED", Detail: "rejected"}).Error()
	if strings.Contains(message, "\n") || strings.ContainsRune(message, '\x1b') || !strings.Contains(message, `\n\x1b`) {
		t.Fatalf("diagnostic contains an unescaped control sequence: %q", message)
	}
}

func FuzzDecodePolicy(f *testing.F) {
	f.Add(readPolicyFixture(f, "valid/file-size-policy.canonical.json"))
	f.Add([]byte(`{"schema_version":"coh.file-size-policy/v1"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		policy, err := DecodePolicy(data)
		if err != nil {
			return
		}
		canonical, err := CanonicalPolicy(policy)
		if err != nil {
			t.Fatalf("accepted policy cannot canonicalize: %v", err)
		}
		if _, err := DecodePolicy(canonical); err != nil {
			t.Fatalf("canonical policy cannot decode: %v", err)
		}
	})
}

func FuzzSafePolicyPath(f *testing.F) {
	f.Add("scripts/tool.sh")
	f.Add("../escape")
	f.Add(strings.Repeat("p", MaximumPathSize+1))
	f.Fuzz(func(t *testing.T, value string) {
		first := safePolicyPath(value)
		second := safePolicyPath(value)
		if first != second {
			t.Fatal("path validation is nondeterministic")
		}
		if first && (len(value) > MaximumPathSize || !utf8.ValidString(value)) {
			t.Fatal("accepted path exceeds the locked encoding or size bound")
		}
	})
}

func FuzzGeneratedHeader(f *testing.F) {
	f.Add([]byte("// Code generated by coh-tool; DO NOT EDIT.\n"), "coh-tool")
	f.Add([]byte("line 1\nline 2\nline 3\nline 4\nline 5\n// Code generated by late; DO NOT EDIT.\n"), "late")
	f.Fuzz(func(t *testing.T, data []byte, generator string) {
		if !generatedHeader([]byte("one\ntwo\nthree\nfour\n// Code generated by fixed; DO NOT EDIT.\n"), "fixed") ||
			generatedHeader([]byte("one\ntwo\nthree\nfour\nfive\n// Code generated by fixed; DO NOT EDIT.\n"), "fixed") {
			t.Fatal("locked first-five-line generated-header invariant failed")
		}
		first := generatedHeader(data, generator)
		if first != generatedHeader(data, generator) {
			t.Fatal("generated-header validation is nondeterministic")
		}
	})
}

func validPolicy() Policy {
	return Policy{
		SchemaVersion: PolicySchema, PolicyVersion: PolicyVersion,
		Thresholds: requiredThresholds, Exceptions: []Exception{},
	}
}

func validException(path, category string) Exception {
	value := Exception{
		Path: path, Category: category, Owner: "security-engineering",
		Justification: "Temporary compatibility exception while the file is decomposed.",
		ExpiresOn:     "2026-08-19", TrackingIssue: "CYB-38",
		ContentSHA256: strings.Repeat("a", 64), ApprovedMaxPhysicalLines: 800,
	}
	if category != "script" {
		value.Generator = "coh-test-generator"
		value.ApprovedMaxPhysicalLines = 900
	}
	return value
}

func readPolicyFixture(tb testing.TB, relative string) []byte {
	tb.Helper()
	data, err := os.ReadFile("../../../contracts/file-size/v1/fixtures/" + relative)
	if err != nil {
		tb.Fatalf("ReadFile(%s) error = %v", relative, err)
	}
	return data
}
