package queryconnector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

const expectedQueryDigest = "sha256:ff6772b072314987ca4e6b001e4f4e38968d7c7599f1c883e81feadfd01df259"

func TestCanonicalQueryFixture(t *testing.T) {
	input := readFixture(t, "valid/query.canonical.json")
	validated, err := DecodeQuery(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(validated.CanonicalBytes(), bytes.TrimSpace(input)) || validated.Digest() != expectedQueryDigest {
		t.Fatalf("canonical=%t digest=%s", bytes.Equal(validated.CanonicalBytes(), bytes.TrimSpace(input)), validated.Digest())
	}
	copyBytes := validated.CanonicalBytes()
	copyBytes[0] = '['
	copyValue := validated.Value()
	copyValue.Scope.ResourceIDs[0] = "changed"
	if validated.CanonicalBytes()[0] != '{' || validated.Value().Scope.ResourceIDs[0] != "securityevent" {
		t.Fatal("validated query exposed mutable state")
	}
	again, err := DecodeQuery(context.Background(), validated.CanonicalBytes())
	if err != nil || again.Digest() != validated.Digest() {
		t.Fatalf("round trip digest=%s err=%v", again.Digest(), err)
	}
}

func TestStrictQueryDenialCorpus(t *testing.T) {
	base := bytes.TrimSpace(readFixture(t, "valid/query.canonical.json"))
	mutations := map[string]func([]byte) []byte{
		"duplicate-key": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"contract_version":"1.0.0"`), []byte(`"contract_version":"1.0.0","contract_version":"1.0.0"`), 1)
		},
		"unknown-field":     func(input []byte) []byte { return append([]byte(`{"unexpected":true,`), input[1:]...) },
		"missing-authority": func(input []byte) []byte { return deleteField(t, input, "authority") },
		"missing-limit":     func(input []byte) []byte { return deleteNestedField(t, input, "limits", "maximum_bytes") },
		"empty-resource-scope": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"resource_ids":["securityevent"]`), []byte(`"resource_ids":[]`), 1)
		},
		"reversed-time-range": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"end":"2026-08-27T18:00:00.000000000Z","start":"2026-08-27T17:00:00.000000000Z"`), []byte(`"end":"2026-08-27T17:00:00.000000000Z","start":"2026-08-27T18:00:00.000000000Z"`), 1)
		},
		"unknown-version": func(input []byte) []byte {
			return bytes.Replace(input, []byte(QuerySchemaVersion), []byte("coh.query-request/v2"), 1)
		},
		"unsorted-resources": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"resource_ids":["securityevent"]`), []byte(`"resource_ids":["zeta","alpha"]`), 1)
		},
		"credential-passthrough": func(input []byte) []byte {
			return append([]byte(`{"credential":"forbidden",`), input[1:]...)
		},
		"zero-capability": func(input []byte) []byte {
			return bytes.Replace(input, []byte(`"capability_digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"`), []byte(`"capability_digest":""`), 1)
		},
	}

	var corpus struct {
		SchemaVersion   string `json:"schema_version"`
		ContractVersion string `json:"contract_version"`
		Cases           []struct {
			Name      string `json:"name"`
			Reason    string `json:"reason"`
			CoveredBy string `json:"covered_by"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(readFixture(t, "denial-corpus.json"), &corpus); err != nil ||
		corpus.SchemaVersion != "coh.query-connector-denials/v1" || corpus.ContractVersion != ContractVersion || len(corpus.Cases) != 10 {
		t.Fatalf("corpus=%+v err=%v", corpus, err)
	}
	for _, denial := range corpus.Cases {
		mutate := mutations[denial.Name]
		if mutate == nil || denial.CoveredBy != "TestStrictQueryDenialCorpus" {
			t.Fatalf("unmapped denial %+v", denial)
		}
		if _, err := DecodeQuery(context.Background(), mutate(append([]byte(nil), base...))); Code(err) != InvalidInput || Reason(err) != denial.Reason {
			t.Fatalf("%s code=%s reason=%s err=%v", denial.Name, Code(err), Reason(err), err)
		}
	}
}

func TestLifecycleRecordsEnforceCompletenessAndOpaqueHandles(t *testing.T) {
	query := decodeQueryFixture(t)
	handle := validHandleFixture()
	execution := Execution{SchemaVersion: ExecutionSchemaVersion, ContractVersion: ContractVersion,
		QueryID: query.Value().QueryID, AttemptID: id("6"), Handle: handle, Outcome: "queued",
		StartedAt: "2026-08-27T18:00:01.000000000Z", ProvenanceDigest: digest("1")}
	if _, err := DecodeExecution(context.Background(), marshal(t, execution)); err != nil {
		t.Fatal(err)
	}
	page := ResultPage{SchemaVersion: PageSchemaVersion, ContractVersion: ContractVersion,
		QueryID: query.Value().QueryID, AttemptID: execution.AttemptID, PageNumber: 1,
		Rows: []map[string]any{{"event_id": "one"}}, ResultDigest: digest("2"),
		Completeness:     Completeness{Status: "partial", ReasonCodes: []string{"vendor_truncated"}, Truncated: true, Partial: true},
		Statistics:       Statistics{RowsScanned: 2, RowsReturned: 1, BytesReturned: 18, DurationMillis: 5, PagesReturned: 1, SlicesCompleted: 1},
		ProvenanceDigest: digest("3")}
	if _, err := DecodePage(context.Background(), marshal(t, page)); err != nil {
		t.Fatal(err)
	}
	page.Completeness.Status = "complete"
	if _, err := DecodePage(context.Background(), marshal(t, page)); Reason(err) != "page_invalid" {
		t.Fatalf("hidden partial result err=%v", err)
	}
	handle.OpaqueDigest = "vendor-token"
	execution.Handle = handle
	if _, err := DecodeExecution(context.Background(), marshal(t, execution)); Reason(err) != "execution_invalid" {
		t.Fatalf("raw opaque value accepted err=%v", err)
	}
}

func TestValidationDenialPreservesQueryAndProvenance(t *testing.T) {
	query := decodeQueryFixture(t)
	denial := ValidationResult{SchemaVersion: ValidationSchemaVersion, ContractVersion: ContractVersion,
		QueryID: query.Value().QueryID, Outcome: "denied", ReasonCodes: []string{"policy_denied"},
		ValidatorVersion: "sentinel-validator-1.0.0", CanonicalQueryDigest: query.Digest(), ProvenanceDigest: digest("4")}
	validated, err := DecodeValidation(context.Background(), marshal(t, denial))
	if err != nil || validated.Value().CanonicalQueryDigest != query.Digest() || validated.Value().ProvenanceDigest == "" {
		t.Fatalf("denial lost query/provenance binding err=%v", err)
	}
	denial.ReasonCodes = nil
	if _, err := DecodeValidation(context.Background(), marshal(t, denial)); Reason(err) != "validation_invalid" {
		t.Fatalf("reasonless denial accepted err=%v", err)
	}
	denial.Outcome = "accepted"
	denial.ReasonCodes = []string{"policy_denied"}
	if _, err := DecodeValidation(context.Background(), marshal(t, denial)); Reason(err) != "validation_invalid" {
		t.Fatalf("accepted result retained denial err=%v", err)
	}
}

func TestExecutionAdmissionRejectsDenialAndSubstitution(t *testing.T) {
	query := decodeQueryFixture(t)
	decision := ValidationResult{SchemaVersion: ValidationSchemaVersion, ContractVersion: ContractVersion,
		QueryID: query.Value().QueryID, Outcome: "accepted", ValidatorVersion: "sentinel-validator-1.0.0",
		CanonicalQueryDigest: query.Digest(), ProvenanceDigest: digest("4")}
	accepted, err := DecodeValidation(context.Background(), marshal(t, decision))
	if err != nil || AdmitExecution(context.Background(), query, accepted) != nil {
		t.Fatalf("accepted admission err=%v", err)
	}
	decision.Outcome, decision.ReasonCodes = "denied", []string{"policy_denied"}
	denied, err := DecodeValidation(context.Background(), marshal(t, decision))
	if err != nil || Code(AdmitExecution(context.Background(), query, denied)) != Denied {
		t.Fatalf("denied admission err=%v", err)
	}
	decision.Outcome, decision.ReasonCodes, decision.CanonicalQueryDigest = "accepted", nil, digest("9")
	substituted, err := DecodeValidation(context.Background(), marshal(t, decision))
	if err != nil || Code(AdmitExecution(context.Background(), query, substituted)) != Conflict {
		t.Fatalf("substituted admission err=%v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if Code(AdmitExecution(canceled, query, accepted)) != Canceled {
		t.Fatal("canceled admission did not fail closed")
	}
}

func TestCapabilityMustAssertReadOnly(t *testing.T) {
	capability := CapabilitySnapshot{SchemaVersion: CapabilitySchemaVersion, ContractVersion: ContractVersion,
		SnapshotID: id("8"), SourceID: "sentinel-prod", AdapterVersion: "sentinel-1.0.0",
		ObservedAt: "2026-08-27T18:00:00.000000000Z", ValidUntil: "2026-08-27T19:00:00.000000000Z",
		QueryLanguages: []string{"kql"}, Features: Features{ReadOnly: true, SchemaDiscovery: true, Validation: true,
			Polling: true, Paging: true, Cancellation: true, Statistics: true},
		HardLimits: Limits{MaximumRows: 1000, MaximumBytes: 1048576, MaximumDurationMillis: 60000,
			MaximumPages: 10, MaximumSlices: 4, MaximumCostMillionths: 1000000, RequestsPerMinute: 12},
		SourceIdentityDigest: digest("5")}
	if _, err := DecodeCapability(context.Background(), marshal(t, capability)); err != nil {
		t.Fatal(err)
	}
	capability.Features.ReadOnly = false
	if _, err := DecodeCapability(context.Background(), marshal(t, capability)); Reason(err) != "capability_invalid" {
		t.Fatalf("mutable capability admitted err=%v", err)
	}
}

func TestCancellationTimeoutAndRecovery(t *testing.T) {
	input := readFixture(t, "valid/query.canonical.json")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := DecodeQuery(canceled, input); Code(err) != Canceled {
		t.Fatalf("cancellation err=%v", err)
	}
	deadline, stop := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer stop()
	if _, err := DecodeQuery(deadline, input); Code(err) != Timeout {
		t.Fatalf("timeout err=%v", err)
	}
	if recovered, err := DecodeQuery(context.Background(), input); err != nil || recovered.Digest() != expectedQueryDigest {
		t.Fatalf("recovery digest=%s err=%v", recovered.Digest(), err)
	}
}

func TestSchemaBundleAndPublicSurfaceAreStrict(t *testing.T) {
	input, err := os.ReadFile("../../../contracts/query/v1/query-connector.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(input, &schema); err != nil || schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema identity err=%v", err)
	}
	definitions, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema definitions missing")
	}
	for _, name := range []string{"capability", "query", "validation", "execution", "schema_page", "poll", "page", "cancellation"} {
		definition, ok := definitions[name].(map[string]any)
		if !ok || definition["additionalProperties"] != false || len(definition["required"].([]any)) == 0 {
			t.Fatalf("definition %s is not strict", name)
		}
	}
	connector := reflect.TypeOf((*Connector)(nil)).Elem()
	wanted := []string{"Cancel", "DiscoverSchema", "Execute", "NextPage", "Poll", "Probe", "Validate"}
	if connector.NumMethod() != len(wanted) {
		t.Fatalf("connector methods=%d", connector.NumMethod())
	}
	for index, name := range wanted {
		if connector.Method(index).Name != name {
			t.Fatalf("method %d=%s", index, connector.Method(index).Name)
		}
	}
	for _, value := range []any{CapabilitySnapshot{}, Query{}, Execution{}, HandleRef{}, ResultPage{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := strings.Split(typeOf.Field(index).Tag.Get("json"), ",")[0]
			for _, forbidden := range []string{"headers", "credential", "secret", "vendor_token", "api_key", "passthrough", "options", "url"} {
				if field == forbidden {
					t.Fatalf("%s exposes %s", typeOf.Name(), field)
				}
			}
		}
	}
}

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	input, err := os.ReadFile("../../../contracts/query/v1/fixtures/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return input
}

func decodeQueryFixture(t *testing.T) ValidatedQuery {
	t.Helper()
	value, err := DecodeQuery(context.Background(), readFixture(t, "valid/query.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func deleteField(t *testing.T, input []byte, field string) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	delete(value, field)
	return marshal(t, value)
}

func deleteNestedField(t *testing.T, input []byte, object, field string) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(input, &value); err != nil {
		t.Fatal(err)
	}
	delete(value[object].(map[string]any), field)
	return marshal(t, value)
}

func marshal(t testing.TB, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func digest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
func id(character string) string     { return "0198e300-1000-7000-8000-00000000000" + character }

func validHandleFixture() HandleRef {
	return HandleRef{HandleID: id("7"), Kind: "query_job", SourceID: "sentinel-prod", OpaqueDigest: digest("a"),
		IssuedAt: "2026-08-27T18:00:01.000000000Z", ExpiresAt: "2026-08-27T18:05:01.000000000Z"}
}

func FuzzQueryDecoderRecoversAcceptedDocuments(f *testing.F) {
	f.Add(bytes.TrimSpace(readFixture(f, "valid/query.canonical.json")))
	f.Fuzz(func(t *testing.T, input []byte) {
		validated, err := DecodeQuery(context.Background(), input)
		if err == nil {
			again, roundTripErr := DecodeQuery(context.Background(), validated.CanonicalBytes())
			if roundTripErr != nil || again.Digest() != validated.Digest() {
				t.Fatalf("accepted input did not recover: %v", roundTripErr)
			}
		}
	})
}
