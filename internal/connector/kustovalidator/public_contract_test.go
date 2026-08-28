package kustovalidator

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
		{"request", "helper-request.json", decodeRequest},
		{"accepted response", "helper-response.accepted.json", decodeResponse},
		{"denied response", "helper-response.denied.json", decodeResponse},
		{"registry", "semantic-registry.json", decodeRegistry},
		{"attestation", "helper-attestation.json", decodeAttestation},
		{"decision", "policy-decision.accepted.json", decodeDecision},
		{"audit", "audit-proof.json", decodeAudit},
		{"revocation", "revocation.json", decodeRevocation},
		{"denials", "denial-corpus.json", decodeDenials},
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
		var schema any
		input, err := os.ReadFile(filepath.Join(contractRoot(t), entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(input, &schema); err != nil {
			t.Fatalf("%s is invalid JSON: %v", entry.Name(), err)
		}
		assertClosedObjects(t, entry.Name(), schema)
	}
	if count != 8 {
		t.Fatalf("schema count = %d, want 8", count)
	}
}

func TestStrictContractDecoders(t *testing.T) {
	t.Parallel()
	base := readFixture(t, "helper-request.json")
	unknown := strings.Replace(string(base), "{", `{"unknown":true,`, 1)
	duplicate := strings.Replace(string(base), `"operation":"kusto.validate",`, `"operation":"other","operation":"kusto.validate",`, 1)
	for name, input := range map[string][]byte{
		"unknown": []byte(unknown), "duplicate": []byte(duplicate),
		"trailing": append(append([]byte(nil), base...), []byte(" true")...),
	} {
		if _, err := DecodeHelperRequest(input); err == nil {
			t.Fatalf("%s document accepted", name)
		}
	}
}

func TestRegistryCannotBeWeakened(t *testing.T) {
	t.Parallel()
	var registry SemanticRegistry
	unmarshalFixture(t, "semantic-registry.json", &registry)
	mutations := map[string]func(*SemanticRegistry){
		"add operator":       func(value *SemanticRegistry) { value.AllowedOperators = append(value.AllowedOperators, "evaluate") },
		"remove prohibition": func(value *SemanticRegistry) { value.ProhibitedConstructs = value.ProhibitedConstructs[1:] },
		"reorder": func(value *SemanticRegistry) {
			value.AllowedOperators[0], value.AllowedOperators[1] = value.AllowedOperators[1], value.AllowedOperators[0]
		},
		"enable evaluate": func(value *SemanticRegistry) { value.EvaluateAllowed = true },
	}
	for name, mutate := range mutations {
		candidate := clone(registry)
		mutate(&candidate)
		candidate.Digest = SemanticRegistryDigest(candidate)
		if _, err := DecodeSemanticRegistry(marshal(t, candidate)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestHelperRequestTamperDenials(t *testing.T) {
	t.Parallel()
	var request HelperRequest
	unmarshalFixture(t, "helper-request.json", &request)
	mutations := map[string]func(*HelperRequest){
		"query":  func(value *HelperRequest) { value.Query += " | take 1" },
		"schema": func(value *HelperRequest) { value.Schema.Tables[0].Name = "OtherTable" },
		"helper": func(value *HelperRequest) { value.HelperIdentityExpectation.ArtifactDigest = repeatDigest("f") },
		"limit":  func(value *HelperRequest) { value.RequestedRows = value.Policy.MaximumRows + 1 },
	}
	for name, mutate := range mutations {
		candidate := clone(request)
		mutate(&candidate)
		if _, err := DecodeHelperRequest(marshal(t, candidate)); err == nil {
			t.Fatalf("%s substitution accepted", name)
		}
	}
}

func TestHelperResponseTamperDenials(t *testing.T) {
	t.Parallel()
	var response HelperResponse
	unmarshalFixture(t, "helper-response.accepted.json", &response)
	mutations := map[string]func(*HelperResponse){
		"terminal take":   func(value *HelperResponse) { value.TerminalTake++ },
		"canonical query": func(value *HelperResponse) { value.CanonicalKQL += " | take 1" },
		"tree":            func(value *HelperResponse) { value.BoundedTreeDigest = repeatDigest("f") },
		"identity":        func(value *HelperResponse) { value.HelperIdentity.RuntimeDigest = repeatDigest("f") },
	}
	for name, mutate := range mutations {
		candidate := clone(response)
		mutate(&candidate)
		if _, err := DecodeHelperResponse(marshal(t, candidate)); err == nil {
			t.Fatalf("%s tamper accepted", name)
		}
	}
}

func TestAttestationDriftDenials(t *testing.T) {
	t.Parallel()
	var attestation HelperAttestation
	unmarshalFixture(t, "helper-attestation.json", &attestation)
	for name, mutate := range map[string]func(*HelperAttestation){
		"runtime":     func(value *HelperAttestation) { value.DotnetRuntimeVersion = "10.0.12" },
		"package":     func(value *HelperAttestation) { value.Identity.PackageClosureDigest = repeatDigest("1") },
		"network":     func(value *HelperAttestation) { value.NetworkDenied = false },
		"credentials": func(value *HelperAttestation) { value.CredentialClasses = []string{"azure"} },
	} {
		candidate := clone(attestation)
		mutate(&candidate)
		if _, err := DecodeHelperAttestation(marshal(t, candidate)); err == nil {
			t.Fatalf("%s drift accepted", name)
		}
	}
}

func TestDecisionAuditAndRevocationAreFailClosed(t *testing.T) {
	t.Parallel()
	var decision PolicyDecision
	unmarshalFixture(t, "policy-decision.accepted.json", &decision)
	decision.ActorID = "018f0000-0000-7000-8000-000000000009"
	if _, err := DecodePolicyDecision(marshal(t, decision)); err == nil {
		t.Fatal("tampered decision accepted")
	}
	var audit AuditProof
	unmarshalFixture(t, "audit-proof.json", &audit)
	audit.QueryTextExposed = true
	if _, err := DecodeAuditProof(marshal(t, audit)); err == nil {
		t.Fatal("query-bearing audit accepted")
	}
	var revocation RevocationEvidence
	unmarshalFixture(t, "revocation.json", &revocation)
	revocation.ExecutionPermitted = true
	if _, err := DecodeRevocationEvidence(marshal(t, revocation)); err == nil {
		t.Fatal("revoked execution accepted")
	}
}

func TestDenialCorpusDeclaresCoverage(t *testing.T) {
	t.Parallel()
	var corpus DenialCorpus
	unmarshalFixture(t, "denial-corpus.json", &corpus)
	covered := map[string]bool{
		"TestSemanticDenialCorpus": true, "TestStrictContractDecoders": true,
		"TestHelperRequestTamperDenials": true, "TestRegistryCannotBeWeakened": true,
		"TestAttestationDriftDenials": true, "TestStaleRevokedAndReplayDenials": true,
		"TestHelperResponseTamperDenials": true, "TestTimeoutCancellationAndRecovery": true,
		"TestAuditFailureWithholdsSuccess": true,
	}
	for _, item := range corpus.Cases {
		if !covered[item.CoveredBy] {
			t.Fatalf("%s has no declared test", item.Class)
		}
	}
}

func TestHelperExchangeBindsRequestSchemaRegistryIdentityAndLimit(t *testing.T) {
	t.Parallel()
	var request HelperRequest
	unmarshalFixture(t, "helper-request.json", &request)
	var response HelperResponse
	unmarshalFixture(t, "helper-response.accepted.json", &response)
	if err := ValidateHelperExchange(request, response); err != nil {
		t.Fatalf("valid exchange denied: %v", err)
	}
	mutations := map[string]func(*HelperResponse){
		"request": func(value *HelperResponse) { value.RequestDigest = repeatDigest("1") },
		"schema":  func(value *HelperResponse) { value.SchemaDigest = repeatDigest("2") },
		"registry": func(value *HelperResponse) {
			value.RegistryDigest = repeatDigest("3")
			value.HelperIdentity.RegistryDigest = value.RegistryDigest
		},
		"identity": func(value *HelperResponse) { value.HelperIdentity.ArtifactDigest = repeatDigest("4") },
		"limit":    func(value *HelperResponse) { value.TerminalTake = request.RequestedRows + 1 },
		"table":    func(value *HelperResponse) { value.Semantic.Tables = []string{"UnknownTable"} },
		"column":   func(value *HelperResponse) { value.Semantic.Columns = []string{"SecurityEvent.UnknownColumn"} },
	}
	for name, mutate := range mutations {
		candidate := clone(response)
		mutate(&candidate)
		candidate.ResponseDigest = HelperResponseDigest(candidate)
		if err := ValidateHelperExchange(request, candidate); err == nil {
			t.Fatalf("%s substitution accepted", name)
		}
	}
}

func TestHelperProtocolExcludesAuthorityAndExecutionSurfaces(t *testing.T) {
	t.Parallel()
	for _, file := range []string{"helper-request.json", "helper-response.accepted.json", "helper-response.denied.json"} {
		var value any
		if err := json.Unmarshal(readFixture(t, file), &value); err != nil {
			t.Fatal(err)
		}
		keys := map[string]bool{}
		collectKeys(value, keys)
		for _, forbidden := range []string{
			"actor", "authorization", "audit", "credential", "endpoint", "environment", "executable", "path", "secret", "token",
		} {
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
		for index, child := range node {
			assertClosedObjects(t, path+"/"+string(rune(index)), child)
		}
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

func unmarshalFixture(t *testing.T, name string, output any) {
	t.Helper()
	if err := json.Unmarshal(readFixture(t, name), output); err != nil {
		t.Fatal(err)
	}
}

func contractRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", "contracts", "kusto-validator", "v1"))
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decodeRequest(input []byte) error     { _, err := DecodeHelperRequest(input); return err }
func decodeResponse(input []byte) error    { _, err := DecodeHelperResponse(input); return err }
func decodeRegistry(input []byte) error    { _, err := DecodeSemanticRegistry(input); return err }
func decodeAttestation(input []byte) error { _, err := DecodeHelperAttestation(input); return err }
func decodeDecision(input []byte) error    { _, err := DecodePolicyDecision(input); return err }
func decodeAudit(input []byte) error       { _, err := DecodeAuditProof(input); return err }
func decodeRevocation(input []byte) error  { _, err := DecodeRevocationEvidence(input); return err }
func decodeDenials(input []byte) error     { _, err := DecodeDenialCorpus(input); return err }

func repeatDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
