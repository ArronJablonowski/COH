package sigmacompiler

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestCanonicalContracts(t *testing.T) {
	request := testRequest()
	response := testResponse(request)
	if validateRequest(request) != nil || validateResponse(response) != nil || ValidateExchange(request, response) != nil {
		t.Fatal("canonical request/response denied")
	}
	if validateCapability(testCapability()) != nil || validateAttestation(testAttestation(request.HelperIdentityExpectation)) != nil ||
		validateProvenance(testProvenance(request, response)) != nil || validateDenialCorpus(testDenials()) != nil ||
		validateRedactedTrace(testTrace(request.RequestDigest)) != nil {
		t.Fatal("canonical evidence denied")
	}
}

func TestStrictDecodersDenyAmbiguityAndTamper(t *testing.T) {
	request := testRequest()
	encoded := marshalTest(t, request)
	unknown := strings.Replace(string(encoded), "{", `{"unknown":true,`, 1)
	duplicate := strings.Replace(string(encoded), `"operation":"sigma.compile",`, `"operation":"other","operation":"sigma.compile",`, 1)
	for name, input := range map[string][]byte{
		"unknown": []byte(unknown), "duplicate": []byte(duplicate), "trailing": append(encoded, []byte(" true")...),
	} {
		if _, err := DecodeCompileRequest(input); err == nil {
			t.Fatalf("%s input accepted", name)
		}
	}
	request.SigmaYAML += "\n"
	if _, err := DecodeCompileRequest(marshalTest(t, request)); err == nil {
		t.Fatal("source tamper accepted")
	}
}

func TestMappingsAreExplicitOneToOneAndSorted(t *testing.T) {
	for name, mutate := range map[string]func(*CompileRequest){
		"missing":   func(value *CompileRequest) { value.Mapping.Fields = value.Mapping.Fields[:0] },
		"ambiguous": func(value *CompileRequest) { value.Mapping.Fields[1].Target = value.Mapping.Fields[0].Target },
		"reordered": func(value *CompileRequest) {
			value.Mapping.Fields[0], value.Mapping.Fields[1] = value.Mapping.Fields[1], value.Mapping.Fields[0]
		},
		"wildcard": func(value *CompileRequest) { value.Mapping.Fields[0].Target = "process.*" },
	} {
		candidate := testRequest()
		mutate(&candidate)
		candidate.Mapping.MappingDigest = MappingDigest(candidate.Mapping)
		candidate.RequestDigest = CompileRequestDigest(candidate)
		if _, err := DecodeCompileRequest(marshalTest(t, candidate)); err == nil {
			t.Fatalf("%s mapping accepted", name)
		}
	}
}

func TestBackendMatrixCannotWidenOrSubstitute(t *testing.T) {
	request := testRequest()
	for name, mutate := range map[string]func(*CompileRequest){
		"lucene":         func(value *CompileRequest) { value.Target.NativeLanguage = "lucene" },
		"backend":        func(value *CompileRequest) { value.Target.BackendVersion = "2.2.0" },
		"format":         func(value *CompileRequest) { value.Target.OutputFormat = "siem_rule" },
		"security-onion": func(value *CompileRequest) { value.Target = targetMatrix[1] },
	} {
		candidate := clone(request)
		mutate(&candidate)
		candidate.RequestDigest = CompileRequestDigest(candidate)
		if _, err := DecodeCompileRequest(marshalTest(t, candidate)); err == nil {
			t.Fatalf("%s substitution accepted", name)
		}
	}
}

func TestPartialOrUnsupportedSuccessCannotReleaseQuery(t *testing.T) {
	request := testRequest()
	for _, outcome := range []string{"needs_mapping", "unsupported", "denied"} {
		candidate := testResponse(request)
		candidate.Outcome = outcome
		candidate.ReasonCodes = []string{"conversion_denied"}
		candidate.ResponseDigest = CompileResponseDigest(candidate)
		if _, err := DecodeCompileResponse(marshalTest(t, candidate)); err == nil {
			t.Fatalf("%s response released query", outcome)
		}
	}
	candidate := testResponse(request)
	candidate.Outcome = "unsupported"
	candidate.ReasonCodes = []string{"backend_unsupported"}
	candidate.NativeQuery, candidate.NativeQueryDigest = "", ""
	candidate.ResponseDigest = CompileResponseDigest(candidate)
	if _, err := DecodeCompileResponse(marshalTest(t, candidate)); err != nil {
		t.Fatalf("closed unsupported response denied: %v", err)
	}
}

func TestAttestationAndTraceRemainFailClosed(t *testing.T) {
	identity := testIdentity()
	for name, mutate := range map[string]func(*HelperAttestation){
		"network":  func(value *HelperAttestation) { value.NetworkDenied = false },
		"plugins":  func(value *HelperAttestation) { value.AmbientPluginsDenied = false },
		"external": func(value *HelperAttestation) { value.ExternalSourcesDenied = false },
		"skip":     func(value *HelperAttestation) { value.SkipUnsupportedDenied = false },
		"runtime":  func(value *HelperAttestation) { value.PythonVersion = "3.14.7" },
	} {
		candidate := testAttestation(identity)
		mutate(&candidate)
		candidate.Digest = HelperAttestationDigest(candidate)
		if _, err := DecodeHelperAttestation(marshalTest(t, candidate)); err == nil {
			t.Fatalf("%s attestation accepted", name)
		}
	}
	trace := testTrace(repeatDigest("1"))
	trace.NativeTextExposed = true
	if _, err := DecodeRedactedTrace(marshalTest(t, trace)); err == nil {
		t.Fatal("native-text trace accepted")
	}
}

func TestDenialCorpusDeclaresExecutableCoverage(t *testing.T) {
	covered := []string{"TestAttestationAndTraceRemainFailClosed", "TestBackendMatrixCannotWidenOrSubstitute",
		"TestMappingsAreExplicitOneToOneAndSorted", "TestPartialOrUnsupportedSuccessCannotReleaseQuery",
		"TestStrictDecodersDenyAmbiguityAndTamper"}
	for _, item := range testDenials().Cases {
		if !slices.Contains(covered, item.CoveredBy) {
			t.Fatalf("%s lacks executable coverage", item.Class)
		}
	}
}

func TestEmitCanonicalFixtures(t *testing.T) {
	if os.Getenv("COH_EMIT_PYSIGMA_FIXTURES") != "1" {
		t.Skip("fixture emission disabled")
	}
	request := testRequest()
	values := map[string]any{
		"compile-request.json":                request,
		"compile-response.compiled.json":      testResponse(request),
		"compile-response.needs-mapping.json": testNeedsMappingResponse(request),
		"capability-snapshot.json":            testCapability(),
		"helper-attestation.json":             testAttestation(request.HelperIdentityExpectation),
		"provenance-receipt.json":             testProvenance(request, testResponse(request)),
		"denial-corpus.json":                  testDenials(),
		"redacted-error-trace.json":           testTrace(request.RequestDigest),
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		encoded, err := json.MarshalIndent(values[name], "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("FIXTURE %s\n%s\nEND FIXTURE\n", name, encoded)
	}
}

func testRequest() CompileRequest {
	mapping := MappingBinding{MappingID: "018f0000-0000-7000-8000-000000000001", Revision: 1,
		TargetResource: "logs-endpoint-events-process-default",
		Logsource:      Logsource{Category: "process_creation", Product: "windows", Service: "sysmon", Definition: "sanitized fixture"},
		Fields: []FieldMapping{{Source: "CommandLine", Target: "process.command_line", DataType: "string"},
			{Source: "Image", Target: "process.executable", DataType: "keyword"}},
		SourceSchemaDigest: repeatDigest("1"), TargetSchemaDigest: repeatDigest("2")}
	mapping.MappingDigest = MappingDigest(mapping)
	sigma := "title: Suspicious Tool Execution\nid: 018f0000-0000-7000-8000-000000000010\nstatus: test\nlogsource:\n  category: process_creation\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    Image|endswith: '/example-tool'\n    CommandLine|contains: '--safe-fixture'\n  condition: selection\n"
	value := CompileRequest{SchemaVersion: RequestVersion, ContractVersion: ContractVersion,
		RequestID: "018f0000-0000-7000-8000-000000000002", Operation: "sigma.compile", SigmaYAML: sigma,
		SigmaDigest: SigmaDigest(sigma), SigmaProfile: SigmaProfile, Target: targetMatrix[0], Mapping: mapping,
		CapabilityDigest: repeatDigest("3"), QualificationDigest: repeatDigest("4"), Policy: testPolicy(),
		HelperIdentityExpectation: testIdentity(), Deadline: "2026-08-28T05:00:00Z"}
	value.RequestDigest = CompileRequestDigest(value)
	return value
}

func testResponse(request CompileRequest) CompileResponse {
	query := `FROM logs-endpoint-events-process-default | WHERE ends_with(process.executable, "/example-tool") AND process.command_line LIKE "*--safe-fixture*"`
	value := CompileResponse{SchemaVersion: ResponseVersion, ContractVersion: ContractVersion,
		RequestID: request.RequestID, RequestDigest: request.RequestDigest, Outcome: "compiled_untrusted",
		ReasonCodes: []string{}, Diagnostics: []Diagnostic{}, Target: request.Target, SigmaDigest: request.SigmaDigest,
		MappingDigest: request.Mapping.MappingDigest, TargetSchemaDigest: request.Mapping.TargetSchemaDigest,
		NativeQuery: query, NativeQueryDigest: NativeQueryDigest(query), HelperIdentity: request.HelperIdentityExpectation,
		ProvenanceDigest: repeatDigest("5")}
	value.ResponseDigest = CompileResponseDigest(value)
	return value
}

func testNeedsMappingResponse(request CompileRequest) CompileResponse {
	value := testResponse(request)
	value.Outcome = "needs_mapping"
	value.ReasonCodes = []string{"mapping_missing"}
	value.Diagnostics = []Diagnostic{{Code: "MAP001", Severity: "error", Class: "mapping_missing", Location: "detection.selection"}}
	value.NativeQuery, value.NativeQueryDigest = "", ""
	value.ResponseDigest = CompileResponseDigest(value)
	return value
}

func testPolicy() Policy {
	return Policy{Profile: SigmaProfile, MaximumSigmaBytes: MaximumSigmaBytes, MaximumYAMLNodes: 4096,
		MaximumYAMLDepth: 32, MaximumMappingEntries: 2048, MaximumSequenceEntries: 2048,
		MaximumScalarBytes: 16384, MaximumScalars: 4096, MaximumSelections: 64,
		MaximumDetectionItems: 512, MaximumDetectionValues: 2048, MaximumConditionTokens: 512,
		MaximumConditionDepth: 32, MaximumExpandedTerms: 2048, MaximumNativeQueryBytes: MaximumNativeBytes}
}

func testIdentity() HelperIdentity {
	return HelperIdentity{Name: "coh-pysigma-helper", Version: CompilerVersion, RID: "osx-arm64",
		ArtifactDigest: repeatDigest("a"), PackageClosureDigest: repeatDigest("b"), RuntimeDigest: repeatDigest("c"),
		BackendMatrixDigest: repeatDigest("d"), ProfileDigest: repeatDigest("e")}
}

func testCapability() CapabilitySnapshot {
	backends := make([]BackendCapability, len(targetMatrix))
	for index, target := range targetMatrix {
		backends[index] = BackendCapability{Target: target.Target, NativeLanguage: target.NativeLanguage,
			BackendPackage: target.BackendPackage, BackendVersion: target.BackendVersion, BackendCommit: target.BackendCommit,
			BackendClass: target.BackendClass, OutputFormat: target.OutputFormat, Qualification: "candidate"}
	}
	backends[1].Qualification, backends[1].ReasonCode = "unavailable", "native_contract_mismatch"
	value := CapabilitySnapshot{SchemaVersion: CapabilityVersion, ContractVersion: ContractVersion,
		ObservedAt: "2026-08-28T04:00:00Z", ValidUntil: "2026-09-27T04:00:00Z", SigmaProfile: SigmaProfile,
		CompilerVersion: CompilerVersion, BackendCapabilities: backends, Policy: testPolicy(),
		BackendMatrixDigest: repeatDigest("d")}
	value.Digest = CapabilitySnapshotDigest(value)
	return value
}

func testAttestation(identity HelperIdentity) HelperAttestation {
	value := HelperAttestation{SchemaVersion: AttestationVersion, ContractVersion: ContractVersion,
		AttestationID: "018f0000-0000-7000-8000-000000000003", ObservedAt: "2026-08-28T04:00:00Z",
		ValidUntil: "2026-09-27T04:00:00Z", Identity: identity, PythonVersion: "3.13.15",
		PySigmaVersion: "1.5.0", PyInstallerVersion: "6.22.2", ManifestDigest: repeatDigest("6"),
		SBOMDigest: repeatDigest("7"), ProvenanceDigest: repeatDigest("8"), NetworkDenied: true,
		CredentialClasses: []string{"none"}, AmbientPluginsDenied: true, ExternalSourcesDenied: true,
		SkipUnsupportedDenied: true, Reproducible: true}
	value.Digest = HelperAttestationDigest(value)
	return value
}

func testProvenance(request CompileRequest, response CompileResponse) ProvenanceReceipt {
	value := ProvenanceReceipt{SchemaVersion: ProvenanceVersion, ContractVersion: ContractVersion,
		RequestDigest: request.RequestDigest, ResponseDigest: response.ResponseDigest, SigmaDigest: request.SigmaDigest,
		MappingDigest: request.Mapping.MappingDigest, TargetSchemaDigest: request.Mapping.TargetSchemaDigest,
		NativeQueryDigest: response.NativeQueryDigest, HelperAttestationDigest: repeatDigest("9"),
		CapabilityDigest: request.CapabilityDigest, QualificationDigest: request.QualificationDigest,
		PolicyDigest: PolicyDigest(request.Policy), AuditReservationDigest: repeatDigest("f"), State: "compiled_untrusted"}
	value.Digest = ProvenanceReceiptDigest(value)
	return value
}

func testDenials() DenialCorpus {
	cases := []DenialCase{
		{Class: "ambient_plugin", Mutation: "enable autodiscovery", Outcome: "denied", Reason: "ambient_plugin_denied", CoveredBy: "TestAttestationAndTraceRemainFailClosed"},
		{Class: "backend_substitution", Mutation: "change backend version", Outcome: "denied", Reason: "backend_binding_denied", CoveredBy: "TestBackendMatrixCannotWidenOrSubstitute"},
		{Class: "duplicate_json", Mutation: "repeat operation key", Outcome: "denied", Reason: "document_ambiguous", CoveredBy: "TestStrictDecodersDenyAmbiguityAndTamper"},
		{Class: "external_source", Mutation: "enable command placeholder", Outcome: "denied", Reason: "external_source_denied", CoveredBy: "TestAttestationAndTraceRemainFailClosed"},
		{Class: "mapping_ambiguous", Mutation: "two sources map to one target", Outcome: "needs_mapping", Reason: "mapping_ambiguous", CoveredBy: "TestMappingsAreExplicitOneToOneAndSorted"},
		{Class: "mapping_missing", Mutation: "remove all field mappings", Outcome: "needs_mapping", Reason: "mapping_missing", CoveredBy: "TestMappingsAreExplicitOneToOneAndSorted"},
		{Class: "output_format", Mutation: "request publication format", Outcome: "unsupported", Reason: "output_format_unsupported", CoveredBy: "TestBackendMatrixCannotWidenOrSubstitute"},
		{Class: "partial_success", Mutation: "return query with denial", Outcome: "denied", Reason: "partial_success_denied", CoveredBy: "TestPartialOrUnsupportedSuccessCannotReleaseQuery"},
		{Class: "security_onion", Mutation: "request OpenSearch fallback", Outcome: "unsupported", Reason: "native_contract_mismatch", CoveredBy: "TestBackendMatrixCannotWidenOrSubstitute"},
		{Class: "sigma_tamper", Mutation: "change YAML after digest", Outcome: "denied", Reason: "sigma_digest_mismatch", CoveredBy: "TestStrictDecodersDenyAmbiguityAndTamper"},
		{Class: "skip_unsupported", Mutation: "enable collected errors", Outcome: "denied", Reason: "skip_unsupported_denied", CoveredBy: "TestAttestationAndTraceRemainFailClosed"},
		{Class: "wildcard_mapping", Mutation: "map to wildcard field", Outcome: "needs_mapping", Reason: "mapping_wildcard_denied", CoveredBy: "TestMappingsAreExplicitOneToOneAndSorted"},
	}
	return DenialCorpus{SchemaVersion: DenialCorpusVersion, ContractVersion: ContractVersion, Cases: cases}
}

func testTrace(requestDigest string) RedactedTrace {
	return RedactedTrace{SchemaVersion: RedactedTraceVersion, ContractVersion: ContractVersion,
		TraceID: "018f0000-0000-7000-8000-000000000004", Events: []TraceEvent{
			{Sequence: 1, Phase: "preflight", Outcome: "accepted", ReasonCodes: []string{}, RequestDigest: requestDigest},
			{Sequence: 2, Phase: "mapping", Outcome: "denied", ReasonCodes: []string{"mapping_ambiguous"}, RequestDigest: requestDigest}},
		NativeTextExposed: false, SigmaTextExposed: false, FieldNameExposed: false, CredentialExposed: false, PathExposed: false}
}

func repeatDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }

func marshalTest(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
