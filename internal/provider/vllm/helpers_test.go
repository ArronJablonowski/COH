package vllm

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type schemaResolverStub struct{ documents map[string]json.RawMessage }

func (stub schemaResolverStub) Resolve(_ context.Context, wanted string) (SchemaDocument, error) {
	return SchemaDocument{Digest: wanted, JSON: append(json.RawMessage(nil), stub.documents[wanted]...)}, nil
}

type tokenCounterStub struct {
	count uint64
	err   error
}

type routeVerifierStub struct{ err error }

func (stub routeVerifierStub) VerifyLocal(context.Context, LocalRouteObservation) error {
	return stub.err
}

type routeVerifierCapture struct {
	observation LocalRouteObservation
	err         error
}

func (capture *routeVerifierCapture) VerifyLocal(_ context.Context, observation LocalRouteObservation) error {
	capture.observation = observation
	return capture.err
}

func (stub tokenCounterStub) Count(context.Context, providercontract.ValidatedRequest) (uint64, error) {
	return stub.count, stub.err
}

type reasoningStoreStub struct {
	mu      sync.Mutex
	records map[string][]byte
}

func (stub *reasoningStoreStub) Put(_ context.Context, reference, itemDigest string, value []byte) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.records[reference+"\x00"+itemDigest] = append([]byte(nil), value...)
	return nil
}

func (stub *reasoningStoreStub) Resolve(_ context.Context, reference, itemDigest string) ([]byte, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return append([]byte(nil), stub.records[reference+"\x00"+itemDigest]...), nil
}

type routeResponse struct {
	status      int
	body        []byte
	contentType string
	err         error
}

type routeHTTPStub struct {
	responses map[string]routeResponse
	requests  []*http.Request
	bodies    [][]byte
	blockPath string
}

func routeKey(method, path string) string { return method + " " + path }

func (stub *routeHTTPStub) Do(request *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(request.Body)
	stub.requests = append(stub.requests, request)
	stub.bodies = append(stub.bodies, body)
	if request.URL.Path == stub.blockPath {
		<-request.Context().Done()
		return nil, request.Context().Err()
	}
	response := stub.responses[routeKey(request.Method, request.URL.Path)]
	if response.err != nil {
		return nil, response.err
	}
	contentType := response.contentType
	if contentType == "" {
		contentType = "application/json"
	}
	return &http.Response{StatusCode: response.status, Body: io.NopCloser(bytes.NewReader(response.body)),
		Request: request, Header: http.Header{"Content-Type": []string{contentType}}}, nil
}

type testRig struct {
	adapter   *Adapter
	request   providercontract.ValidatedRequest
	http      *routeHTTPStub
	reasoning *reasoningStoreStub
	clock     time.Time
}

func newTestRig(t *testing.T) testRig {
	t.Helper()
	clock := mustTime(t, "2026-08-26T06:10:00.000000000Z")
	provider := testProvider(t)
	capability, err := DiscoverCapability(context.Background(), CapabilityDefinition{
		SnapshotID: "0198e300-3000-7000-8000-000000000001", ObservedAt: mustTime(t, "2026-08-26T05:00:00.000000000Z"),
		ValidUntil: mustTime(t, "2026-08-27T05:00:00.000000000Z"), Provider: provider,
		Limits: providercontract.Limits{MaximumInputTokens: 24576, MaximumOutputTokens: 8192, MaximumMessages: 512,
			MaximumTools: 32, MaximumParallelToolCalls: 4, MaximumStreamSeconds: 600}})
	if err != nil {
		t.Fatal(err)
	}
	inputDigest, outputDigest, structuredDigest := testDigest("a"), testDigest("b"), testDigest("c")
	strictSchema := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"host":{"type":"string"}},"required":["host"]}`)
	structuredSchema := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"verdict":{"type":"string"}},"required":["verdict"]}`)
	httpClient := &routeHTTPStub{responses: map[string]routeResponse{
		routeKey(http.MethodGet, HealthPath):        {status: http.StatusOK, body: readFixture(t, "health.empty")},
		routeKey(http.MethodGet, VersionPath):       {status: http.StatusOK, body: readFixture(t, "version.json")},
		routeKey(http.MethodGet, ModelsPath):        {status: http.StatusOK, body: readFixture(t, "models.json")},
		routeKey(http.MethodGet, TokenizerInfoPath): {status: http.StatusOK, body: readFixture(t, "tokenizer-info.json")},
		routeKey(http.MethodPost, ChatPath):         {status: http.StatusOK, body: readFixture(t, "completed-chat.json")},
	}}
	reasoning := &reasoningStoreStub{records: make(map[string][]byte)}
	clockTick := uint64(0)
	adapter, err := New(Config{Endpoint: VLLMEndpoint, Capability: capability,
		Qualifications: qualifiedRegistry(t, capability, clock),
		Schemas: schemaResolverStub{documents: map[string]json.RawMessage{inputDigest: strictSchema, outputDigest: strictSchema,
			structuredDigest: structuredSchema}},
		Reasoning: reasoning, Tokens: tokenCounterStub{count: 100}, Route: routeVerifierStub{}, HTTP: httpClient,
		Clock: func() time.Time {
			value := clock.Add(time.Duration(clockTick) * time.Nanosecond)
			clockTick++
			return value
		}})
	if err != nil {
		t.Fatal(err)
	}
	request := providercontract.InferenceRequest{SchemaVersion: providercontract.RequestSchemaVersion,
		ContractVersion: providercontract.ContractVersion, RequestID: "0198e300-3000-7000-8000-000000000003",
		AttemptID: "0198e300-3000-7000-8000-000000000004", OrganizationID: "0198e300-3000-7000-8000-000000000005",
		TenantID: "0198e300-3000-7000-8000-000000000006", CaseID: "0198e300-3000-7000-8000-000000000007",
		TaskID: "0198e300-3000-7000-8000-000000000008", ActorID: "0198e300-3000-7000-8000-000000000009",
		Provider: provider, CapabilityDigest: capability.Digest(), QualificationID: "0198e300-3000-7000-8000-000000000002",
		ModelSurface: testSurfaceBinding("0198e300-3000-7000-8000-000000000010"),
		Messages: []providercontract.Message{{MessageID: "0198e300-3000-7000-8000-000000000010", Role: "user",
			Items: []providercontract.ContentItem{{Kind: "text", Text: "Inspect the host."}}}},
		Tools: []providercontract.Tool{{Name: "query_host", Description: "Query one host.", InputSchemaDigest: inputDigest,
			OutputSchemaDigest: outputDigest}}, OutputConstraint: providercontract.OutputConstraint{Kind: "text"},
		Sampling: providercontract.Sampling{TemperatureMilli: 200, TopPMillionths: 900000, Seed: 7}, MaximumOutputTokens: 1024,
		State: providercontract.State{Mode: "stateless"}, Deadline: "2026-08-26T06:30:00.000000000Z",
		AuthorizationDigest: testDigest("d"), PolicyDecisionDigest: testDigest("e"), ApprovalDecisionDigest: testDigest("f"),
		AuditReservationDigest: testDigest("1")}
	return testRig{adapter: adapter, request: decodeRequest(t, request), http: httpClient, reasoning: reasoning, clock: clock}
}

func testSurfaceBinding(messageID string) providercontract.ModelSurfaceBinding {
	return providercontract.ModelSurfaceBinding{RunID: "0198e300-3000-7000-8000-000000000020", ProviderID: "vllm.local", ProjectionID: "0198e300-3000-7000-8000-000000000021", ProjectionVersion: providercontract.ContractVersion, ProjectionDigest: testDigest("2"), OrderedSourceRecordIDs: []string{messageID}, ArtifactDigests: []string{}, VocabularyDigest: testDigest("3"), CompositionDigest: testDigest("4"), SurfaceDigest: testDigest("5"), BindingDigest: testDigest("6")}
}

func testProvider(t *testing.T) providercontract.ProviderIdentity {
	t.Helper()
	var version versionResponse
	if err := decodeExact(readFixture(t, "version.json"), &version); err != nil {
		t.Fatal(err)
	}
	var models modelsResponse
	if err := decodeExact(readFixture(t, "models.json"), &models); err != nil {
		t.Fatal(err)
	}
	_, contextLimit, err := validateModels(models, "qwen3-8b-coh")
	if err != nil {
		t.Fatal(err)
	}
	var info tokenizerInfo
	canonical, err := canonicalJSON(readFixture(t, "tokenizer-info.json"))
	if err != nil || decodeExact(canonical, &info) != nil {
		t.Fatal(err)
	}
	name, tokenizerVersion, template, err := validateTokenizerInfo(info, contextLimit)
	if err != nil {
		t.Fatal(err)
	}
	return providercontract.ProviderIdentity{ProviderKind: "vllm", AdapterVersion: AdapterVersion,
		EndpointIdentityDigest: EndpointIdentityDigest(VLLMEndpoint), DataRoute: "local", RequestedModel: "qwen3-8b-coh",
		ActualModel: "qwen3-8b-coh", ModelRevision: testDigest("a"), RuntimeName: "vLLM",
		RuntimeVersion: version.Version, RuntimeDigest: testDigest("8"),
		TokenizerName: name, TokenizerVersion: tokenizerVersion,
		TokenizerDigest: digest(tokenizerDigestDomain, canonical), ChatTemplateDigest: digest(templateDigestDomain, []byte(template)),
		ToolParserDigest: ToolParserDigest(), ReasoningParserDigest: ReasoningParserDigest(), ContextLimit: contextLimit,
		SamplingProfileDigest: SamplingProfileDigest(), HardwareProfileDigest: testDigest("9"), StateMode: "stateless", PolicyRevision: 7}
}

func qualifiedRegistry(t *testing.T, capability providercontract.ValidatedCapability,
	now time.Time) *providercontract.QualificationRegistry {
	t.Helper()
	cases := make([]providercontract.QualificationCase, 0, 6)
	for index, kind := range []string{"cancellation", "capability", "identity_provenance", "policy_route", "structured_output", "tool_call"} {
		cases = append(cases, providercontract.QualificationCase{Kind: kind, FixtureDigest: testDigest(strconv.Itoa(index + 1)),
			Outcome: "passed", TraceDigest: testDigest(strconv.Itoa(index + 2)), DurationMilliseconds: 1})
	}
	record := providercontract.QualificationRecord{SchemaVersion: providercontract.QualificationSchemaVersion,
		ContractVersion: providercontract.ContractVersion, QualificationID: "0198e300-3000-7000-8000-000000000002",
		IssuedAt: "2026-08-26T05:05:00.000000000Z", ExpiresAt: "2026-09-25T05:05:00.000000000Z",
		Provider: capability.Value().Provider, CapabilityDigest: capability.Digest(),
		ReleaseMatrix: providercontract.ReleaseMatrix{Profile: "native-macos-arm64", OS: "darwin", Architecture: "arm64",
			DeploymentMode: "native", NetworkMode: "restricted_connected"}, Cases: cases, AggregateOutcome: "passed",
		SuiteDigest: testDigest("a"), QualifierIdentityDigest: testDigest("b")}
	encoded, _ := json.Marshal(record)
	qualification, err := providercontract.DecodeQualification(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte("q"), ed25519.SeedSize))
	authority := providercontract.QualifierAuthority{IdentityDigest: record.QualifierIdentityDigest, KeyID: "qualifier-2026",
		KeyRevision: 3, ApprovalRevision: 9, Active: true, Approved: true, PublicKey: privateKey.Public().(ed25519.PublicKey)}
	signature := ed25519.Sign(privateKey, qualificationSignatureMessage(qualification.CanonicalBytes(), authority))
	envelope := providercontract.SignedQualification{SchemaVersion: providercontract.SignedQualificationSchemaVersion,
		ContractVersion: providercontract.ContractVersion, Qualification: qualification.Value(), QualificationDigest: qualification.Digest(),
		QualifierIdentityDigest: authority.IdentityDigest, QualifierKeyID: authority.KeyID, QualifierKeyRevision: authority.KeyRevision,
		QualifierApprovalRevision: authority.ApprovalRevision, SignatureAlgorithm: providercontract.SignatureAlgorithm,
		Signature: base64.RawURLEncoding.EncodeToString(signature)}
	envelopeBytes, _ := json.Marshal(envelope)
	verified, err := providercontract.VerifyQualification(context.Background(), envelopeBytes, authority)
	if err != nil {
		t.Fatal(err)
	}
	registry := providercontract.NewQualificationRegistry()
	if _, err := registry.Admit(context.Background(), capability, verified, now); err != nil {
		t.Fatal(err)
	}
	return registry
}

func qualificationSignatureMessage(qualification []byte, authority providercontract.QualifierAuthority) []byte {
	message := append([]byte("COH-SIGNED-PROVIDER-QUALIFICATION-V1\x00"), qualification...)
	message = append(message, 0)
	message = append(message, authority.IdentityDigest...)
	message = append(message, 0)
	message = append(message, authority.KeyID...)
	message = append(message, 0)
	message = strconv.AppendUint(message, authority.KeyRevision, 10)
	message = append(message, 0)
	return strconv.AppendUint(message, authority.ApprovalRevision, 10)
}

func decodeRequest(t *testing.T, value providercontract.InferenceRequest) providercontract.ValidatedRequest {
	t.Helper()
	encoded, _ := json.Marshal(value)
	validated, err := providercontract.DecodeRequest(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func testDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
