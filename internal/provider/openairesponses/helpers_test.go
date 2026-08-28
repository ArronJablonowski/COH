package openairesponses

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
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

type credentialResolverStub struct {
	value []byte
	err   error
}

func (stub credentialResolverStub) Resolve(context.Context, string) (Credential, error) {
	if stub.err != nil {
		return Credential{}, stub.err
	}
	return NewCredential(stub.value), nil
}

type schemaResolverStub struct {
	documents map[string]json.RawMessage
}

func (stub schemaResolverStub) Resolve(_ context.Context, digest string) (SchemaDocument, error) {
	return SchemaDocument{Digest: digest, JSON: append(json.RawMessage(nil), stub.documents[digest]...)}, nil
}

type tokenCounterStub struct {
	count uint64
	err   error
}

func (stub tokenCounterStub) Count(context.Context, providercontract.ValidatedRequest) (uint64, error) {
	return stub.count, stub.err
}

type reasoningStoreStub struct {
	mu      sync.Mutex
	records map[string][]byte
}

func (stub *reasoningStoreStub) Put(_ context.Context, reference, digest string, value []byte) error {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.records[reference+"\x00"+digest] = append([]byte(nil), value...)
	return nil
}

func (stub *reasoningStoreStub) Resolve(_ context.Context, reference, digest string) ([]byte, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return append([]byte(nil), stub.records[reference+"\x00"+digest]...), nil
}

type httpStub struct {
	status               int
	body                 []byte
	contentType          string
	tls                  *tls.ConnectionState
	err                  error
	request              *http.Request
	requestBody          []byte
	authorizationPresent bool
	deadline             time.Time
}

func (stub *httpStub) Do(request *http.Request) (*http.Response, error) {
	stub.request = request
	stub.authorizationPresent = request.Header.Get("Authorization") != ""
	stub.deadline, _ = request.Context().Deadline()
	if request.Body != nil {
		stub.requestBody, _ = io.ReadAll(request.Body)
	}
	if stub.err != nil {
		return nil, stub.err
	}
	contentType := stub.contentType
	if contentType == "" {
		contentType = "application/json"
	}
	state := stub.tls
	if state == nil {
		state = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, ServerName: "api.openai.com"}
	}
	return &http.Response{StatusCode: stub.status, Body: io.NopCloser(bytes.NewReader(stub.body)), Request: request,
		Header: http.Header{"Content-Type": []string{contentType}}, TLS: state}, nil
}

type testRig struct {
	adapter   *Adapter
	request   providercontract.ValidatedRequest
	http      *httpStub
	reasoning *reasoningStoreStub
	schemas   schemaResolverStub
	registry  *providercontract.QualificationRegistry
	clock     time.Time
}

func newTestRig(t *testing.T, fixture string) testRig {
	t.Helper()
	clock := mustTime(t, "2026-08-26T06:10:00.000000000Z")
	provider := testProvider()
	capability, err := DiscoverCapability(context.Background(), CapabilityDefinition{
		SnapshotID: "0198e300-2000-7000-8000-000000000001", ObservedAt: mustTime(t, "2026-08-26T05:00:00.000000000Z"),
		ValidUntil: mustTime(t, "2026-08-27T05:00:00.000000000Z"), Provider: provider,
		Limits: providercontract.Limits{MaximumInputTokens: 24576, MaximumOutputTokens: 8192, MaximumMessages: 512,
			MaximumTools: 32, MaximumParallelToolCalls: 4, MaximumStreamSeconds: 600}})
	if err != nil {
		t.Fatal(err)
	}
	registry := qualifiedRegistry(t, capability, clock)
	inputDigest, outputDigest, structuredDigest := testDigest("a"), testDigest("b"), testDigest("c")
	strictSchema := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"host":{"type":"string"}},"required":["host"]}`)
	structuredSchema := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"verdict":{"type":"string"}},"required":["verdict"]}`)
	schemas := schemaResolverStub{documents: map[string]json.RawMessage{
		inputDigest: strictSchema, outputDigest: strictSchema, structuredDigest: structuredSchema,
	}}
	reasoning := &reasoningStoreStub{records: make(map[string][]byte)}
	httpClient := &httpStub{status: http.StatusOK, body: readFixture(t, fixture)}
	config := Config{Endpoint: ResponsesEndpoint, CredentialReference: "openai.primary",
		Credentials: credentialResolverStub{value: []byte(strings.Repeat("x", 32))}, Capability: capability,
		Qualifications: registry, Schemas: schemas, Reasoning: reasoning, Tokens: tokenCounterStub{count: 100},
		HTTP: httpClient, Clock: func() time.Time { return clock }}
	adapter, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	request := providercontract.InferenceRequest{SchemaVersion: providercontract.RequestSchemaVersion,
		ContractVersion: providercontract.ContractVersion, RequestID: "0198e300-2000-7000-8000-000000000003",
		AttemptID: "0198e300-2000-7000-8000-000000000004", OrganizationID: "0198e300-2000-7000-8000-000000000005",
		TenantID: "0198e300-2000-7000-8000-000000000006", CaseID: "0198e300-2000-7000-8000-000000000007",
		TaskID: "0198e300-2000-7000-8000-000000000008", ActorID: "0198e300-2000-7000-8000-000000000009",
		Provider: provider, CapabilityDigest: capability.Digest(), QualificationID: "0198e300-2000-7000-8000-000000000002",
		ModelSurface: testSurfaceBinding("0198e300-2000-7000-8000-000000000010"),
		Messages: []providercontract.Message{{MessageID: "0198e300-2000-7000-8000-000000000010", Role: "user",
			Items: []providercontract.ContentItem{{Kind: "text", Text: "Inspect the host."}}}},
		Tools: []providercontract.Tool{{Name: "query_host", Description: "Query one host.", InputSchemaDigest: inputDigest,
			OutputSchemaDigest: outputDigest}}, OutputConstraint: providercontract.OutputConstraint{Kind: "text"},
		Sampling: providercontract.Sampling{TemperatureMilli: 200, TopPMillionths: 900000}, MaximumOutputTokens: 1024,
		State: providercontract.State{Mode: "stateless"}, Deadline: "2026-08-26T06:30:00.000000000Z",
		AuthorizationDigest: testDigest("d"), PolicyDecisionDigest: testDigest("e"), ApprovalDecisionDigest: testDigest("f"),
		AuditReservationDigest: testDigest("1")}
	return testRig{adapter: adapter, request: decodeRequest(t, request), http: httpClient, reasoning: reasoning,
		schemas: schemas, registry: registry, clock: clock}
}

func testSurfaceBinding(messageID string) providercontract.ModelSurfaceBinding {
	return providercontract.ModelSurfaceBinding{RunID: "0198e300-2000-7000-8000-000000000020", ProviderID: "openai_responses.approved_external", ProjectionID: "0198e300-2000-7000-8000-000000000021", ProjectionVersion: providercontract.ContractVersion, ProjectionDigest: testDigest("2"), OrderedSourceRecordIDs: []string{messageID}, ArtifactDigests: []string{}, VocabularyDigest: testDigest("3"), CompositionDigest: testDigest("4"), SurfaceDigest: testDigest("5"), BindingDigest: testDigest("6")}
}

func testProvider() providercontract.ProviderIdentity {
	return providercontract.ProviderIdentity{ProviderKind: "openai_responses", AdapterVersion: AdapterVersion,
		EndpointIdentityDigest: EndpointIdentityDigest(ResponsesEndpoint), DataRoute: "approved_external",
		RequestedModel: "gpt-5.6", ActualModel: "gpt-5.6", ModelRevision: testDigest("2"),
		RuntimeName: "openai-responses", RuntimeVersion: "1.0.0", RuntimeDigest: testDigest("3"),
		TokenizerName: "openai-tokenizer", TokenizerVersion: "1.0.0", TokenizerDigest: testDigest("4"),
		ChatTemplateDigest: testDigest("5"), ToolParserDigest: testDigest("6"), ReasoningParserDigest: testDigest("7"),
		ContextLimit: 32768, SamplingProfileDigest: testDigest("8"), HardwareProfileDigest: testDigest("9"),
		StateMode: "stateless", PolicyRevision: 7}
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
		ContractVersion: providercontract.ContractVersion, QualificationID: "0198e300-2000-7000-8000-000000000002",
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
	seed := bytes.Repeat([]byte("q"), ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
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
