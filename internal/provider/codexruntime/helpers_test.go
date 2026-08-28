package codexruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

type schemaStub struct{ docs map[string]json.RawMessage }

func (s schemaStub) Resolve(_ context.Context, digest string) (SchemaDocument, error) {
	return SchemaDocument{Digest: digest, JSON: append(json.RawMessage(nil), s.docs[digest]...)}, nil
}

type toolStub struct {
	calls  []ToolCall
	result ToolResult
	err    error
}

func (s *toolStub) Call(_ context.Context, call ToolCall) (ToolResult, error) {
	s.calls = append(s.calls, call)
	return s.result, s.err
}

type reasoningStub struct {
	mu      sync.Mutex
	records map[string][]byte
}

func (s *reasoningStub) Put(_ context.Context, ref, digest string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[ref+"\x00"+digest] = append([]byte(nil), value...)
	return nil
}

type transportStub struct {
	mu       sync.Mutex
	incoming [][]byte
	sent     [][]byte
	closed   bool
	block    bool
}

func (s *transportStub) Send(_ context.Context, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, append([]byte(nil), value...))
	return nil
}
func (s *transportStub) Receive(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	if len(s.incoming) == 0 {
		s.mu.Unlock()
		if s.block {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, io.EOF
	}
	value := s.incoming[0]
	s.incoming = s.incoming[1:]
	s.mu.Unlock()
	return append([]byte(nil), value...), nil
}
func (s *transportStub) Close() error { s.closed = true; return nil }

type factoryStub struct {
	transport   *transportStub
	observation LaunchObservation
	err         error
}

func (s factoryStub) Open(context.Context) (RPCTransport, LaunchObservation, error) {
	return s.transport, s.observation, s.err
}

type batchStub struct {
	result     BatchResult
	err        error
	invocation BatchInvocation
}

func (s *batchStub) Run(_ context.Context, value BatchInvocation) (BatchResult, error) {
	s.invocation = value
	return s.result, s.err
}

type testRig struct {
	adapter   *Adapter
	request   providercontract.ValidatedRequest
	transport *transportStub
	tools     *toolStub
	batch     *batchStub
	clock     time.Time
}

func newRig(t *testing.T) testRig {
	t.Helper()
	clock := mustTime(t, "2026-08-26T15:40:00.000000000Z")
	provider := testProvider("codex-app-server")
	capability, err := DiscoverCapability(context.Background(), CapabilityDefinition{SnapshotID: "0199a213-81c0-7800-8aa1-bbab2a035a50", ObservedAt: mustTime(t, "2026-08-26T15:00:00.000000000Z"), ValidUntil: mustTime(t, "2026-08-27T15:00:00.000000000Z"), Provider: provider, Limits: providercontract.Limits{MaximumInputTokens: 300000, MaximumOutputTokens: 64000, MaximumMessages: 512, MaximumTools: 32, MaximumParallelToolCalls: 4, MaximumStreamSeconds: 900}})
	if err != nil {
		t.Fatal(err)
	}
	input, output, structured := testDigest("1"), testDigest("2"), testDigest("3")
	schema := json.RawMessage(`{"type":"object","properties":{"host":{"type":"string"}},"required":["host"],"additionalProperties":false}`)
	outSchema := json.RawMessage(`{"type":"object","properties":{"reachable":{"type":"boolean"}},"required":["reachable"],"additionalProperties":false}`)
	structuredSchema := json.RawMessage(`{"type":"object","properties":{"result":{"type":"string"}},"required":["result"],"additionalProperties":false}`)
	toolValue := json.RawMessage(`{"reachable":true}`)
	resultDigest, _ := providercontract.DigestToolResult(toolValue)
	tools := &toolStub{result: ToolResult{Outcome: "succeeded", Value: toolValue, ResultDigest: resultDigest}}
	transport := &transportStub{incoming: readJSONLines(t, "app-server.jsonl")}
	batch := &batchStub{result: BatchResult{JSONL: readFixture(t, "exec.jsonl"), ExitCode: 0, Observation: testObservation("exec-jsonl", provider)}}
	reasoning := &reasoningStub{records: map[string][]byte{}}
	tick := uint64(0)
	adapter, err := New(Config{Capability: capability, Qualifications: qualifiedRegistry(t, capability, clock), Schemas: schemaStub{docs: map[string]json.RawMessage{input: schema, output: outSchema, structured: structuredSchema}}, Tools: tools, Reasoning: reasoning, Factory: factoryStub{transport: transport, observation: testObservation("stdio", provider)}, Batch: batch, Clock: func() time.Time { value := clock.Add(time.Duration(tick) * time.Nanosecond); tick++; return value }, Workspace: "/workspace"})
	if err != nil {
		t.Fatal(err)
	}
	request := providercontract.InferenceRequest{SchemaVersion: providercontract.RequestSchemaVersion, ContractVersion: providercontract.ContractVersion, RequestID: "0199a213-81c0-7800-8aa1-bbab2a035a56", AttemptID: "0199a213-81c0-7800-8aa1-bbab2a035a57", OrganizationID: "0199a213-81c0-7800-8aa1-bbab2a035a58", TenantID: "0199a213-81c0-7800-8aa1-bbab2a035a59", CaseID: "0199a213-81c0-7800-8aa1-bbab2a035a60", TaskID: "0199a213-81c0-7800-8aa1-bbab2a035a61", ActorID: "0199a213-81c0-7800-8aa1-bbab2a035a62", Provider: provider, CapabilityDigest: capability.Digest(), QualificationID: "0199a213-81c0-7800-8aa1-bbab2a035a51", ModelSurface: testSurfaceBinding("0199a213-81c0-7800-8aa1-bbab2a035a63"), Messages: []providercontract.Message{{MessageID: "0199a213-81c0-7800-8aa1-bbab2a035a63", Role: "user", Items: []providercontract.ContentItem{{Kind: "text", Text: "Inspect the host."}}}}, Tools: []providercontract.Tool{{Name: "query_host", Description: "Query one host.", InputSchemaDigest: input, OutputSchemaDigest: output}}, OutputConstraint: providercontract.OutputConstraint{Kind: "text"}, Sampling: providercontract.Sampling{TemperatureMilli: 0, TopPMillionths: 1000000, Seed: 0}, MaximumOutputTokens: 1024, State: providercontract.State{Mode: "stateless"}, Deadline: "2026-08-26T15:50:00.000000000Z", AuthorizationDigest: testDigest("4"), PolicyDecisionDigest: testDigest("5"), ApprovalDecisionDigest: testDigest("6"), AuditReservationDigest: testDigest("7")}
	return testRig{adapter: adapter, request: decodeRequest(t, request), transport: transport, tools: tools, batch: batch, clock: clock}
}

func testProvider(mode string) providercontract.ProviderIdentity {
	return providercontract.ProviderIdentity{ProviderKind: "codex_runtime", AdapterVersion: AdapterVersion, EndpointIdentityDigest: EndpointIdentityDigest(mode, "/workspace"), DataRoute: "approved_external", RequestedModel: "gpt-5.6-terra", ActualModel: "gpt-5.6-terra", ModelRevision: testDigest("a"), RuntimeName: mode, RuntimeVersion: RuntimeVersion, RuntimeDigest: RuntimeDigest, TokenizerName: "openai-managed", TokenizerVersion: "1.0.0", TokenizerDigest: testDigest("b"), ChatTemplateDigest: testDigest("c"), ToolParserDigest: ToolParserDigest(), ReasoningParserDigest: ReasoningParserDigest(), ContextLimit: 400000, SamplingProfileDigest: SamplingProfileDigest(), HardwareProfileDigest: testDigest("9"), StateMode: "stateless", PolicyRevision: 7}
}

func testSurfaceBinding(messageID string) providercontract.ModelSurfaceBinding {
	return providercontract.ModelSurfaceBinding{RunID: "0199a213-81c0-7800-8aa1-bbab2a035a64", ProviderID: "codex_runtime.approved_external", ProjectionID: "0199a213-81c0-7800-8aa1-bbab2a035a65", ProjectionVersion: providercontract.ContractVersion, ProjectionDigest: testDigest("1"), OrderedSourceRecordIDs: []string{messageID}, ArtifactDigests: []string{}, VocabularyDigest: testDigest("2"), CompositionDigest: testDigest("3"), SurfaceDigest: testDigest("8"), BindingDigest: testDigest("9")}
}
func testObservation(mode string, p providercontract.ProviderIdentity) LaunchObservation {
	return LaunchObservation{RuntimeVersion: RuntimeVersion, RuntimeDigest: RuntimeDigest, ProtocolDigest: ProtocolDigest, Model: p.ActualModel, ModelRevision: p.ModelRevision, Workspace: "/workspace", Transport: mode, Sandbox: "read-only", ApprovalPolicy: "untrusted", NetworkMode: "connected", ConfigDigest: p.ChatTemplateDigest, EnvironmentDigest: p.HardwareProfileDigest, CredentialMode: "invocation-scoped", ExperimentalSurface: map[bool]string{true: "tools-disabled", false: "dynamicTools-only"}[mode == "exec-jsonl"], CodexHome: "/managed/codex-home", ConfigMode: "managed-isolated", RulesMode: "disabled", HooksMode: "disabled", MCPMode: map[bool]string{true: "disabled", false: "broker-only"}[mode == "exec-jsonl"], WebSearchMode: "disabled", MutationMode: "disabled", EnvironmentMode: "allowlist"}
}

func qualifiedRegistry(t *testing.T, cap providercontract.ValidatedCapability, now time.Time) *providercontract.QualificationRegistry {
	t.Helper()
	cases := []providercontract.QualificationCase{}
	for i, kind := range []string{"cancellation", "capability", "identity_provenance", "policy_route", "structured_output", "tool_call"} {
		cases = append(cases, providercontract.QualificationCase{Kind: kind, FixtureDigest: testDigest(strconv.Itoa(i + 1)), Outcome: "passed", TraceDigest: testDigest(strconv.Itoa(i + 2)), DurationMilliseconds: 1})
	}
	record := providercontract.QualificationRecord{SchemaVersion: providercontract.QualificationSchemaVersion, ContractVersion: providercontract.ContractVersion, QualificationID: "0199a213-81c0-7800-8aa1-bbab2a035a51", IssuedAt: "2026-08-26T15:05:00.000000000Z", ExpiresAt: "2026-09-25T15:05:00.000000000Z", Provider: cap.Value().Provider, CapabilityDigest: cap.Digest(), ReleaseMatrix: providercontract.ReleaseMatrix{Profile: "native-linux-amd64", OS: "linux", Architecture: "amd64", DeploymentMode: "dedicated", NetworkMode: "connected"}, Cases: cases, AggregateOutcome: "passed", SuiteDigest: testDigest("d"), QualifierIdentityDigest: testDigest("e")}
	encoded, _ := json.Marshal(record)
	qualification, err := providercontract.DecodeQualification(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte("q"), ed25519.SeedSize))
	authority := providercontract.QualifierAuthority{IdentityDigest: record.QualifierIdentityDigest, KeyID: "qualifier-2026", KeyRevision: 3, ApprovalRevision: 9, Active: true, Approved: true, PublicKey: private.Public().(ed25519.PublicKey)}
	signature := ed25519.Sign(private, qualificationSignatureMessage(qualification.CanonicalBytes(), authority))
	envelope := providercontract.SignedQualification{SchemaVersion: providercontract.SignedQualificationSchemaVersion, ContractVersion: providercontract.ContractVersion, Qualification: qualification.Value(), QualificationDigest: qualification.Digest(), QualifierIdentityDigest: authority.IdentityDigest, QualifierKeyID: authority.KeyID, QualifierKeyRevision: authority.KeyRevision, QualifierApprovalRevision: authority.ApprovalRevision, SignatureAlgorithm: providercontract.SignatureAlgorithm, Signature: base64.RawURLEncoding.EncodeToString(signature)}
	envelopeBytes, _ := json.Marshal(envelope)
	verified, err := providercontract.VerifyQualification(context.Background(), envelopeBytes, authority)
	if err != nil {
		t.Fatal(err)
	}
	registry := providercontract.NewQualificationRegistry()
	if _, err := registry.Admit(context.Background(), cap, verified, now); err != nil {
		t.Fatal(err)
	}
	return registry
}
func qualificationSignatureMessage(q []byte, a providercontract.QualifierAuthority) []byte {
	message := append([]byte("COH-SIGNED-PROVIDER-QUALIFICATION-V1\x00"), q...)
	message = append(message, 0)
	message = append(message, a.IdentityDigest...)
	message = append(message, 0)
	message = append(message, a.KeyID...)
	message = append(message, 0)
	message = strconv.AppendUint(message, a.KeyRevision, 10)
	message = append(message, 0)
	return strconv.AppendUint(message, a.ApprovalRevision, 10)
}
func decodeRequest(t *testing.T, value providercontract.InferenceRequest) providercontract.ValidatedRequest {
	t.Helper()
	encoded, _ := json.Marshal(value)
	result, err := providercontract.DecodeRequest(context.Background(), encoded)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	value, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func readJSONLines(t *testing.T, name string) [][]byte {
	t.Helper()
	scanner := bufio.NewScanner(bytes.NewReader(readFixture(t, name)))
	values := [][]byte{}
	for scanner.Scan() {
		values = append(values, append([]byte(nil), scanner.Bytes()...))
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return values
}
func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse("2006-01-02T15:04:05.000000000Z", value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
func testDigest(c string) string { return "sha256:" + strings.Repeat(c, 64) }
