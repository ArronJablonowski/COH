package ollama

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/modelsurface"
	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
	providergateway "github.com/ArronJablonowski/COH/internal/provider"
)

type liveSurfaceStore struct {
	vocabulary []byte
	source     []byte
	snapshot   modelsurface.ContentSnapshot
}

func (store liveSurfaceStore) ReadVocabulary(context.Context, string) ([]byte, bool, error) {
	return append([]byte(nil), store.vocabulary...), true, nil
}

func (store liveSurfaceStore) ReadSource(context.Context, modelsurface.Scope, string, uint64) ([]byte, bool, error) {
	return append([]byte(nil), store.source...), true, nil
}

func (store liveSurfaceStore) ReadDurableRecord(context.Context, modelsurface.Scope, string,
	modelsurface.ContentBinding) (modelsurface.ContentSnapshot, bool, error) {
	return store.snapshot, true, nil
}

func (store liveSurfaceStore) ReadArtifact(context.Context, modelsurface.Scope, string,
	modelsurface.ContentBinding) (modelsurface.ContentSnapshot, bool, error) {
	return modelsurface.ContentSnapshot{}, false, nil
}

type exactLiveRoute struct{ expected observedIdentity }

func (route exactLiveRoute) VerifyLocal(_ context.Context, value LocalRouteObservation) error {
	if value.Endpoint != OllamaEndpoint || value.RuntimeVersion != route.expected.RuntimeVersion ||
		value.Model != route.expected.Model || value.ModelRevision != route.expected.ModelRevision {
		return fmt.Errorf("live loopback identity differs")
	}
	return nil
}

func TestLiveSurfaceGatewayEndToEnd(t *testing.T) {
	if os.Getenv("COH_OLLAMA_LIVE") != "1" {
		t.Skip("set COH_OLLAMA_LIVE=1 for explicit local model invocation")
	}
	model := os.Getenv("COH_OLLAMA_MODEL")
	if model == "" {
		t.Fatal("COH_OLLAMA_MODEL is required")
	}
	now := time.Now().UTC()
	httpClient, err := NewLoopbackHTTPClient(3 * time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	bootstrap := &Adapter{config: Config{Endpoint: OllamaEndpoint, HTTP: httpClient}}
	observed, err := bootstrap.observeIdentity(context.Background(), model)
	if err != nil {
		t.Fatalf("live identity observation: code=%s reason=%s err=%v", Code(err), Reason(err), err)
	}
	identity := providercontract.ProviderIdentity{ProviderKind: "ollama", AdapterVersion: AdapterVersion,
		EndpointIdentityDigest: EndpointIdentityDigest(OllamaEndpoint), DataRoute: "local", RequestedModel: model,
		ActualModel: observed.Model, ModelRevision: observed.ModelRevision, RuntimeName: "ollama",
		RuntimeVersion: observed.RuntimeVersion, RuntimeDigest: observed.RuntimeDigest, TokenizerName: "ollama-model-info",
		TokenizerVersion: observed.RuntimeVersion, TokenizerDigest: observed.ModelInfoDigest,
		ChatTemplateDigest: observed.TemplateDigest, ToolParserDigest: ToolParserDigest(),
		ReasoningParserDigest: ReasoningParserDigest(), ContextLimit: observed.ContextLimit,
		SamplingProfileDigest: SamplingProfileDigest(), HardwareProfileDigest: testDigest("9"),
		StateMode: "stateless", PolicyRevision: 1}
	capability, err := DiscoverCapability(context.Background(), CapabilityDefinition{
		SnapshotID: "0199a300-0000-7000-8000-000000000001", ObservedAt: now.Add(-time.Minute),
		ValidUntil: now.Add(23 * time.Hour), Provider: identity,
		Limits: providercontract.Limits{MaximumInputTokens: 4096, MaximumOutputTokens: 512, MaximumMessages: 16,
			MaximumTools: 4, MaximumParallelToolCalls: 2, MaximumStreamSeconds: 120}})
	if err != nil {
		t.Fatal(err)
	}
	schemaDigest := testDigest("c")
	schema := json.RawMessage(`{"additionalProperties":false,"properties":{"status":{"enum":["LIVE_E2E_OK"],"type":"string"}},"required":["status"],"type":"object"}`)
	reasoning := &reasoningStoreStub{records: make(map[string][]byte)}
	adapter, err := New(Config{Endpoint: OllamaEndpoint, Capability: capability,
		Qualifications: qualifiedRegistry(t, capability, now),
		Schemas:        schemaResolverStub{documents: map[string]json.RawMessage{schemaDigest: schema}}, Reasoning: reasoning,
		Tokens: tokenCounterStub{count: 100}, Route: exactLiveRoute{expected: observed}, HTTP: httpClient,
		Clock: func() time.Time { return time.Now().UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	surface := liveProjectedSurface(t, now)
	strict := true
	scope := surface.Projection().Scope
	template := providercontract.InferenceRequest{SchemaVersion: providercontract.RequestSchemaVersion,
		ContractVersion: providercontract.ContractVersion, RequestID: "0199a300-0000-7000-8000-000000000010",
		AttemptID: "0199a300-0000-7000-8000-000000000011", OrganizationID: scope.OrganizationID,
		TenantID: scope.TenantID, CaseID: scope.CaseID, TaskID: scope.TaskID,
		ActorID: "0199a300-0000-7000-8000-000000000012", Provider: identity,
		CapabilityDigest: capability.Digest(), QualificationID: "0198e300-3000-7000-8000-000000000002",
		OutputConstraint: providercontract.OutputConstraint{Kind: "json_schema", Name: "live_result",
			SchemaDigest: schemaDigest, Strict: &strict}, Sampling: providercontract.Sampling{TemperatureMilli: 0,
			TopPMillionths: 1000000, Seed: 7}, MaximumOutputTokens: 256,
		State: providercontract.State{Mode: "stateless"}, Deadline: formatTimestamp(now.Add(2 * time.Minute)),
		AuthorizationDigest: testDigest("d"), PolicyDecisionDigest: testDigest("e"),
		ApprovalDecisionDigest: testDigest("f"), AuditReservationDigest: testDigest("1")}
	admitted, err := modelsurface.AdmitInference(context.Background(), surface, template)
	if err != nil {
		t.Fatalf("surface admission: %v", err)
	}
	gateway, err := providergateway.NewSurfaceGateway(adapter)
	if err != nil {
		t.Fatal(err)
	}
	response, err := gateway.Invoke(context.Background(), admitted)
	if err != nil {
		t.Fatalf("surface gateway invocation: code=%s reason=%s err=%v", Code(err), Reason(err), err)
	}
	value := response.Value()
	if value.Outcome != "succeeded" || len(value.Items) == 0 || value.Items[0].Kind != "output_json" ||
		string(value.Items[0].Value) != `{"status":"LIVE_E2E_OK"}` || value.ProvenanceDigest == "" ||
		value.Provider.ModelRevision != observed.ModelRevision || value.Usage.InputTokens == 0 || value.Usage.OutputTokens == 0 {
		t.Fatalf("unexpected live response: %+v", value)
	}
	t.Logf("live E2E passed: runtime=%s model=%s revision=%s input_tokens=%d output_tokens=%d binding=%s provenance=%s",
		observed.RuntimeVersion, observed.Model, observed.ModelRevision, value.Usage.InputTokens, value.Usage.OutputTokens,
		admitted.Binding().BindingDigest, value.ProvenanceDigest)
}

func liveProjectedSurface(t *testing.T, now time.Time) modelsurface.ProjectedSurface {
	t.Helper()
	scope := modelsurface.Scope{OrganizationID: "0199a300-0000-7000-8000-000000000020",
		TenantID: "0199a300-0000-7000-8000-000000000021", CaseID: "0199a300-0000-7000-8000-000000000022",
		TaskID: "0199a300-0000-7000-8000-000000000023"}
	runID := "0199a300-0000-7000-8000-000000000024"
	payload, err := modelsurface.CanonicalPayload(modelsurface.SurfacePayload{SchemaVersion: modelsurface.PayloadSchema,
		ContractVersion: modelsurface.ContractVersion, SurfaceKind: "message", Role: "user", ContentKind: "text",
		Content: json.RawMessage(`"Return exactly this JSON object and no other content: {\"status\":\"LIVE_E2E_OK\"}"`)})
	if err != nil {
		t.Fatal(err)
	}
	contentDigest := liveRawDigest(payload)
	definition := modelsurface.EventDefinition{EventType: "live.user.message", EventVersion: 1,
		EventClass: "model_surface", Persistence: "durable", ProducerModule: "live.test",
		ConsumerModules: []string{"model.projector"}, ProjectionRule: "message", PayloadSchemaDigest: testDigest("2")}
	vocabulary, vocabularyDigest, err := modelsurface.CanonicalVocabulary(context.Background(), modelsurface.EventVocabulary{
		SchemaVersion: modelsurface.VocabularySchema, ContractVersion: modelsurface.ContractVersion,
		VocabularyRevision: 1, Definitions: []modelsurface.EventDefinition{definition}})
	if err != nil {
		t.Fatal(err)
	}
	source := modelsurface.Source{SchemaVersion: modelsurface.SourceSchema, ContractVersion: modelsurface.ContractVersion,
		SourceRecordID: "0199a300-0000-7000-8000-000000000025", EventType: definition.EventType,
		EventVersion: 1, EventClass: "model_surface", ProjectionRule: "message", Scope: scope, RunID: runID,
		RecordRevision: 1, RecordDigest: testDigest("3"), Content: modelsurface.ContentBinding{Kind: "durable_record",
			ContentID: "live.prompt", Digest: contentDigest, MediaType: "application/json", Length: uint64(len(payload)),
			Classification: "restricted", Immutable: true}, Trust: "trusted_user",
		InstructionDisposition: "trusted_user_instruction", OccurredAt: formatTimestamp(now), Sequence: 1, Immutable: true}
	sourceBytes, sourceDigest, err := modelsurface.CanonicalSource(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	store := liveSurfaceStore{vocabulary: vocabulary, source: sourceBytes,
		snapshot: modelsurface.ContentSnapshot{Scope: scope, RunID: runID, Kind: source.Content.Kind,
			ContentID: source.Content.ContentID, Digest: contentDigest, MediaType: source.Content.MediaType,
			Classification: source.Content.Classification, Immutable: true, Bytes: payload}}
	resolver, err := modelsurface.NewResolver(store, store, store, store)
	if err != nil {
		t.Fatal(err)
	}
	projector, err := modelsurface.NewProjector(resolver)
	if err != nil {
		t.Fatal(err)
	}
	projected, err := projector.Project(context.Background(), modelsurface.ProjectionRequest{
		ProjectionID: "0199a300-0000-7000-8000-000000000026", Scope: scope, RunID: runID,
		VocabularyDigest: vocabularyDigest, CompositionDigest: testDigest("4"),
		Sources: []modelsurface.SourceReference{{SourceRecordID: source.SourceRecordID,
			RecordRevision: source.RecordRevision, SourceDigest: sourceDigest}}, CreatedAt: formatTimestamp(now)})
	if err != nil {
		t.Fatal(err)
	}
	return projected
}

func liveRawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
