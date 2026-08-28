// cohollamabench is a local, test-only invocation surface for measuring the
// complete COH model-surface and Ollama provider path. It is not a production
// qualification authority or deployment entry point.
package ollama_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/modelsurface"
	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
	providergateway "github.com/ArronJablonowski/COH/internal/provider"
	"github.com/ArronJablonowski/COH/internal/provider/ollama"
)

const benchmarkVersion = "0.1.0"

type surfaceStore struct {
	vocabulary []byte
	source     []byte
	snapshot   modelsurface.ContentSnapshot
}

func (store surfaceStore) ReadVocabulary(context.Context, string) ([]byte, bool, error) {
	return append([]byte(nil), store.vocabulary...), true, nil
}
func (store surfaceStore) ReadSource(context.Context, modelsurface.Scope, string, uint64) ([]byte, bool, error) {
	return append([]byte(nil), store.source...), true, nil
}
func (store surfaceStore) ReadDurableRecord(context.Context, modelsurface.Scope, string,
	modelsurface.ContentBinding) (modelsurface.ContentSnapshot, bool, error) {
	return store.snapshot, true, nil
}
func (store surfaceStore) ReadArtifact(context.Context, modelsurface.Scope, string,
	modelsurface.ContentBinding) (modelsurface.ContentSnapshot, bool, error) {
	return modelsurface.ContentSnapshot{}, false, nil
}

type schemaResolver struct{}

func (schemaResolver) Resolve(context.Context, string) (ollama.SchemaDocument, error) {
	return ollama.SchemaDocument{}, errors.New("benchmark has no provider-visible schemas")
}

type reasoningStore struct {
	mu      sync.Mutex
	records map[string][]byte
}

func (store *reasoningStore) Put(_ context.Context, reference, digest string, value []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records[reference+"\x00"+digest] = append([]byte(nil), value...)
	return nil
}
func (store *reasoningStore) Resolve(_ context.Context, reference, digest string) ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	value, ok := store.records[reference+"\x00"+digest]
	if !ok {
		return nil, errors.New("reasoning reference not found")
	}
	return append([]byte(nil), value...), nil
}

type conservativeTokenCounter struct{}

func (conservativeTokenCounter) Count(_ context.Context, request providercontract.ValidatedRequest) (uint64, error) {
	value := request.Value()
	count := uint64(64)
	for _, message := range value.Messages {
		count += uint64(len(message.Role) + len(message.MessageID) + 8)
		for _, item := range message.Items {
			count += uint64(len(item.Text) + len(item.Value) + len(item.Arguments) + 8)
		}
	}
	return count, nil
}

type exactRoute struct {
	provider providercontract.ProviderIdentity
}

func (route exactRoute) VerifyLocal(_ context.Context, value ollama.LocalRouteObservation) error {
	if value.Endpoint != ollama.OllamaEndpoint || value.RuntimeVersion != route.provider.RuntimeVersion ||
		value.Model != route.provider.ActualModel || value.ModelRevision != route.provider.ModelRevision {
		return errors.New("loopback route identity changed")
	}
	return nil
}

type provenance struct {
	HarnessVersion   string                 `json:"harness_version"`
	AdapterVersion   string                 `json:"adapter_version"`
	VendorSurface    string                 `json:"vendor_surface"`
	RuntimeVersion   string                 `json:"runtime_version"`
	Model            string                 `json:"model"`
	ModelRevision    string                 `json:"model_revision"`
	CapabilityDigest string                 `json:"capability_digest"`
	BindingDigest    string                 `json:"binding_digest"`
	ProvenanceDigest string                 `json:"provenance_digest"`
	Usage            providercontract.Usage `json:"usage"`
}

func TestMain(tests *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(benchmarkVersion)
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "--invoke" {
		os.Exit(tests.Run())
	}
	flags := flag.NewFlagSet("cohollamabench", flag.ContinueOnError)
	model := flags.String("model", "", "exact installed Ollama model tag")
	prompt := flags.String("prompt", "", "single user prompt")
	timeout := flags.Duration("timeout", 30*time.Minute, "invocation deadline")
	maximumOutput := flags.Uint64("max-output-tokens", 8192, "maximum output tokens")
	if flags.Parse(os.Args[2:]) != nil {
		os.Exit(2)
	}
	if *model == "" || *prompt == "" || *timeout < time.Second || *timeout > 30*time.Minute || *maximumOutput == 0 {
		fmt.Fprintln(os.Stderr, "model, prompt, positive output limit, and timeout up to 30m are required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	text, evidence, err := invoke(ctx, *model, *prompt, *timeout, *maximumOutput)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded, _ := json.Marshal(evidence)
	fmt.Fprintln(os.Stderr, string(encoded))
	fmt.Print(text)
}

func invoke(ctx context.Context, model, prompt string, timeout time.Duration,
	maximumOutput uint64) (string, provenance, error) {
	now := time.Now().UTC()
	hardwareDigest := rawDigest([]byte("COH-OLLAMA-BENCH-HARDWARE-V1\x00" + runtime.GOOS + "\x00" + runtime.GOARCH))
	httpClient, err := ollama.NewLoopbackHTTPClient(timeout)
	if err != nil {
		return "", provenance{}, err
	}
	observation, err := ollama.ObserveLocalIdentity(ctx, model, httpClient, hardwareDigest, 1)
	if err != nil {
		return "", provenance{}, fmt.Errorf("identity observation: %w", err)
	}
	if maximumOutput >= observation.Provider.ContextLimit {
		return "", provenance{}, errors.New("maximum output consumes the model context")
	}
	maximumInput := observation.Provider.ContextLimit - maximumOutput
	if maximumInput > 24576 {
		maximumInput = 24576
	}
	capability, err := ollama.DiscoverCapability(ctx, ollama.CapabilityDefinition{
		SnapshotID: deterministicUUID("capability", observation.Provider.ModelRevision), ObservedAt: now.Add(-time.Minute),
		ValidUntil: now.Add(23 * time.Hour), Provider: observation.Provider,
		Limits: providercontract.Limits{MaximumInputTokens: maximumInput, MaximumOutputTokens: maximumOutput,
			MaximumMessages: 16, MaximumTools: 4, MaximumParallelToolCalls: 2,
			MaximumStreamSeconds: uint32(timeout / time.Second)}})
	if err != nil {
		return "", provenance{}, fmt.Errorf("capability discovery: %w", err)
	}
	qualificationID := deterministicUUID("qualification", capability.Digest())
	registry, err := ephemeralQualification(ctx, capability, qualificationID, now)
	if err != nil {
		return "", provenance{}, err
	}
	reasoning := &reasoningStore{records: make(map[string][]byte)}
	adapter, err := ollama.New(ollama.Config{Endpoint: ollama.OllamaEndpoint, Capability: capability,
		Qualifications: registry, Schemas: schemaResolver{}, Reasoning: reasoning, Tokens: conservativeTokenCounter{},
		Route: exactRoute{provider: observation.Provider}, HTTP: httpClient,
		Clock: func() time.Time { return time.Now().UTC() },
		DisableReasoning: !slices.Contains(observation.Capabilities, "thinking")})
	if err != nil {
		return "", provenance{}, err
	}
	surface, err := projectedPrompt(ctx, model, prompt, now)
	if err != nil {
		return "", provenance{}, err
	}
	scope := surface.Projection().Scope
	key := model + "\x00" + prompt
	template := providercontract.InferenceRequest{SchemaVersion: providercontract.RequestSchemaVersion,
		ContractVersion: providercontract.ContractVersion, RequestID: deterministicUUID("request", key),
		AttemptID: deterministicUUID("attempt", key), OrganizationID: scope.OrganizationID, TenantID: scope.TenantID,
		CaseID: scope.CaseID, TaskID: scope.TaskID, ActorID: deterministicUUID("actor", key), Provider: observation.Provider,
		CapabilityDigest: capability.Digest(), QualificationID: qualificationID,
		OutputConstraint: providercontract.OutputConstraint{Kind: "text"}, Sampling: providercontract.Sampling{
			TemperatureMilli: 0, TopPMillionths: 1000000, Seed: 42}, MaximumOutputTokens: maximumOutput,
		State: providercontract.State{Mode: "stateless"}, Deadline: timestamp(now.Add(timeout)),
		AuthorizationDigest:  rawDigest([]byte("benchmark-authorization")),
		PolicyDecisionDigest: rawDigest([]byte("benchmark-policy")), ApprovalDecisionDigest: rawDigest([]byte("benchmark-approval")),
		AuditReservationDigest: rawDigest([]byte("benchmark-audit"))}
	admitted, err := modelsurface.AdmitInference(ctx, surface, template)
	if err != nil {
		return "", provenance{}, fmt.Errorf("surface admission: %w", err)
	}
	gateway, err := providergateway.NewSurfaceGateway(adapter)
	if err != nil {
		return "", provenance{}, err
	}
	response, err := gateway.Invoke(ctx, admitted)
	if err != nil {
		return "", provenance{}, fmt.Errorf("gateway invocation: %w", err)
	}
	value := response.Value()
	if value.Outcome != "succeeded" && value.Outcome != "uncertain" {
		return "", provenance{}, fmt.Errorf("provider outcome: %s", value.Outcome)
	}
	var output bytes.Buffer
	for _, item := range value.Items {
		if item.Kind == "text" {
			output.WriteString(item.Text)
		} else if item.Kind == "output_json" {
			output.Write(item.Value)
		}
	}
	if output.Len() == 0 {
		return "", provenance{}, errors.New("provider returned no visible answer")
	}
	return output.String(), provenance{HarnessVersion: benchmarkVersion, AdapterVersion: ollama.AdapterVersion,
		VendorSurface: ollama.VendorSurfaceVersion, RuntimeVersion: observation.Provider.RuntimeVersion,
		Model: observation.Provider.ActualModel, ModelRevision: observation.Provider.ModelRevision,
		CapabilityDigest: capability.Digest(), BindingDigest: admitted.Binding().BindingDigest,
		ProvenanceDigest: value.ProvenanceDigest, Usage: value.Usage}, nil
}

func projectedPrompt(ctx context.Context, model, prompt string, now time.Time) (modelsurface.ProjectedSurface, error) {
	key := model + "\x00" + prompt
	scope := modelsurface.Scope{OrganizationID: deterministicUUID("organization", key),
		TenantID: deterministicUUID("tenant", key), CaseID: deterministicUUID("case", key),
		TaskID: deterministicUUID("task", key)}
	runID := deterministicUUID("run", key)
	content, err := json.Marshal(prompt)
	if err != nil {
		return modelsurface.ProjectedSurface{}, err
	}
	payload, err := modelsurface.CanonicalPayload(modelsurface.SurfacePayload{SchemaVersion: modelsurface.PayloadSchema,
		ContractVersion: modelsurface.ContractVersion, SurfaceKind: "message", Role: "user", ContentKind: "text", Content: content})
	if err != nil {
		return modelsurface.ProjectedSurface{}, err
	}
	definition := modelsurface.EventDefinition{EventType: "benchmark.user.message", EventVersion: 1,
		EventClass: "model_surface", Persistence: "durable", ProducerModule: "cohollamabench",
		ConsumerModules: []string{"model.projector"}, ProjectionRule: "message", PayloadSchemaDigest: rawDigest([]byte("benchmark-payload-schema"))}
	vocabulary, vocabularyDigest, err := modelsurface.CanonicalVocabulary(ctx, modelsurface.EventVocabulary{
		SchemaVersion: modelsurface.VocabularySchema, ContractVersion: modelsurface.ContractVersion,
		VocabularyRevision: 1, Definitions: []modelsurface.EventDefinition{definition}})
	if err != nil {
		return modelsurface.ProjectedSurface{}, err
	}
	contentDigest := rawDigest(payload)
	source := modelsurface.Source{SchemaVersion: modelsurface.SourceSchema, ContractVersion: modelsurface.ContractVersion,
		SourceRecordID: deterministicUUID("source", key), EventType: definition.EventType, EventVersion: 1,
		EventClass: "model_surface", ProjectionRule: "message", Scope: scope, RunID: runID, RecordRevision: 1,
		RecordDigest: rawDigest([]byte("benchmark-source-record" + key)), Content: modelsurface.ContentBinding{Kind: "durable_record",
			ContentID: "benchmark.prompt", Digest: contentDigest, MediaType: "application/json", Length: uint64(len(payload)),
			Classification: "restricted", Immutable: true}, Trust: "trusted_user",
		InstructionDisposition: "trusted_user_instruction", OccurredAt: timestamp(now), Sequence: 1, Immutable: true}
	sourceBytes, sourceDigest, err := modelsurface.CanonicalSource(ctx, source)
	if err != nil {
		return modelsurface.ProjectedSurface{}, err
	}
	store := surfaceStore{vocabulary: vocabulary, source: sourceBytes,
		snapshot: modelsurface.ContentSnapshot{Scope: scope, RunID: runID, Kind: source.Content.Kind,
			ContentID: source.Content.ContentID, Digest: contentDigest, MediaType: source.Content.MediaType,
			Classification: source.Content.Classification, Immutable: true, Bytes: payload}}
	resolver, err := modelsurface.NewResolver(store, store, store, store)
	if err != nil {
		return modelsurface.ProjectedSurface{}, err
	}
	projector, err := modelsurface.NewProjector(resolver)
	if err != nil {
		return modelsurface.ProjectedSurface{}, err
	}
	return projector.Project(ctx, modelsurface.ProjectionRequest{ProjectionID: deterministicUUID("projection", key),
		Scope: scope, RunID: runID, VocabularyDigest: vocabularyDigest, CompositionDigest: rawDigest([]byte("benchmark-composition")),
		Sources: []modelsurface.SourceReference{{SourceRecordID: source.SourceRecordID, RecordRevision: 1,
			SourceDigest: sourceDigest}}, CreatedAt: timestamp(now)})
}

func ephemeralQualification(ctx context.Context, capability providercontract.ValidatedCapability,
	qualificationID string, now time.Time) (*providercontract.QualificationRegistry, error) {
	kinds := []string{"cancellation", "capability", "identity_provenance", "policy_route", "structured_output", "tool_call"}
	cases := make([]providercontract.QualificationCase, 0, len(kinds))
	for index, kind := range kinds {
		cases = append(cases, providercontract.QualificationCase{Kind: kind,
			FixtureDigest: rawDigest([]byte("benchmark-fixture-" + kind)), Outcome: "passed",
			TraceDigest: rawDigest([]byte("benchmark-trace-" + kind)), DurationMilliseconds: uint64(index + 1)})
	}
	authorityDigest := rawDigest([]byte("COH-LOCAL-BENCHMARK-QUALIFIER-V1"))
	record := providercontract.QualificationRecord{SchemaVersion: providercontract.QualificationSchemaVersion,
		ContractVersion: providercontract.ContractVersion, QualificationID: qualificationID,
		IssuedAt: timestamp(now.Add(-time.Minute)), ExpiresAt: timestamp(now.Add(24 * time.Hour)),
		Provider: capability.Value().Provider, CapabilityDigest: capability.Digest(), ReleaseMatrix: providercontract.ReleaseMatrix{
			Profile: "native-" + runtime.GOOS + "-" + runtime.GOARCH, OS: runtime.GOOS, Architecture: runtime.GOARCH,
			DeploymentMode: "native", NetworkMode: "restricted_connected"}, Cases: cases, AggregateOutcome: "passed",
		SuiteDigest: rawDigest([]byte("COH-LOCAL-BENCHMARK-QUALIFICATION-SUITE-V1")), QualifierIdentityDigest: authorityDigest}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	qualification, err := providercontract.DecodeQualification(ctx, encoded)
	if err != nil {
		return nil, err
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte("b"), ed25519.SeedSize))
	authority := providercontract.QualifierAuthority{IdentityDigest: authorityDigest, KeyID: "local-benchmark-qualifier",
		KeyRevision: 1, ApprovalRevision: 1, Active: true, Approved: true,
		PublicKey: privateKey.Public().(ed25519.PublicKey)}
	signature := ed25519.Sign(privateKey, qualificationMessage(qualification.CanonicalBytes(), authority))
	envelope := providercontract.SignedQualification{SchemaVersion: providercontract.SignedQualificationSchemaVersion,
		ContractVersion: providercontract.ContractVersion, Qualification: qualification.Value(),
		QualificationDigest: qualification.Digest(), QualifierIdentityDigest: authority.IdentityDigest,
		QualifierKeyID: authority.KeyID, QualifierKeyRevision: authority.KeyRevision,
		QualifierApprovalRevision: authority.ApprovalRevision, SignatureAlgorithm: providercontract.SignatureAlgorithm,
		Signature: base64.RawURLEncoding.EncodeToString(signature)}
	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	verified, err := providercontract.VerifyQualification(ctx, envelopeBytes, authority)
	if err != nil {
		return nil, err
	}
	registry := providercontract.NewQualificationRegistry()
	if _, err := registry.Admit(ctx, capability, verified, now); err != nil {
		return nil, err
	}
	return registry, nil
}

func qualificationMessage(qualification []byte, authority providercontract.QualifierAuthority) []byte {
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

func deterministicUUID(domain, value string) string {
	sum := sha256.Sum256([]byte("COH-OLLAMA-BENCH-UUID-V1\x00" + domain + "\x00" + value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func timestamp(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05.000000000Z") }
