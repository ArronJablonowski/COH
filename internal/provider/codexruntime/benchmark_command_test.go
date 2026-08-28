// cohcodexbench is a local, test-only invocation surface for measuring the
// complete COH model-surface and Codex Runtime provider path. It is not a
// production qualification authority or deployment entry point.
package codexruntime_test

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
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/modelsurface"
	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
	providergateway "github.com/ArronJablonowski/COH/internal/provider"
	"github.com/ArronJablonowski/COH/internal/provider/codexruntime"
)

const benchmarkVersion = "0.1.0"

var supportedModels = map[string]bool{
	"gpt-5.6-sol": true, "gpt-5.6-terra": true, "gpt-5.6-luna": true,
	"gpt-daybreak-blue-latest": true,
}

type surfaceStore struct {
	vocabulary, source []byte
	snapshot           modelsurface.ContentSnapshot
}

func (s surfaceStore) ReadVocabulary(context.Context, string) ([]byte, bool, error) {
	return append([]byte(nil), s.vocabulary...), true, nil
}
func (s surfaceStore) ReadSource(context.Context, modelsurface.Scope, string, uint64) ([]byte, bool, error) {
	return append([]byte(nil), s.source...), true, nil
}
func (s surfaceStore) ReadDurableRecord(context.Context, modelsurface.Scope, string, modelsurface.ContentBinding) (modelsurface.ContentSnapshot, bool, error) {
	return s.snapshot, true, nil
}
func (s surfaceStore) ReadArtifact(context.Context, modelsurface.Scope, string, modelsurface.ContentBinding) (modelsurface.ContentSnapshot, bool, error) {
	return modelsurface.ContentSnapshot{}, false, nil
}

type schemaResolver struct{}

func (schemaResolver) Resolve(context.Context, string) (codexruntime.SchemaDocument, error) {
	return codexruntime.SchemaDocument{}, errors.New("benchmark has no provider-visible schemas")
}

type toolBroker struct{}

func (toolBroker) Call(context.Context, codexruntime.ToolCall) (codexruntime.ToolResult, error) {
	return codexruntime.ToolResult{}, errors.New("benchmark tools are disabled")
}

type reasoningStore struct {
	mu      sync.Mutex
	records map[string][]byte
}

func (s *reasoningStore) Put(_ context.Context, reference, digest string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[reference+"\x00"+digest] = append([]byte(nil), value...)
	return nil
}

type disabledFactory struct{}

func (disabledFactory) Open(context.Context) (codexruntime.RPCTransport, codexruntime.LaunchObservation, error) {
	return nil, codexruntime.LaunchObservation{}, errors.New("app-server mode disabled for benchmark")
}

type batchRunner struct {
	binary, workspace, codexHome string
	provider                     providercontract.ProviderIdentity
}

func (r batchRunner) Run(ctx context.Context, invocation codexruntime.BatchInvocation) (codexruntime.BatchResult, error) {
	wanted := []string{"codex", "exec", "--json", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--strict-config", "--sandbox", "read-only", "--cd", r.workspace, "--model", r.provider.ActualModel, "-"}
	if strings.Join(invocation.Argv, "\x00") != strings.Join(wanted, "\x00") || invocation.WorkingDirectory != r.workspace || len(invocation.Environment) != 0 || len(invocation.OutputSchema) != 0 || invocation.MaximumOutputBytes != 16<<20 {
		return codexruntime.BatchResult{}, errors.New("COH batch invocation departed from the qualified surface")
	}
	command := exec.CommandContext(ctx, r.binary, invocation.Argv[1:]...)
	command.Dir = invocation.WorkingDirectory
	command.Stdin = bytes.NewReader(invocation.Stdin)
	command.Env = allowedEnvironment(r.codexHome)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	exitCode := 0
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			exitCode = exit.ExitCode()
		} else {
			return codexruntime.BatchResult{}, err
		}
	}
	if stdout.Len() > int(invocation.MaximumOutputBytes) || stderr.Len() > int(invocation.MaximumOutputBytes) {
		return codexruntime.BatchResult{}, errors.New("Codex runtime output exceeded the COH bound")
	}
	return codexruntime.BatchResult{JSONL: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exitCode,
		Observation: observation(r.provider, r.workspace, r.codexHome)}, nil
}

func allowedEnvironment(codexHome string) []string {
	allowed := []string{"HOME", "PATH", "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"}
	result := []string{"CODEX_HOME=" + codexHome}
	for _, key := range allowed {
		if value, ok := os.LookupEnv(key); ok {
			result = append(result, key+"="+value)
		}
	}
	return result
}

func observation(provider providercontract.ProviderIdentity, workspace, codexHome string) codexruntime.LaunchObservation {
	return codexruntime.LaunchObservation{RuntimeVersion: codexruntime.RuntimeVersion, RuntimeDigest: codexruntime.RuntimeDigest,
		ProtocolDigest: codexruntime.ProtocolDigest, Model: provider.ActualModel, ModelRevision: provider.ModelRevision,
		Workspace: workspace, Transport: "exec-jsonl", Sandbox: "read-only", ApprovalPolicy: "untrusted",
		NetworkMode: "connected", ConfigDigest: provider.ChatTemplateDigest, EnvironmentDigest: provider.HardwareProfileDigest,
		CredentialMode: "invocation-scoped", ExperimentalSurface: "tools-disabled", CodexHome: codexHome,
		ConfigMode: "managed-isolated", RulesMode: "disabled", HooksMode: "disabled", MCPMode: "disabled",
		WebSearchMode: "disabled", MutationMode: "disabled", EnvironmentMode: "allowlist"}
}

type provenance struct {
	HarnessVersion, AdapterVersion, RuntimeVersion string
	Model, ModelRevision                           string
	CapabilityDigest, BindingDigest                string
	ProvenanceDigest                               string
	Usage                                          providercontract.Usage
}

func (p provenance) MarshalJSON() ([]byte, error) {
	type document struct {
		HarnessVersion   string                 `json:"harness_version"`
		AdapterVersion   string                 `json:"adapter_version"`
		RuntimeVersion   string                 `json:"runtime_version"`
		Model            string                 `json:"model"`
		ModelRevision    string                 `json:"model_revision"`
		CapabilityDigest string                 `json:"capability_digest"`
		BindingDigest    string                 `json:"binding_digest"`
		ProvenanceDigest string                 `json:"provenance_digest"`
		Usage            providercontract.Usage `json:"usage"`
	}
	return json.Marshal(document(p))
}

func TestMain(tests *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println(benchmarkVersion)
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "--invoke" {
		os.Exit(tests.Run())
	}
	flags := flag.NewFlagSet("cohcodexbench", flag.ContinueOnError)
	model := flags.String("model", "", "exact Codex model identifier")
	prompt := flags.String("prompt", "", "single user prompt")
	workspace := flags.String("workspace", "", "managed empty Git workspace")
	codexBinary := flags.String("codex-binary", "", "pinned Codex executable")
	codexHome := flags.String("codex-home", "", "Codex authentication directory")
	timeout := flags.Duration("timeout", 30*time.Minute, "invocation deadline")
	maximumOutput := flags.Uint64("max-output-tokens", 32768, "maximum output tokens")
	if flags.Parse(os.Args[2:]) != nil {
		os.Exit(2)
	}
	if !supportedModels[*model] || *prompt == "" || !filepath.IsAbs(*workspace) || !filepath.IsAbs(*codexBinary) || !filepath.IsAbs(*codexHome) || *timeout < time.Second || *timeout > 30*time.Minute || *maximumOutput == 0 || *maximumOutput > 128000 {
		fmt.Fprintln(os.Stderr, "supported model, prompt, absolute runtime paths, positive output limit, and timeout up to 30m are required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	text, evidence, err := invoke(ctx, *model, *prompt, *workspace, *codexBinary, *codexHome, *timeout, *maximumOutput)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded, _ := json.Marshal(evidence)
	fmt.Fprintln(os.Stderr, string(encoded))
	fmt.Print(text)
}

func invoke(ctx context.Context, model, prompt, workspace, binary, codexHome string, timeout time.Duration, maximumOutput uint64) (string, provenance, error) {
	now := time.Now().UTC()
	provider := providerIdentity(model, workspace, codexHome)
	capability, err := codexruntime.DiscoverCapability(ctx, codexruntime.CapabilityDefinition{
		SnapshotID: deterministicUUID("capability", provider.ModelRevision), ObservedAt: now.Add(-time.Minute), ValidUntil: now.Add(23 * time.Hour), Provider: provider,
		Limits: providercontract.Limits{MaximumInputTokens: 900000, MaximumOutputTokens: 128000, MaximumMessages: 16,
			MaximumTools: 1, MaximumParallelToolCalls: 1, MaximumStreamSeconds: uint32(timeout / time.Second)}})
	if err != nil {
		return "", provenance{}, fmt.Errorf("capability discovery: %w", err)
	}
	qualificationID := deterministicUUID("qualification", capability.Digest())
	registry, err := ephemeralQualification(ctx, capability, qualificationID, now)
	if err != nil {
		return "", provenance{}, err
	}
	adapter, err := codexruntime.New(codexruntime.Config{Capability: capability, Qualifications: registry,
		Schemas: schemaResolver{}, Tools: toolBroker{}, Reasoning: &reasoningStore{records: map[string][]byte{}},
		Factory: disabledFactory{}, Batch: batchRunner{binary: binary, workspace: workspace, codexHome: codexHome, provider: provider},
		Clock: func() time.Time { return time.Now().UTC() }, Workspace: workspace})
	if err != nil {
		return "", provenance{}, err
	}
	surface, err := projectedPrompt(ctx, model, prompt, now)
	if err != nil {
		return "", provenance{}, err
	}
	scope, key := surface.Projection().Scope, model+"\x00"+prompt
	template := providercontract.InferenceRequest{SchemaVersion: providercontract.RequestSchemaVersion, ContractVersion: providercontract.ContractVersion,
		RequestID: deterministicUUID("request", key), AttemptID: deterministicUUID("attempt", key), OrganizationID: scope.OrganizationID,
		TenantID: scope.TenantID, CaseID: scope.CaseID, TaskID: scope.TaskID, ActorID: deterministicUUID("actor", key),
		Provider: provider, CapabilityDigest: capability.Digest(), QualificationID: qualificationID,
		OutputConstraint: providercontract.OutputConstraint{Kind: "text"}, Sampling: providercontract.Sampling{TemperatureMilli: 0, TopPMillionths: 1000000, Seed: 0},
		MaximumOutputTokens: maximumOutput, State: providercontract.State{Mode: "stateless"}, Deadline: timestamp(now.Add(timeout)),
		AuthorizationDigest: rawDigest([]byte("benchmark-authorization")), PolicyDecisionDigest: rawDigest([]byte("benchmark-policy")),
		ApprovalDecisionDigest: rawDigest([]byte("benchmark-approval")), AuditReservationDigest: rawDigest([]byte("benchmark-audit"))}
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
	var output bytes.Buffer
	for _, item := range value.Items {
		if item.Kind == "text" {
			output.WriteString(item.Text)
		}
	}
	if output.Len() == 0 {
		return "", provenance{}, errors.New("provider returned no visible answer")
	}
	return output.String(), provenance{HarnessVersion: benchmarkVersion, AdapterVersion: codexruntime.AdapterVersion,
		RuntimeVersion: codexruntime.RuntimeVersion, Model: model, ModelRevision: provider.ModelRevision,
		CapabilityDigest: capability.Digest(), BindingDigest: admitted.Binding().BindingDigest,
		ProvenanceDigest: value.ProvenanceDigest, Usage: value.Usage}, nil
}

func providerIdentity(model, workspace, codexHome string) providercontract.ProviderIdentity {
	return providercontract.ProviderIdentity{ProviderKind: "codex_runtime", AdapterVersion: codexruntime.AdapterVersion,
		EndpointIdentityDigest: codexruntime.EndpointIdentityDigest("codex-exec", workspace), DataRoute: "approved_external",
		RequestedModel: model, ActualModel: model, ModelRevision: rawDigest([]byte("COH-CODEX-MODEL-ALIAS-V1\x00" + model)),
		RuntimeName: "codex-exec", RuntimeVersion: codexruntime.RuntimeVersion, RuntimeDigest: codexruntime.RuntimeDigest,
		TokenizerName: "openai-managed", TokenizerVersion: "1.0.0", TokenizerDigest: rawDigest([]byte("COH-OPENAI-MANAGED-TOKENIZER-V1")),
		ChatTemplateDigest: rawDigest([]byte("COH-CODEX-BENCH-CONFIG-V1\x00exec-jsonl\x00ignore-user-config\x00ignore-rules\x00strict-config\x00read-only")),
		ToolParserDigest:   codexruntime.ToolParserDigest(), ReasoningParserDigest: codexruntime.ReasoningParserDigest(), ContextLimit: 1050000,
		SamplingProfileDigest: codexruntime.SamplingProfileDigest(), HardwareProfileDigest: rawDigest([]byte("COH-CODEX-BENCH-ENV-V1\x00" + runtime.GOOS + "\x00" + runtime.GOARCH + "\x00" + codexHome)),
		StateMode: "stateless", PolicyRevision: 1}
}

func projectedPrompt(ctx context.Context, model, prompt string, now time.Time) (modelsurface.ProjectedSurface, error) {
	key := model + "\x00" + prompt
	scope := modelsurface.Scope{OrganizationID: deterministicUUID("organization", key), TenantID: deterministicUUID("tenant", key),
		CaseID: deterministicUUID("case", key), TaskID: deterministicUUID("task", key)}
	runID := deterministicUUID("run", key)
	content, _ := json.Marshal(prompt)
	payload, err := modelsurface.CanonicalPayload(modelsurface.SurfacePayload{SchemaVersion: modelsurface.PayloadSchema,
		ContractVersion: modelsurface.ContractVersion, SurfaceKind: "message", Role: "user", ContentKind: "text", Content: content})
	if err != nil {
		return modelsurface.ProjectedSurface{}, err
	}
	definition := modelsurface.EventDefinition{EventType: "benchmark.user.message", EventVersion: 1, EventClass: "model_surface",
		Persistence: "durable", ProducerModule: "cohcodexbench", ConsumerModules: []string{"model.projector"}, ProjectionRule: "message",
		PayloadSchemaDigest: rawDigest([]byte("benchmark-payload-schema"))}
	vocabulary, vocabularyDigest, err := modelsurface.CanonicalVocabulary(ctx, modelsurface.EventVocabulary{SchemaVersion: modelsurface.VocabularySchema,
		ContractVersion: modelsurface.ContractVersion, VocabularyRevision: 1, Definitions: []modelsurface.EventDefinition{definition}})
	if err != nil {
		return modelsurface.ProjectedSurface{}, err
	}
	contentDigest := rawDigest(payload)
	source := modelsurface.Source{SchemaVersion: modelsurface.SourceSchema, ContractVersion: modelsurface.ContractVersion,
		SourceRecordID: deterministicUUID("source", key), EventType: definition.EventType, EventVersion: 1, EventClass: "model_surface",
		ProjectionRule: "message", Scope: scope, RunID: runID, RecordRevision: 1, RecordDigest: rawDigest([]byte("benchmark-source-record" + key)),
		Content: modelsurface.ContentBinding{Kind: "durable_record", ContentID: "benchmark.prompt", Digest: contentDigest,
			MediaType: "application/json", Length: uint64(len(payload)), Classification: "restricted", Immutable: true},
		Trust: "trusted_user", InstructionDisposition: "trusted_user_instruction", OccurredAt: timestamp(now), Sequence: 1, Immutable: true}
	sourceBytes, sourceDigest, err := modelsurface.CanonicalSource(ctx, source)
	if err != nil {
		return modelsurface.ProjectedSurface{}, err
	}
	store := surfaceStore{vocabulary: vocabulary, source: sourceBytes, snapshot: modelsurface.ContentSnapshot{Scope: scope, RunID: runID,
		Kind: source.Content.Kind, ContentID: source.Content.ContentID, Digest: contentDigest, MediaType: source.Content.MediaType,
		Classification: source.Content.Classification, Immutable: true, Bytes: payload}}
	resolver, err := modelsurface.NewResolver(store, store, store, store)
	if err != nil {
		return modelsurface.ProjectedSurface{}, err
	}
	projector, err := modelsurface.NewProjector(resolver)
	if err != nil {
		return modelsurface.ProjectedSurface{}, err
	}
	return projector.Project(ctx, modelsurface.ProjectionRequest{ProjectionID: deterministicUUID("projection", key), Scope: scope,
		RunID: runID, VocabularyDigest: vocabularyDigest, CompositionDigest: rawDigest([]byte("benchmark-composition")),
		Sources: []modelsurface.SourceReference{{SourceRecordID: source.SourceRecordID, RecordRevision: 1, SourceDigest: sourceDigest}}, CreatedAt: timestamp(now)})
}

func ephemeralQualification(ctx context.Context, capability providercontract.ValidatedCapability, qualificationID string, now time.Time) (*providercontract.QualificationRegistry, error) {
	kinds := []string{"cancellation", "capability", "identity_provenance", "policy_route", "structured_output", "tool_call"}
	cases := make([]providercontract.QualificationCase, 0, len(kinds))
	for index, kind := range kinds {
		cases = append(cases, providercontract.QualificationCase{Kind: kind, FixtureDigest: rawDigest([]byte("benchmark-fixture-" + kind)),
			Outcome: "passed", TraceDigest: rawDigest([]byte("benchmark-trace-" + kind)), DurationMilliseconds: uint64(index + 1)})
	}
	authorityDigest := rawDigest([]byte("COH-LOCAL-BENCHMARK-QUALIFIER-V1"))
	record := providercontract.QualificationRecord{SchemaVersion: providercontract.QualificationSchemaVersion,
		ContractVersion: providercontract.ContractVersion, QualificationID: qualificationID, IssuedAt: timestamp(now.Add(-time.Minute)),
		ExpiresAt: timestamp(now.Add(24 * time.Hour)), Provider: capability.Value().Provider, CapabilityDigest: capability.Digest(),
		ReleaseMatrix: providercontract.ReleaseMatrix{Profile: "native-" + runtime.GOOS + "-" + runtime.GOARCH, OS: runtime.GOOS,
			Architecture: runtime.GOARCH, DeploymentMode: "native", NetworkMode: "connected"}, Cases: cases, AggregateOutcome: "passed",
		SuiteDigest: rawDigest([]byte("COH-LOCAL-BENCHMARK-QUALIFICATION-SUITE-V1")), QualifierIdentityDigest: authorityDigest}
	encoded, _ := json.Marshal(record)
	qualification, err := providercontract.DecodeQualification(ctx, encoded)
	if err != nil {
		return nil, err
	}
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte("c"), ed25519.SeedSize))
	authority := providercontract.QualifierAuthority{IdentityDigest: authorityDigest, KeyID: "local-benchmark-qualifier", KeyRevision: 1,
		ApprovalRevision: 1, Active: true, Approved: true, PublicKey: privateKey.Public().(ed25519.PublicKey)}
	signature := ed25519.Sign(privateKey, qualificationMessage(qualification.CanonicalBytes(), authority))
	envelope := providercontract.SignedQualification{SchemaVersion: providercontract.SignedQualificationSchemaVersion,
		ContractVersion: providercontract.ContractVersion, Qualification: qualification.Value(), QualificationDigest: qualification.Digest(),
		QualifierIdentityDigest: authority.IdentityDigest, QualifierKeyID: authority.KeyID, QualifierKeyRevision: authority.KeyRevision,
		QualifierApprovalRevision: authority.ApprovalRevision, SignatureAlgorithm: providercontract.SignatureAlgorithm,
		Signature: base64.RawURLEncoding.EncodeToString(signature)}
	envelopeBytes, _ := json.Marshal(envelope)
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
	sum := sha256.Sum256([]byte("COH-CODEX-BENCH-UUID-V1\x00" + domain + "\x00" + value))
	sum[6], sum[8] = sum[6]&0x0f|0x70, sum[8]&0x3f|0x80
	encoded := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}

func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func timestamp(value time.Time) string { return value.UTC().Format("2006-01-02T15:04:05.000000000Z") }
