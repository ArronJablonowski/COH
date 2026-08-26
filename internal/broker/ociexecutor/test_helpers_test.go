package ociexecutor

import (
	"context"
	"sync"
	"time"

	"github.com/ArronJablonowski/COH/internal/broker/executionstop"
	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

const (
	testArtifactDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDecisionDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testManifestDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

var testNow = time.Date(2026, 8, 26, 4, 0, 0, 0, time.UTC)

type fixedClock struct{ value time.Time }

func (clock fixedClock) Now() time.Time { return clock.value }

type fakeResolver struct {
	mu         sync.Mutex
	capability toolregistry.Capability
	err        error
	calls      int
}

func (resolver *fakeResolver) ResolveOperation(_ context.Context, _ toolregistry.ToolReference, _, _, _ string,
	_ toolregistry.PublisherAuthority) (toolregistry.Capability, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	resolver.calls++
	return resolver.capability, resolver.err
}

type fakeAuthorizer struct {
	mu        sync.Mutex
	authority DispatchAuthority
	err       error
	calls     int
}

func (authorizer *fakeAuthorizer) Authorize(_ context.Context, request AuthorizationRequest) (DispatchAuthority, error) {
	authorizer.mu.Lock()
	defer authorizer.mu.Unlock()
	authorizer.calls++
	value := authorizer.authority
	value.Request = request
	return value, authorizer.err
}

type fakeNetworkBroker struct {
	mu       sync.Mutex
	clock    Clock
	mutate   func(*NetworkLease)
	err      error
	cleanup  error
	calls    int
	cleanups int
}

func (broker *fakeNetworkBroker) Acquire(_ context.Context, request NetworkRequest) (NetworkLease, error) {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	broker.calls++
	if broker.err != nil {
		return NetworkLease{}, broker.err
	}
	now := broker.clock.Now().UTC()
	lease := NetworkLease{LeaseID: request.AttemptID, Request: request, EngineNetwork: "none",
		EnforcementDigest: digestBytes(canonicalBytes(request)), AuthorizedAt: formatTime(now),
		ValidUntil: request.AuthorityUntil}
	if request.Policy.Mode != "none" {
		lease.EngineNetwork = "coh-egress-profile"
	}
	lease.Cleanup = func() error {
		broker.mu.Lock()
		broker.cleanups++
		broker.mu.Unlock()
		return broker.cleanup
	}
	if broker.mutate != nil {
		broker.mutate(&lease)
	}
	return lease, nil
}

type fakeRuntime struct {
	mu      sync.Mutex
	mutate  func(*RuntimeResult)
	err     error
	calls   int
	plans   []ContainerPlan
	block   <-chan struct{}
	started chan struct{}
}

func (runtime *fakeRuntime) Execute(ctx context.Context, plan ContainerPlan) (RuntimeResult, error) {
	runtime.mu.Lock()
	runtime.calls++
	runtime.plans = append(runtime.plans, plan)
	runtime.mu.Unlock()
	if runtime.started != nil {
		close(runtime.started)
	}
	if runtime.block != nil {
		select {
		case <-ctx.Done():
			return validRuntimeResult(plan), ctx.Err()
		case <-runtime.block:
		}
	}
	result := validRuntimeResult(plan)
	if runtime.mutate != nil {
		runtime.mutate(&result)
	}
	return result, runtime.err
}

func validRuntimeResult(plan ContainerPlan) RuntimeResult {
	return RuntimeResult{ExitCode: 0, StandardOutput: []byte(`{"message":"hello"}`),
		ResolvedImageDigest: plan.ImageDigest, ContainerSpecDigest: digestBytes(canonicalBytes(plan)),
		HealthCommandDigest: digestBytes(canonicalBytes(plan.HealthArguments)), HealthOutcome: "healthy",
		RuntimeDigest: testDecisionDigest, CleanupComplete: true}
}

func testRequest() Request {
	return Request{AttemptID: "0198d6c4-5555-7555-8555-555555555555",
		OrganizationID: "0198d6c4-1111-7111-8111-111111111111",
		TenantID:       "0198d6c4-2222-7222-8222-222222222222",
		CaseID:         "0198d6c4-3333-7333-8333-333333333333",
		ActorID:        "0198d6c4-4444-7444-8444-444444444444",
		Tool:           toolregistry.ToolReference{Name: "fixture.oci", Version: "1.0.0", ArtifactDigest: testArtifactDigest},
		Operation:      "execute", RequiredTier: "T2", Inputs: map[string]InputValue{"message": {Kind: "string", String: "hello"}}}
}

func testRegistration() Registration {
	request := testRequest()
	return Registration{Tool: request.Tool, Operation: request.Operation, ImageRepository: "registry.example/coh/fixture",
		ImageDigest: request.Tool.ArtifactDigest, Entrypoint: "/usr/local/bin/fixture", FixedArguments: []string{"execute"},
		HealthArguments: []string{"health"}, FixedEnvironment: []EnvironmentVariable{{Name: "LANG", Value: "C"}},
		RunAsUser: 65532, RunAsGroup: 65532, WritableMounts: []WritableMount{{Destination: "/work", Bytes: 1 << 20}}}
}

func testCapability() toolregistry.Capability {
	request := testRequest()
	return toolregistry.Capability{ManifestDigest: testManifestDigest,
		ManifestID: "0198d6c4-6666-7666-8666-666666666666", Tool: request.Tool,
		RequiredTier: request.RequiredTier, RuntimeCeiling: "T3", EffectiveCeiling: "T3",
		Operation: toolregistry.Operation{Name: request.Operation, InputSchemaVersion: "coh.tool-input/v1",
			InputFields:        []toolregistry.InputField{{Name: "message", Type: "string", Required: true, MaximumBytes: 64, Enum: []string{}}},
			BaselineActionTier: "T2", MaximumActionTier: "T3", IsolationClass: "oci_sandbox",
			CredentialClasses: []string{"none"}, ResourceLimits: testLimits(), NetworkPolicy: noNetwork(),
			CancellationMode: "cooperative", RetryMode: "never"}}
}

func testLimits() toolregistry.ResourceLimits {
	return toolregistry.ResourceLimits{WallTimeMilliseconds: 30_000, CPUMilliseconds: 10_000,
		MemoryBytes: 256 << 20, OutputBytes: 1 << 20, EphemeralStorageBytes: 8 << 20,
		ProcessCount: 8, OpenFileCount: 64}
}

func noNetwork() toolregistry.NetworkPolicy {
	return toolregistry.NetworkPolicy{Mode: "none", DNSMode: "none", Protocols: []string{}}
}

func testExecutor() (*Executor, *fakeResolver, *fakeAuthorizer, *fakeNetworkBroker, *fakeRuntime) {
	resolver := &fakeResolver{capability: testCapability()}
	authorizer := &fakeAuthorizer{authority: DispatchAuthority{AuthorizationID: "0198d6c4-7777-7777-8777-777777777777",
		DecisionDigest: testDecisionDigest, RuntimeCeiling: "T3", AuthorizedAt: formatTime(testNow.Add(-time.Second)),
		ValidUntil: formatTime(testNow.Add(time.Minute))}}
	network := &fakeNetworkBroker{clock: fixedClock{testNow}}
	runtime := &fakeRuntime{}
	executor, err := New(resolver, authorizer, testContainmentNetwork(network), runtime, testOCIExecutionTracker(), fixedClock{testNow}, []Registration{testRegistration()})
	if err != nil {
		panic(err)
	}
	return executor, resolver, authorizer, network, runtime
}

func testOCIExecutionTracker() *executionstop.Tracker {
	tracker, err := executionstop.New("oci-executions", &mutableStopGuard{})
	if err != nil {
		panic(err)
	}
	return tracker
}

func testContainmentNetwork(inner NetworkBroker) *ContainmentNetworkBroker {
	broker, err := NewContainmentNetworkBroker(inner, &mutableStopGuard{})
	if err != nil {
		panic(err)
	}
	return broker
}
