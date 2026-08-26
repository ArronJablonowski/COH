package nativeexecutor

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/broker/executionstop"
	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

const (
	testDigest  = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	inputDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type fixedClock struct{ value time.Time }

func (clock fixedClock) Now() time.Time { return clock.value }

type fakeResolver struct {
	capability toolregistry.Capability
	err        error
	calls      atomic.Int32
}

func (resolver *fakeResolver) ResolveOperation(context.Context, toolregistry.ToolReference, string, string, string,
	toolregistry.PublisherAuthority) (toolregistry.Capability, error) {
	resolver.calls.Add(1)
	return resolver.capability, resolver.err
}

type fakeAuthorizer struct {
	authority DispatchAuthority
	err       error
	mutate    func(*DispatchAuthority)
	calls     atomic.Int32
}

func (authorizer *fakeAuthorizer) Authorize(_ context.Context, request AuthorizationRequest) (DispatchAuthority, error) {
	authorizer.calls.Add(1)
	authority := authorizer.authority
	authority.Request = request
	if authorizer.mutate != nil {
		authorizer.mutate(&authority)
	}
	return authority, authorizer.err
}

type fakeArtifacts struct {
	prepared PreparedArtifact
	err      error
	calls    atomic.Int32
}

func (artifacts *fakeArtifacts) Prepare(context.Context, string, string, uint64) (PreparedArtifact, error) {
	artifacts.calls.Add(1)
	return artifacts.prepared, artifacts.err
}

type fakeSandbox struct {
	execute func(context.Context, Plan) (SandboxResult, error)
	calls   atomic.Int32
}

func (sandbox *fakeSandbox) Execute(ctx context.Context, plan Plan) (SandboxResult, error) {
	sandbox.calls.Add(1)
	return sandbox.execute(ctx, plan)
}

func TestExecutorResolvesStagesAndReplaysExactlyOnce(t *testing.T) {
	resolver := &fakeResolver{capability: testCapability()}
	cleanupCalls := atomic.Int32{}
	artifacts := &fakeArtifacts{prepared: PreparedArtifact{Path: "/private/staged/tool", Digest: testDigest,
		Cleanup: func() error { cleanupCalls.Add(1); return nil }}}
	sandbox := &fakeSandbox{execute: func(_ context.Context, plan Plan) (SandboxResult, error) {
		if plan.ExecutablePath != "/private/staged/tool" || len(plan.Arguments) != 1 || plan.Arguments[0] != "--query" {
			t.Fatalf("unexpected executable plan: %+v", plan)
		}
		if len(plan.Environment) != 2 || plan.Environment[0] != "LANG=C" || plan.Environment[1] != "TZ=UTC" {
			t.Fatalf("environment is not fixed and sorted: %v", plan.Environment)
		}
		if string(plan.Input) != `{"query_digest":"`+inputDigest+`"}` {
			t.Fatalf("input=%s", plan.Input)
		}
		return SandboxResult{ExitCode: 0, StandardOutput: []byte("ok\n")}, nil
	}}
	authorizer := testAuthorizer()
	executor := newTestExecutor(t, resolver, authorizer, artifacts, sandbox)
	request := testRequest()
	result, err := executor.Execute(context.Background(), request)
	if err != nil {
		t.Fatalf("Execute() error=%v", err)
	}
	if result.Provenance.Outcome != "succeeded" || result.Provenance.Replayed ||
		result.Provenance.ManifestDigest != testCapability().ManifestDigest || string(result.StandardOutput) != "ok\n" {
		t.Fatalf("result=%+v", result)
	}
	replayed, err := executor.Execute(context.Background(), request)
	if err != nil || !replayed.Provenance.Replayed || sandbox.calls.Load() != 1 || authorizer.calls.Load() != 1 ||
		artifacts.calls.Load() != 1 || resolver.calls.Load() != 1 || cleanupCalls.Load() != 1 {
		t.Fatalf("replay=%+v err=%v calls=%d/%d/%d cleanup=%d", replayed, err, resolver.calls.Load(),
			artifacts.calls.Load(), sandbox.calls.Load(), cleanupCalls.Load())
	}
	changed := request
	changed.Inputs = map[string]InputValue{"query_digest": {Kind: "digest", String: testDigest}}
	if _, err := executor.Execute(context.Background(), changed); Code(err) != Conflict || Reason(err) != "attempt_identity_collision" {
		t.Fatalf("collision error=%v", err)
	}
}

func TestExecutorConcurrentReplayRunsSandboxOnce(t *testing.T) {
	resolver := &fakeResolver{capability: testCapability()}
	artifacts := &fakeArtifacts{prepared: PreparedArtifact{Path: "/private/staged/tool", Digest: testDigest,
		Cleanup: func() error { return nil }}}
	release := make(chan struct{})
	sandbox := &fakeSandbox{execute: func(context.Context, Plan) (SandboxResult, error) {
		<-release
		return SandboxResult{}, nil
	}}
	executor := newTestExecutor(t, resolver, testAuthorizer(), artifacts, sandbox)
	const count = 12
	results := make(chan Result, count)
	errors := make(chan error, count)
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := executor.Execute(context.Background(), testRequest())
			results <- result
			errors <- err
		}()
	}
	for sandbox.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	wait.Wait()
	close(results)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent error=%v", err)
		}
	}
	replays := 0
	for result := range results {
		if result.Provenance.Replayed {
			replays++
		}
	}
	if sandbox.calls.Load() != 1 || replays != count-1 {
		t.Fatalf("sandbox calls=%d replays=%d", sandbox.calls.Load(), replays)
	}
}

func TestExecutorDenialsNeverReachSandbox(t *testing.T) {
	tests := []struct {
		name        string
		mutateCap   func(*toolregistry.Capability)
		mutateReq   func(*Request)
		resolverErr error
		reason      string
		outcome     string
	}{
		{"registry denial", nil, nil, toolregistry.NewError(toolregistry.Denied, "publisher_revoked"), "registry_publisher_revoked", "denied"},
		{"wrong isolation", func(value *toolregistry.Capability) { value.Operation.IsolationClass = "oci_sandbox" }, nil, nil, "native_capability_binding", "denied"},
		{"t2 capability", func(value *toolregistry.Capability) { value.RequiredTier = "T2" }, nil, nil, "native_capability_binding", "denied"},
		{"unknown input", nil, func(value *Request) { value.Inputs["extra"] = InputValue{Kind: "string", String: "x"} }, nil, "operation_inputs", "invalid"},
		{"wrong input type", nil, func(value *Request) { value.Inputs["query_digest"] = InputValue{Kind: "string", String: inputDigest} }, nil, "operation_input_type", "invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capability := testCapability()
			if test.mutateCap != nil {
				test.mutateCap(&capability)
			}
			resolver := &fakeResolver{capability: capability, err: test.resolverErr}
			artifacts := &fakeArtifacts{prepared: PreparedArtifact{Path: "/staged", Digest: testDigest, Cleanup: func() error { return nil }}}
			sandbox := &fakeSandbox{execute: func(context.Context, Plan) (SandboxResult, error) { return SandboxResult{}, nil }}
			executor := newTestExecutor(t, resolver, testAuthorizer(), artifacts, sandbox)
			request := testRequest()
			if test.mutateReq != nil {
				test.mutateReq(&request)
			}
			result, err := executor.Execute(context.Background(), request)
			if Reason(err) != test.reason || result.Provenance.Outcome != test.outcome || sandbox.calls.Load() != 0 {
				t.Fatalf("result=%+v error=%v sandbox calls=%d", result, err, sandbox.calls.Load())
			}
		})
	}
}

func TestDispatchAuthorityFailsClosedBeforeRegistryAndSandbox(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DispatchAuthority)
		err    error
		reason string
	}{
		{"expired", func(value *DispatchAuthority) { value.ValidUntil = "2026-08-26T02:59:59Z" }, nil, "dispatch_authority"},
		{"tier elevation", func(value *DispatchAuthority) { value.RuntimeCeiling = "T2" }, nil, "dispatch_authority"},
		{"decision tamper", func(value *DispatchAuthority) { value.DecisionDigest = testDigest[:70] }, nil, "dispatch_authority"},
		{"scope tamper", func(value *DispatchAuthority) { value.Request.ActorID = value.Request.CaseID }, nil, "dispatch_authority"},
		{"policy denial", nil, NewError(Denied, "policy_denied"), "policy_denied"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolver := &fakeResolver{capability: testCapability()}
			authorizer := testAuthorizer()
			authorizer.err, authorizer.mutate = test.err, test.mutate
			artifacts := &fakeArtifacts{prepared: PreparedArtifact{Path: "/staged", Digest: testDigest,
				Cleanup: func() error { return nil }}}
			sandbox := &fakeSandbox{execute: func(context.Context, Plan) (SandboxResult, error) { return SandboxResult{}, nil }}
			executor := newTestExecutor(t, resolver, authorizer, artifacts, sandbox)
			result, err := executor.Execute(context.Background(), testRequest())
			if Reason(err) != test.reason || result.Provenance.Outcome != "denied" ||
				resolver.calls.Load() != 0 || artifacts.calls.Load() != 0 || sandbox.calls.Load() != 0 {
				t.Fatalf("result=%+v error=%v calls=%d/%d/%d", result, err, resolver.calls.Load(), artifacts.calls.Load(), sandbox.calls.Load())
			}
		})
	}
}

func TestExecutorTimeoutAndRecoveryUseDistinctAttempts(t *testing.T) {
	resolver := &fakeResolver{capability: testCapability()}
	artifacts := &fakeArtifacts{prepared: PreparedArtifact{Path: "/staged", Digest: testDigest, Cleanup: func() error { return nil }}}
	first := atomic.Bool{}
	sandbox := &fakeSandbox{execute: func(ctx context.Context, _ Plan) (SandboxResult, error) {
		if !first.Swap(true) {
			<-ctx.Done()
			return SandboxResult{}, ctx.Err()
		}
		return SandboxResult{}, nil
	}}
	capability := resolver.capability
	capability.Operation.ResourceLimits.WallTimeMilliseconds = 2
	resolver.capability = capability
	executor := newTestExecutor(t, resolver, testAuthorizer(), artifacts, sandbox)
	result, err := executor.Execute(context.Background(), testRequest())
	if Code(err) != Timeout || result.Provenance.Outcome != "timeout" {
		t.Fatalf("timeout result=%+v error=%v", result, err)
	}
	recovery := testRequest()
	recovery.AttemptID = "0198d6c4-5555-7555-8555-555555555556"
	result, err = executor.Execute(context.Background(), recovery)
	if err != nil || result.Provenance.Outcome != "succeeded" || sandbox.calls.Load() != 2 {
		t.Fatalf("recovery result=%+v error=%v calls=%d", result, err, sandbox.calls.Load())
	}
}

func newTestExecutor(t *testing.T, resolver Resolver, authorizer Authorizer,
	artifacts ArtifactPreparer, sandbox Sandbox) *Executor {
	t.Helper()
	executor, err := New(resolver, authorizer, artifacts, sandbox, testExecutionTracker(), fixedClock{time.Date(2026, 8, 26, 3, 0, 0, 0, time.UTC)},
		[]Registration{{Tool: testRequest().Tool, Operation: "execute", ExecutablePath: "/approved/tool",
			FixedArguments: []string{"--query"}, FixedEnvironment: []EnvironmentVariable{{Name: "TZ", Value: "UTC"}, {Name: "LANG", Value: "C"}}}})
	if err != nil {
		t.Fatalf("New() error=%v", err)
	}
	return executor
}

type allowStopGuard struct{}

func (allowStopGuard) Allow(context.Context, string, string, string) error { return nil }

func testExecutionTracker() *executionstop.Tracker {
	tracker, err := executionstop.New("native-executions", allowStopGuard{})
	if err != nil {
		panic(err)
	}
	return tracker
}

func testRequest() Request {
	return Request{AttemptID: "0198d6c4-5555-7555-8555-555555555555",
		OrganizationID: "0198d6c4-6666-7666-8666-666666666666",
		TenantID:       "0198d6c4-7777-7777-8777-777777777777",
		CaseID:         "0198d6c4-8888-7888-8888-888888888888",
		ActorID:        "0198d6c4-9999-7999-8999-999999999999",
		Tool:           toolregistry.ToolReference{Name: "query.execute", Version: "1.2.3", ArtifactDigest: testDigest},
		Operation:      "execute", RequiredTier: "T1",
		Publisher: toolregistry.PublisherAuthority{PublisherID: "0198d6c4-2222-7222-8222-222222222222", KeyID: "publisher.primary", KeyRevision: 3, ApprovalRevision: 4, Active: true, Approved: true},
		Inputs:    map[string]InputValue{"query_digest": {Kind: "digest", String: inputDigest}}}
}

func testAuthorizer() *fakeAuthorizer {
	return &fakeAuthorizer{authority: DispatchAuthority{
		AuthorizationID: "0198d6c4-aaaa-7aaa-8aaa-aaaaaaaaaaaa",
		DecisionDigest:  "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		RuntimeCeiling:  "T1", AuthorizedAt: "2026-08-26T03:00:00Z", ValidUntil: "2026-08-26T03:01:00Z"}}
}

func testCapability() toolregistry.Capability {
	return toolregistry.Capability{ManifestDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		ManifestID: "0198d6c4-1111-7111-8111-111111111111", Tool: testRequest().Tool,
		Operation: toolregistry.Operation{Name: "execute", BaselineActionTier: "T1", MaximumActionTier: "T2",
			IsolationClass: "native_restricted", InputFields: []toolregistry.InputField{{Name: "query_digest", Type: "digest", Required: true, MaximumBytes: 71}},
			ResourceLimits: toolregistry.ResourceLimits{WallTimeMilliseconds: 60_000, CPUMilliseconds: 30_000,
				MemoryBytes: 268435456, OutputBytes: 16777216, EphemeralStorageBytes: 67108864, ProcessCount: 4, OpenFileCount: 128},
			NetworkPolicy: toolregistry.NetworkPolicy{Mode: "none", DNSMode: "none"}},
		RequiredTier: "T1", RuntimeCeiling: "T1", EffectiveCeiling: "T1"}
}
