package ociexecutor

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

func TestExecutorBuildsLeastPrivilegeBoundPlanAndProvenance(t *testing.T) {
	executor, resolver, authorizer, network, runtime := testExecutor()
	result, err := executor.Execute(context.Background(), testRequest())
	if err != nil {
		t.Fatalf("Execute() error=%v", err)
	}
	if string(result.StandardOutput) != `{"message":"hello"}` || result.Provenance.Outcome != "succeeded" ||
		result.Provenance.AuthorizationID == "" || result.Provenance.PolicyDecisionDigest != testDecisionDigest ||
		result.Provenance.ManifestDigest != testManifestDigest || result.Provenance.ResolvedImageDigest != testArtifactDigest ||
		result.Provenance.NetworkPolicyDigest == "" || result.Provenance.NetworkEnforcementHash == "" ||
		result.Provenance.HealthOutcome != "healthy" || !result.Provenance.CleanupComplete {
		t.Fatalf("result=%+v", result)
	}
	if authorizer.calls != 1 || resolver.calls != 1 || network.calls != 1 || network.cleanups != 1 || runtime.calls != 1 {
		t.Fatalf("calls authorizer=%d resolver=%d network=%d cleanups=%d runtime=%d",
			authorizer.calls, resolver.calls, network.calls, network.cleanups, runtime.calls)
	}
	plan := runtime.plans[0]
	registration := testRegistration()
	if plan.ImageReference != registration.ImageRepository+"@"+testArtifactDigest ||
		plan.Entrypoint != registration.Entrypoint || !reflect.DeepEqual(plan.Arguments, registration.FixedArguments) ||
		!reflect.DeepEqual(plan.HealthArguments, registration.HealthArguments) || plan.RunAsUser == 0 || plan.RunAsGroup == 0 ||
		plan.WorkingDirectory != "/work" || plan.EngineNetwork != "none" || string(plan.Input) != `{"message":"hello"}` {
		t.Fatalf("plan=%+v", plan)
	}
	request := testRequest()
	request.Inputs["message"] = InputValue{Kind: "string", String: "changed"}
	if string(plan.Input) != `{"message":"hello"}` || plan.Arguments[0] != "execute" {
		t.Fatalf("runtime plan aliased request or registration: %+v", plan)
	}
}

func TestExecutorExactAndConcurrentReplayRunsRuntimeOnce(t *testing.T) {
	executor, _, authorizer, network, runtime := testExecutor()
	result, err := executor.Execute(context.Background(), testRequest())
	if err != nil {
		t.Fatal(err)
	}
	replay, err := executor.Execute(context.Background(), testRequest())
	if err != nil || !replay.Provenance.Replayed || replay.Provenance.ContainerSpecDigest != result.Provenance.ContainerSpecDigest {
		t.Fatalf("replay=%+v error=%v", replay, err)
	}
	if runtime.calls != 1 || authorizer.calls != 1 || network.calls != 1 {
		t.Fatalf("exact replay crossed authority boundary")
	}
	collision := testRequest()
	collision.RequiredTier = "T3"
	if _, err := executor.Execute(context.Background(), collision); Code(err) != Conflict || Reason(err) != "attempt_identity_collision" {
		t.Fatalf("collision error=%v", err)
	}

	gate := make(chan struct{})
	executor, _, _, _, runtime = testExecutor()
	runtime.block = gate
	var wait sync.WaitGroup
	results := make([]Result, 8)
	errorsFound := make([]error, 8)
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errorsFound[index] = executor.Execute(context.Background(), testRequest())
		}(index)
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	wait.Wait()
	if runtime.calls != 1 {
		t.Fatalf("runtime calls=%d", runtime.calls)
	}
	replayed := 0
	for index, executionErr := range errorsFound {
		if executionErr != nil {
			t.Fatalf("result %d error=%v", index, executionErr)
		}
		if results[index].Provenance.Replayed {
			replayed++
		}
	}
	if replayed != len(results)-1 {
		t.Fatalf("replayed=%d", replayed)
	}
}

func TestExecutorDenialsDoNotReachRuntime(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Executor, *fakeResolver, *fakeAuthorizer, *fakeNetworkBroker, *fakeRuntime, *Request)
		reason string
	}{
		{name: "authorization denied", mutate: func(_ *Executor, _ *fakeResolver, authorizer *fakeAuthorizer, _ *fakeNetworkBroker, _ *fakeRuntime, _ *Request) {
			authorizer.err = NewError(Denied, "policy_denied")
		}, reason: "policy_denied"},
		{name: "authority tampered", mutate: func(_ *Executor, _ *fakeResolver, authorizer *fakeAuthorizer, _ *fakeNetworkBroker, _ *fakeRuntime, _ *Request) {
			authorizer.authority.DecisionDigest = "sha256:bad"
		}, reason: "dispatch_authority"},
		{name: "registry denied", mutate: func(_ *Executor, resolver *fakeResolver, _ *fakeAuthorizer, _ *fakeNetworkBroker, _ *fakeRuntime, _ *Request) {
			resolver.err = toolregistry.NewError(toolregistry.Denied, "publisher_revoked")
		}, reason: "registry_publisher_revoked"},
		{name: "wrong isolation", mutate: func(_ *Executor, resolver *fakeResolver, _ *fakeAuthorizer, _ *fakeNetworkBroker, _ *fakeRuntime, _ *Request) {
			resolver.capability.Operation.IsolationClass = "native_restricted"
		}, reason: "oci_capability_binding"},
		{name: "credential injection unsupported", mutate: func(_ *Executor, resolver *fakeResolver, _ *fakeAuthorizer, _ *fakeNetworkBroker, _ *fakeRuntime, _ *Request) {
			resolver.capability.Operation.CredentialClasses = []string{"query_reader"}
		}, reason: "oci_capability_binding"},
		{name: "T4 denied", mutate: func(_ *Executor, _ *fakeResolver, _ *fakeAuthorizer, _ *fakeNetworkBroker, _ *fakeRuntime, request *Request) {
			request.RequiredTier = "T4"
		}, reason: "execution_request"},
		{name: "mount exceeds signed storage", mutate: func(executor *Executor, _ *fakeResolver, _ *fakeAuthorizer, _ *fakeNetworkBroker, _ *fakeRuntime, _ *Request) {
			key := registrationKey(testRequest().Tool, "execute")
			registration := executor.registrations[key]
			registration.WritableMounts[0].Bytes = 9 << 20
			executor.registrations[key] = registration
		}, reason: "mount_storage_limit"},
		{name: "network lease tamper", mutate: func(_ *Executor, _ *fakeResolver, _ *fakeAuthorizer, network *fakeNetworkBroker, _ *fakeRuntime, _ *Request) {
			network.mutate = func(lease *NetworkLease) { lease.EngineNetwork = "default" }
		}, reason: "network_lease"},
		{name: "network policy mutation", mutate: func(_ *Executor, _ *fakeResolver, _ *fakeAuthorizer, network *fakeNetworkBroker, _ *fakeRuntime, _ *Request) {
			network.mutate = func(lease *NetworkLease) { lease.Request.Policy.Mode = "target_only" }
		}, reason: "network_lease"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor, resolver, authorizer, network, runtime := testExecutor()
			request := testRequest()
			test.mutate(executor, resolver, authorizer, network, runtime, &request)
			result, err := executor.Execute(context.Background(), request)
			if Reason(err) != test.reason || result.Provenance.Outcome == "succeeded" || runtime.calls != 0 {
				t.Fatalf("result=%+v error=%v runtime calls=%d", result, err, runtime.calls)
			}
		})
	}
}

func TestExecutorRuntimeContractCleanupTimeoutAndRecovery(t *testing.T) {
	t.Run("tamper", func(t *testing.T) {
		executor, _, _, _, runtime := testExecutor()
		runtime.mutate = func(result *RuntimeResult) { result.ResolvedImageDigest = testDecisionDigest }
		result, err := executor.Execute(context.Background(), testRequest())
		if Code(err) != Denied || Reason(err) != "runtime_contract_violation" || result.Provenance.Outcome != "denied" {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
	t.Run("cleanup", func(t *testing.T) {
		executor, _, _, _, runtime := testExecutor()
		runtime.mutate = func(result *RuntimeResult) { result.CleanupComplete = false }
		result, err := executor.Execute(context.Background(), testRequest())
		if Code(err) != Unavailable || Reason(err) != "runtime_cleanup_failed" || result.Provenance.CleanupComplete {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
	t.Run("network cleanup", func(t *testing.T) {
		executor, _, _, network, _ := testExecutor()
		network.cleanup = errors.New("cleanup")
		result, err := executor.Execute(context.Background(), testRequest())
		if Code(err) != Unavailable || Reason(err) != "runtime_cleanup_failed" || result.Provenance.CleanupComplete {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
	t.Run("image unavailable preserves typed failure", func(t *testing.T) {
		executor, _, _, _, runtime := testExecutor()
		runtime.mutate = func(result *RuntimeResult) {
			result.ResolvedImageDigest = ""
			result.HealthOutcome = ""
		}
		runtime.err = NewError(Unavailable, "image_unavailable")
		result, err := executor.Execute(context.Background(), testRequest())
		if Code(err) != Unavailable || Reason(err) != "image_unavailable" || result.Provenance.ContainerSpecDigest == "" ||
			!result.Provenance.CleanupComplete {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
	t.Run("health denial preserves typed failure", func(t *testing.T) {
		executor, _, _, _, runtime := testExecutor()
		runtime.mutate = func(result *RuntimeResult) { result.HealthOutcome = "unhealthy" }
		runtime.err = NewError(Denied, "health_check_failed")
		result, err := executor.Execute(context.Background(), testRequest())
		if Code(err) != Denied || Reason(err) != "health_check_failed" || result.Provenance.HealthOutcome != "unhealthy" ||
			!result.Provenance.CleanupComplete {
			t.Fatalf("result=%+v error=%v", result, err)
		}
	})
	t.Run("timeout and new attempt recovery", func(t *testing.T) {
		executor, _, _, _, runtime := testExecutor()
		never := make(chan struct{})
		runtime.block = never
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()
		result, err := executor.Execute(ctx, testRequest())
		if Code(err) != Timeout || result.Provenance.Outcome != "timeout" {
			t.Fatalf("result=%+v error=%v", result, err)
		}
		runtime.block = nil
		recovery := testRequest()
		recovery.AttemptID = "0198d6c4-5555-7555-8555-555555555556"
		if _, err := executor.Execute(context.Background(), recovery); err != nil {
			t.Fatalf("recovery error=%v", err)
		}
	})
}

func TestExecutorUsesBrokerAttestedExplicitEgressProfile(t *testing.T) {
	executor, resolver, _, network, runtime := testExecutor()
	resolver.capability.Operation.NetworkPolicy = toolregistry.NetworkPolicy{Mode: "target_only", Protocols: []string{"tcp"},
		DNSMode: "broker_resolved", MaximumConnections: 4}
	result, err := executor.Execute(context.Background(), testRequest())
	if err != nil || result.Provenance.NetworkEnforcementHash == "" || runtime.calls != 1 ||
		runtime.plans[0].EngineNetwork != "coh-egress-profile" || network.cleanups != 1 {
		t.Fatalf("result=%+v error=%v plans=%+v cleanups=%d", result, err, runtime.plans, network.cleanups)
	}
}

func TestCanceledRequestDoesNotAuthorizeResolveNetworkOrRun(t *testing.T) {
	executor, resolver, authorizer, network, runtime := testExecutor()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := executor.Execute(ctx, testRequest()); Code(err) != Canceled {
		t.Fatalf("error=%v", err)
	}
	if authorizer.calls != 0 || resolver.calls != 0 || network.calls != 0 || runtime.calls != 0 {
		t.Fatalf("canceled request crossed boundary")
	}
}

func TestExecutorMapsUnknownBoundaryFailureToUnavailable(t *testing.T) {
	executor, _, authorizer, _, _ := testExecutor()
	authorizer.err = errors.New("opaque")
	result, err := executor.Execute(context.Background(), testRequest())
	if Code(err) != Unavailable || Reason(err) != "authorization_unavailable" || result.Provenance.Outcome != "unavailable" {
		t.Fatalf("result=%+v error=%v", result, err)
	}
}
