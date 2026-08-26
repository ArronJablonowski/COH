package ociexecutor

import (
	"context"
	"testing"
)

func TestRegistrationRejectsFloatingRootHostAndSecretExpansion(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Registration)
	}{
		{name: "floating repository", mutate: func(value *Registration) { value.ImageRepository += ":latest" }},
		{name: "digest mismatch", mutate: func(value *Registration) { value.ImageDigest = testDecisionDigest }},
		{name: "relative entrypoint", mutate: func(value *Registration) { value.Entrypoint = "bin/tool" }},
		{name: "shell entrypoint", mutate: func(value *Registration) { value.Entrypoint = "/bin/sh" }},
		{name: "root user", mutate: func(value *Registration) { value.RunAsUser = 0 }},
		{name: "root group", mutate: func(value *Registration) { value.RunAsGroup = 0 }},
		{name: "missing health", mutate: func(value *Registration) { value.HealthArguments = nil }},
		{name: "host path", mutate: func(value *Registration) { value.WritableMounts[0].Destination = "/var/run/docker.sock" }},
		{name: "unbounded mount", mutate: func(value *Registration) { value.WritableMounts[0].Bytes = 0 }},
		{name: "overlapping mount", mutate: func(value *Registration) {
			value.WritableMounts = append(value.WritableMounts, WritableMount{Destination: "/work/nested", Bytes: 1024})
		}},
		{name: "secret environment", mutate: func(value *Registration) {
			value.FixedEnvironment = []EnvironmentVariable{{Name: "API_TOKEN", Value: "secret"}}
		}},
		{name: "argument injection", mutate: func(value *Registration) { value.FixedArguments = []string{"ok\x00bad"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registration := testRegistration()
			test.mutate(&registration)
			if _, err := New(&fakeResolver{}, &fakeAuthorizer{}, testContainmentNetwork(&fakeNetworkBroker{}), &fakeRuntime{}, fixedClock{testNow},
				[]Registration{registration}); Code(err) != InvalidInput {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestTypedInputVocabularyAndBounds(t *testing.T) {
	executor, _, _, _, _ := testExecutor()
	request := testRequest()
	request.Inputs["message"] = InputValue{Kind: "integer", Integer: 1}
	result, err := executor.Execute(context.Background(), request)
	if Code(err) != InvalidInput || Reason(err) != "operation_input_type" || result.Provenance.Outcome != "invalid" {
		t.Fatalf("result=%+v error=%v", result, err)
	}
	executor, _, _, _, _ = testExecutor()
	request = testRequest()
	request.Inputs["message"] = InputValue{Kind: "string", String: string(make([]byte, 65))}
	if _, err := executor.Execute(context.Background(), request); Code(err) != InvalidInput || Reason(err) != "operation_input_bounds" {
		t.Fatalf("error=%v", err)
	}
	executor, _, _, _, _ = testExecutor()
	request = testRequest()
	request.Inputs["unknown"] = InputValue{Kind: "string", String: "value"}
	if _, err := executor.Execute(context.Background(), request); Code(err) != InvalidInput || Reason(err) != "operation_inputs" {
		t.Fatalf("error=%v", err)
	}
}

func TestContainerPlanRejectsDefaultBridgeAndCallerLikeExpansion(t *testing.T) {
	registration := testRegistration()
	capability := testCapability()
	plan := ContainerPlan{AttemptID: testRequest().AttemptID,
		ImageReference: registration.ImageRepository + "@" + registration.ImageDigest, ImageDigest: registration.ImageDigest,
		Entrypoint: registration.Entrypoint, Arguments: registration.FixedArguments, HealthArguments: registration.HealthArguments,
		Environment: []string{"LANG=C"}, Input: []byte(`{"message":"hello"}`), RunAsUser: registration.RunAsUser,
		RunAsGroup: registration.RunAsGroup, WorkingDirectory: "/work", WritableMounts: registration.WritableMounts,
		Limits: capability.Operation.ResourceLimits, Network: capability.Operation.NetworkPolicy, EngineNetwork: "none",
		NetworkPolicyHash: digestBytes(canonicalBytes(capability.Operation.NetworkPolicy))}
	if err := validateContainerPlan(plan); err != nil {
		t.Fatalf("valid plan error=%v", err)
	}
	tests := []struct {
		name   string
		mutate func(*ContainerPlan)
	}{
		{name: "floating image", mutate: func(value *ContainerPlan) { value.ImageReference = "registry.example/coh/fixture:latest" }},
		{name: "default bridge", mutate: func(value *ContainerPlan) { value.EngineNetwork = "bridge" }},
		{name: "root", mutate: func(value *ContainerPlan) { value.RunAsUser = 0 }},
		{name: "host mount", mutate: func(value *ContainerPlan) { value.WritableMounts[0].Destination = "/host" }},
		{name: "policy tamper", mutate: func(value *ContainerPlan) { value.NetworkPolicyHash = testDecisionDigest }},
		{name: "secret env", mutate: func(value *ContainerPlan) { value.Environment = []string{"TOKEN=value"} }},
		{name: "unenforceable CPU", mutate: func(value *ContainerPlan) {
			value.Limits.CPUMilliseconds = 1
			value.Limits.WallTimeMilliseconds = 1_000
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := plan
			changed.Arguments = append([]string(nil), plan.Arguments...)
			changed.WritableMounts = append([]WritableMount(nil), plan.WritableMounts...)
			test.mutate(&changed)
			if err := validateContainerPlan(changed); Code(err) != Denied {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
