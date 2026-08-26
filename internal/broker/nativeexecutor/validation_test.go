package nativeexecutor

import (
	"context"
	"testing"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

func TestRegistrationRejectsExecutableAndEnvironmentExpansion(t *testing.T) {
	valid := Registration{Tool: testRequest().Tool, Operation: "execute", ExecutablePath: "/approved/tool",
		FixedArguments: []string{"--fixed"}, FixedEnvironment: []EnvironmentVariable{{Name: "LANG", Value: "C"}}}
	tests := []struct {
		name   string
		mutate func(*Registration)
		reason string
	}{
		{"relative executable", func(value *Registration) { value.ExecutablePath = "tool" }, "registration_executable"},
		{"path lookup", func(value *Registration) { value.ExecutablePath = "/approved/../tool" }, "registration_executable"},
		{"argument nul", func(value *Registration) { value.FixedArguments = []string{"x\x00y"} }, "registration_arguments"},
		{"loader injection", func(value *Registration) {
			value.FixedEnvironment = []EnvironmentVariable{{Name: "DYLD_INSERT_LIBRARIES", Value: "/tmp/x"}}
		}, "registration_environment"},
		{"path environment", func(value *Registration) {
			value.FixedEnvironment = []EnvironmentVariable{{Name: "PATH", Value: "/tmp"}}
		}, "registration_environment"},
		{"secret environment", func(value *Registration) {
			value.FixedEnvironment = []EnvironmentVariable{{Name: "API_KEY", Value: "value"}}
		}, "registration_environment"},
		{"duplicate environment", func(value *Registration) {
			value.FixedEnvironment = []EnvironmentVariable{{Name: "LANG", Value: "C"}, {Name: "LANG", Value: "C"}}
		}, "registration_environment"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registration := valid
			test.mutate(&registration)
			if err := validateRegistration(registration); Reason(err) != test.reason {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestTypedInputVocabularyAndBounds(t *testing.T) {
	minimum, maximum := int64(1), int64(5)
	fields := []toolregistry.InputField{
		{Name: "count", Type: "integer", Required: true, Minimum: &minimum, Maximum: &maximum, Enum: []string{}},
		{Name: "digests", Type: "digest_list", Required: true, MaximumBytes: 71, MaximumItems: 2, Enum: []string{}},
		{Name: "mode", Type: "string", Required: true, MaximumBytes: 8, Enum: []string{"safe"}},
	}
	valid := map[string]InputValue{
		"count":   {Kind: "integer", Integer: 3},
		"digests": {Kind: "digest_list", Strings: []string{testDigest, inputDigest}},
		"mode":    {Kind: "string", String: "safe"},
	}
	if data, err := encodeInputs(fields, valid); err != nil || len(data) == 0 {
		t.Fatalf("valid input data=%s error=%v", data, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]InputValue)
		reason string
	}{
		{"missing", func(values map[string]InputValue) { delete(values, "mode") }, "operation_inputs"},
		{"numeric bound", func(values map[string]InputValue) { values["count"] = InputValue{Kind: "integer", Integer: 6} }, "operation_input_bounds"},
		{"enum", func(values map[string]InputValue) { values["mode"] = InputValue{Kind: "string", String: "unsafe"} }, "operation_input_bounds"},
		{"unsorted list", func(values map[string]InputValue) {
			values["digests"] = InputValue{Kind: "digest_list", Strings: []string{inputDigest, testDigest}}
		}, "operation_input_bounds"},
		{"duplicate list", func(values map[string]InputValue) {
			values["digests"] = InputValue{Kind: "digest_list", Strings: []string{testDigest, testDigest}}
		}, "operation_input_bounds"},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := make(map[string]InputValue, len(valid))
			for name, value := range valid {
				values[name] = value
			}
			test.mutate(values)
			if _, err := encodeInputs(fields, values); Reason(err) != test.reason {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCanceledRequestDoesNotAuthorizeOrExecute(t *testing.T) {
	resolver := &fakeResolver{capability: testCapability()}
	authorizer := testAuthorizer()
	artifacts := &fakeArtifacts{}
	sandbox := &fakeSandbox{execute: func(context.Context, Plan) (SandboxResult, error) { return SandboxResult{}, nil }}
	executor := newTestExecutor(t, resolver, authorizer, artifacts, sandbox)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := executor.Execute(ctx, testRequest()); Code(err) != Canceled ||
		authorizer.calls.Load() != 0 || resolver.calls.Load() != 0 || artifacts.calls.Load() != 0 || sandbox.calls.Load() != 0 {
		t.Fatalf("error=%v calls=%d/%d/%d/%d", err, authorizer.calls.Load(), resolver.calls.Load(), artifacts.calls.Load(), sandbox.calls.Load())
	}
}
