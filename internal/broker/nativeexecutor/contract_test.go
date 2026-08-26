package nativeexecutor

import (
	"reflect"
	"testing"
)

func TestNarrowPublicContractsExcludeCallerControlledExecution(t *testing.T) {
	request := reflect.TypeFor[Request]()
	expected := []string{"AttemptID", "OrganizationID", "TenantID", "CaseID", "ActorID", "Tool",
		"Operation", "RequiredTier", "Publisher", "Inputs"}
	if request.NumField() != len(expected) {
		t.Fatalf("Request fields=%d want=%d", request.NumField(), len(expected))
	}
	for index, name := range expected {
		if request.Field(index).Name != name {
			t.Fatalf("Request field[%d]=%s want=%s", index, request.Field(index).Name, name)
		}
	}
	for _, forbidden := range []string{"ExecutablePath", "Arguments", "Environment", "RuntimeCeiling", "Command", "URL"} {
		if _, found := request.FieldByName(forbidden); found {
			t.Fatalf("Request exposes caller-controlled %s", forbidden)
		}
	}
	assertInterfaceMethods(t, reflect.TypeFor[Resolver](), []string{"ResolveOperation"})
	assertInterfaceMethods(t, reflect.TypeFor[Authorizer](), []string{"Authorize"})
	assertInterfaceMethods(t, reflect.TypeFor[ArtifactPreparer](), []string{"Prepare"})
	assertInterfaceMethods(t, reflect.TypeFor[Sandbox](), []string{"Execute"})
}

func TestProvenanceContainsAuthorityAndExecutionBindings(t *testing.T) {
	value := reflect.TypeFor[Provenance]()
	for _, required := range []string{"AttemptID", "OrganizationID", "TenantID", "CaseID", "ActorID",
		"AuthorizationID", "PolicyDecisionDigest", "ManifestDigest", "ManifestID", "Tool", "Operation",
		"RequiredTier", "EffectiveCeiling", "ArtifactDigest", "ArgumentDigest", "EnvironmentDigest",
		"InputDigest", "StartedAt", "FinishedAt", "Outcome", "Reason", "ExitCode", "TerminationSignal",
		"StandardOutput", "StandardError", "Replayed"} {
		if _, found := value.FieldByName(required); !found {
			t.Fatalf("Provenance is missing %s", required)
		}
	}
}

func assertInterfaceMethods(t *testing.T, value reflect.Type, expected []string) {
	t.Helper()
	if value.NumMethod() != len(expected) {
		t.Fatalf("%s methods=%d want=%d", value, value.NumMethod(), len(expected))
	}
	for index, name := range expected {
		if value.Method(index).Name != name {
			t.Fatalf("%s method[%d]=%s want=%s", value, index, value.Method(index).Name, name)
		}
	}
}
