package ociexecutor

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

func TestPublicContractsExcludeCallerControlledContainerExecution(t *testing.T) {
	request := reflect.TypeOf(Request{})
	for _, forbidden := range []string{"Image", "ImageReference", "ImageDigest", "Entrypoint", "Arguments", "Command",
		"Environment", "Mounts", "Network", "Runtime", "Capability", "Policy", "Authorization", "User", "Group"} {
		if _, found := request.FieldByName(forbidden); found {
			t.Fatalf("Request exposes %s", forbidden)
		}
	}
	authority := reflect.TypeOf(DispatchAuthority{})
	for _, forbidden := range []string{"Image", "Arguments", "Environment", "Mounts", "EngineNetwork", "Capability"} {
		if _, found := authority.FieldByName(forbidden); found {
			t.Fatalf("DispatchAuthority exposes %s", forbidden)
		}
	}
	plan := reflect.TypeOf(ContainerPlan{})
	for _, required := range []string{"ImageReference", "ImageDigest", "Entrypoint", "Arguments", "HealthArguments",
		"RunAsUser", "RunAsGroup", "WritableMounts", "Limits", "Network", "EngineNetwork", "NetworkPolicyHash"} {
		if _, found := plan.FieldByName(required); !found {
			t.Fatalf("ContainerPlan missing %s", required)
		}
	}
}

func TestNoNetworkBrokerFailsClosedForConnectedPolicies(t *testing.T) {
	broker, err := NewNoNetworkBroker(fixedClock{testNow})
	if err != nil {
		t.Fatal(err)
	}
	authorityUntil := formatTime(testNow.Add(time.Minute))
	policy := noNetwork()
	request := NetworkRequest{AttemptID: testRequest().AttemptID, OrganizationID: testRequest().OrganizationID,
		TenantID: testRequest().TenantID, CaseID: testRequest().CaseID, ActorID: testRequest().ActorID,
		AuthorizationID: "0198d6c4-7777-7777-8777-777777777777", AuthorityUntil: authorityUntil,
		Policy: policy, PolicyDigest: digestBytes(canonicalBytes(policy))}
	lease, err := broker.Acquire(context.Background(), request)
	if err != nil || lease.EngineNetwork != "none" || lease.Cleanup == nil || lease.EnforcementDigest == "" {
		t.Fatalf("lease=%+v error=%v", lease, err)
	}
	request.Policy = toolregistry.NetworkPolicy{Mode: "target_only", Protocols: []string{"tcp"}, DNSMode: "none", MaximumConnections: 1}
	request.PolicyDigest = digestBytes(canonicalBytes(request.Policy))
	if _, err := broker.Acquire(context.Background(), request); Code(err) != Denied || Reason(err) != "network_policy_not_supported" {
		t.Fatalf("connected policy error=%v", err)
	}
}

func TestProvenanceContainsSecurityBindingsWithoutRawValues(t *testing.T) {
	typeOf := reflect.TypeOf(Provenance{})
	for _, required := range []string{"AuthorizationID", "PolicyDecisionDigest", "ManifestDigest", "ImageReferenceDigest",
		"ResolvedImageDigest", "EntrypointDigest", "ArgumentDigest", "EnvironmentDigest", "InputDigest", "MountDigest",
		"NetworkPolicyDigest", "NetworkEnforcementHash", "ContainerSpecDigest", "HealthCommandDigest", "RuntimeDigest",
		"CleanupComplete", "Replayed"} {
		if _, found := typeOf.FieldByName(required); !found {
			t.Fatalf("Provenance missing %s", required)
		}
	}
	for _, forbidden := range []string{"Input", "Inputs", "Environment", "Arguments", "Mounts", "Secret", "Credential"} {
		if _, found := typeOf.FieldByName(forbidden); found {
			t.Fatalf("Provenance exposes %s", forbidden)
		}
	}
}
