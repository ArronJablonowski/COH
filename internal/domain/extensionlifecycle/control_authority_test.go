package extensionlifecycle

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestControlAuthorityAndEStopObservationCannotBeSerialized(t *testing.T) {
	if _, err := json.Marshal(ControlAuthority{}); err == nil {
		t.Fatal("control authority serialized")
	}
	if _, err := json.Marshal(EStopObservation{}); err == nil {
		t.Fatal("E-stop observation serialized")
	}
	var authority ControlAuthority
	if err := json.Unmarshal([]byte(`{}`), &authority); err == nil {
		t.Fatal("control authority accepted JSON")
	}
	var estop EStopObservation
	if err := json.Unmarshal([]byte(`{}`), &estop); err == nil {
		t.Fatal("E-stop observation accepted JSON")
	}
}

func TestControlAuthorityBindsAdministratorAndFreshBrokerEStop(t *testing.T) {
	fixture := newAdmissionFixture(t)
	intent, err := DecodeIntent(context.Background(), fixture.intent)
	if err != nil {
		t.Fatal(err)
	}
	command := intent.Value()
	authority := ControlAuthority{ObservedAt: testNow.Add(-time.Second), ExpiresAt: testNow.Add(time.Minute),
		ActorID: command.ActorID, ActorKind: "administrator", OrganizationID: command.OrganizationID,
		TenantID: command.TenantID, ActorRevision: 3, Authenticated: true, Active: true,
		Administrator: true, LifecycleAllowed: true, AuthorizationDecisionDigest: testDigest('d')}
	estop := EStopObservation{ObservedAt: testNow, OrganizationID: command.OrganizationID,
		TenantID: command.TenantID, State: "armed", Revision: command.EStopRevision}
	if err := VerifyControlAuthority(context.Background(), intent, authority, estop, fixture.snapshot, fixedClock{testNow}); err != nil {
		t.Fatalf("VerifyControlAuthority() error = %v", err)
	}
}

func TestControlAuthorityDeniesAgentsAuthorityDriftAndEStop(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ControlAuthority, *EStopObservation)
		reason string
	}{
		{"production agent", func(authority *ControlAuthority, _ *EStopObservation) { authority.ProductionAgent = true }, "production_agent_lifecycle_denied"},
		{"agent kind", func(authority *ControlAuthority, _ *EStopObservation) { authority.ActorKind = "agent" }, "production_agent_lifecycle_denied"},
		{"not administrator", func(authority *ControlAuthority, _ *EStopObservation) { authority.Administrator = false }, "command_root_authority"},
		{"authorization denied", func(authority *ControlAuthority, _ *EStopObservation) { authority.LifecycleAllowed = false }, "command_root_authority"},
		{"caller mismatch", func(authority *ControlAuthority, _ *EStopObservation) {
			authority.ActorID = "0198d6c4-0099-7000-8000-000000000099"
		}, "command_root_binding"},
		{"tripped", func(_ *ControlAuthority, estop *EStopObservation) { estop.State = "tripped" }, "broker_estop_boundary"},
		{"stale", func(_ *ControlAuthority, estop *EStopObservation) {
			estop.ObservedAt = testNow.Add(-MaximumEStopObservationAge - time.Second)
		}, "broker_estop_boundary"},
		{"revision drift", func(_ *ControlAuthority, estop *EStopObservation) { estop.Revision++ }, "broker_estop_boundary"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newAdmissionFixture(t)
			intent, err := DecodeIntent(context.Background(), fixture.intent)
			if err != nil {
				t.Fatal(err)
			}
			command := intent.Value()
			authority := ControlAuthority{ObservedAt: testNow.Add(-time.Second), ExpiresAt: testNow.Add(time.Minute),
				ActorID: command.ActorID, ActorKind: "administrator", OrganizationID: command.OrganizationID,
				TenantID: command.TenantID, ActorRevision: 3, Authenticated: true, Active: true,
				Administrator: true, LifecycleAllowed: true, AuthorizationDecisionDigest: testDigest('d')}
			estop := EStopObservation{ObservedAt: testNow, OrganizationID: command.OrganizationID,
				TenantID: command.TenantID, State: "armed", Revision: command.EStopRevision}
			test.mutate(&authority, &estop)
			err = VerifyControlAuthority(context.Background(), intent, authority, estop, fixture.snapshot, fixedClock{testNow})
			if Reason(err) != test.reason {
				t.Fatalf("reason = %q, want %q (err=%v)", Reason(err), test.reason, err)
			}
		})
	}
}
