package profileactivation

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestActivationRecordsAreCanonicalStrictAndTamperEvident(t *testing.T) {
	request := activationTestRequest()
	intent, err := intentDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	transition := Transition{SchemaVersion: TransitionSchema, ContractVersion: ContractVersion,
		TransitionID: request.TransitionID, IntentDigest: intent, Mode: request.Mode,
		MaxDrainDurationMS: request.MaxDrainDurationMS, Candidate: request.Candidate,
		Phase: Prepared, Sequence: 1, CreatedAt: "2026-08-28T08:00:00Z", UpdatedAt: "2026-08-28T08:00:00Z"}
	encoded, digest, err := CanonicalTransition(context.Background(), transition)
	if err != nil || digest == "" {
		t.Fatalf("digest=%s err=%v", digest, err)
	}
	decoded, err := DecodeTransition(context.Background(), encoded)
	if err != nil || decoded.TransitionDigest != digest {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	unknown := []byte(strings.Replace(string(encoded), `"schema_version":`, `"unknown":true,"schema_version":`, 1))
	if _, err := DecodeTransition(context.Background(), unknown); Code(err) != InvalidInput {
		t.Fatalf("unknown err=%v", err)
	}
	tampered := []byte(strings.Replace(string(encoded), string(Prepared), string(Quiescent), 1))
	if _, err := DecodeTransition(context.Background(), tampered); err == nil {
		t.Fatal("tampered transition accepted")
	}
	active := activeFromTransition(decoded, "2026-08-28T08:00:01Z")
	activeBytes, activeDigest, err := CanonicalActive(context.Background(), active)
	if err != nil || activeDigest == "" {
		t.Fatalf("active digest=%s err=%v", activeDigest, err)
	}
	if value, err := DecodeActive(context.Background(), activeBytes); err != nil || value.ActiveDigest != activeDigest {
		t.Fatalf("active=%+v err=%v", value, err)
	}
}

func TestActivationBoundaryHasNoGenericCallbackOrExecutableAuthority(t *testing.T) {
	gate := reflect.TypeOf((*MaintenanceGate)(nil)).Elem()
	if gate.NumMethod() != 2 || gate.Method(0).Name != "Quiesce" || gate.Method(1).Name != "Release" {
		t.Fatalf("maintenance gate=%v", gate)
	}
	for _, value := range []any{Request{}, Candidate{}, Transition{}, ActiveProfile{}, QuiescencePlan{}, QuiescenceAttestation{}, Result{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			if typeOf.Field(index).Type.Kind() == reflect.Func || typeOf.Field(index).Type.Kind() == reflect.Interface {
				t.Fatalf("%s exposes authority field %s", typeOf, typeOf.Field(index).Name)
			}
		}
	}
	if _, err := NewController(nil, nil, nil); Code(err) != InvalidInput {
		t.Fatalf("missing dependency err=%v", err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, _, err := CanonicalTransition(ctx, Transition{}); Code(err) != Timeout {
		t.Fatalf("timeout err=%v", err)
	}
}

func activationTestRequest() Request {
	digest := "sha256:" + strings.Repeat("1", 64)
	return Request{TransitionID: "018f0000-0000-7000-8000-000000000901", Mode: Startup, MaxDrainDurationMS: 30000,
		Candidate: Candidate{ProfileID: "018f0000-0000-7000-8000-000000000900", ProfileRevision: 1,
			Target: Target{DeploymentKind: "native_workstation", ConnectivityMode: "connected",
				Platform: "darwin_arm64", Surface: "web"}, ProfileBindingDigest: digest,
			CompositionDigest: digest, CapabilityGraphDigest: digest, InspectionDigest: digest}}
}
