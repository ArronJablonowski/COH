package opaengine

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ArronJablonowski/COH/internal/policy"
)

func TestSignedBundleLoadAndTwoPhaseEvaluation(t *testing.T) {
	clock := &fixedClock{now: time.Date(2026, 8, 25, 23, 30, 0, 0, time.UTC)}
	audit := &auditMemory{}
	engine, err := New(audit, clock)
	if err != nil {
		t.Fatal(err)
	}
	key := newBundleKey(t, 3)
	contents := signedBundle(t, 7, key, allowPolicy)
	activation, err := engine.Load(t.Context(), contents, key.authority)
	if err != nil {
		t.Fatal(err)
	}
	if activation.PolicyDigest != digest(contents) || activation.PolicyRevision != 7 || activation.SignerKeyRevision != 3 {
		t.Fatalf("activation = %+v", activation)
	}
	request := validRequest(t, activation.PolicyDigest, activation.PolicyRevision)
	intent, err := engine.Evaluate(t.Context(), request, key.authority)
	if err != nil || intent.Outcome != "allowed" || !intent.ApprovalRequired || intent.InputDigest == "" || intent.DecisionDigest == "" {
		t.Fatalf("intent = %+v, err = %v", intent, err)
	}
	request.Phase, request.EvaluationID = policy.PreDispatch, uuid("9")
	dispatch, err := engine.Evaluate(t.Context(), request, key.authority)
	if err != nil || dispatch.Outcome != "allowed" || dispatch.Phase != policy.PreDispatch || dispatch.DecisionDigest == intent.DecisionDigest {
		t.Fatalf("dispatch = %+v, err = %v", dispatch, err)
	}
	if len(audit.events) != 3 || audit.events[0].Kind != "policy_activation" || audit.events[2].Decision.Outcome != "allowed" {
		t.Fatalf("audit events = %+v", audit.events)
	}
}

func TestCommittedSignedBundleFixture(t *testing.T) {
	contents, authority := committedBundle(t)
	if digest(contents) != "sha256:443fec8618e5f466af7fdfc95ab100ef36f075f61d78d824b02c1249bb0c2347" {
		t.Fatalf("committed bundle digest = %s", digest(contents))
	}
	engine, err := New(&auditMemory{}, &fixedClock{now: time.Date(2026, 8, 25, 23, 30, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	activation, err := engine.Load(t.Context(), contents, authority)
	if err != nil || activation.PolicyRevision != 7 || activation.PolicyDigest != digest(contents) {
		t.Fatalf("activation = %+v, err = %v", activation, err)
	}
}

func TestDefaultDenyRuntimeAuthority(t *testing.T) {
	engine, key, activation := loadedEngine(t)
	base := validRequest(t, activation.PolicyDigest, activation.PolicyRevision)
	tests := []struct {
		name   string
		reason string
		mutate func(*policy.Request)
	}{
		{"tool", "unknown_tool", func(r *policy.Request) { r.Runtime.ToolRegistered = false }},
		{"target", "unknown_target", func(r *policy.Request) { r.Runtime.TargetsAuthorized = false }},
		{"tenant", "unknown_tenant", func(r *policy.Request) { r.Runtime.TenantAuthorized = false }},
		{"route", "unknown_data_route", func(r *policy.Request) { r.Runtime.DataRouteAuthorized = false }},
		{"capability", "unknown_capability_field", func(r *policy.Request) { r.Runtime.CapabilityFieldsKnown = false }},
		{"validator", "validator_unqualified", func(r *policy.Request) { r.Runtime.ValidatorState = "stale" }},
		{"estop", "emergency_stop_active", func(r *policy.Request) { r.Runtime.EmergencyStopActive = true }},
		{"actor", "actor_revoked", func(r *policy.Request) { r.Actor.Active = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			request.EvaluationID = uuid("8")
			test.mutate(&request)
			decision, err := engine.Evaluate(t.Context(), request, key.authority)
			if policy.Code(err) != policy.Denied || decision.Outcome != "denied" || decision.ReasonCode != test.reason {
				t.Fatalf("decision = %+v, err = %v", decision, err)
			}
		})
	}
}

func TestTamperRevocationStaleStateAndRecovery(t *testing.T) {
	engine, key, activation := loadedEngine(t)
	request := validRequest(t, activation.PolicyDigest, activation.PolicyRevision)

	revoked := key.authority
	revoked.Active = false
	decision, err := engine.Evaluate(t.Context(), request, revoked)
	if policy.Code(err) != policy.Denied || decision.ReasonCode != "policy_signer_revoked" {
		t.Fatalf("revoked = %+v, err = %v", decision, err)
	}

	tampered := signedBundle(t, 8, key, allowPolicy)
	tampered[len(tampered)/2] ^= 1
	if _, err := engine.Load(t.Context(), tampered, key.authority); policy.Code(err) != policy.Denied {
		t.Fatalf("tamper err = %v", err)
	}
	if decision, err = engine.Evaluate(t.Context(), request, key.authority); err != nil || decision.Outcome != "allowed" {
		t.Fatalf("last-known-good = %+v, err = %v", decision, err)
	}

	duplicate := bytes.Replace(signedBundle(t, 8, key, allowPolicy),
		[]byte(`"contract_version":"1.0.0"`),
		[]byte(`"contract_version":"1.0.0","contract_version":"1.0.0"`), 1)
	if _, err := engine.Load(t.Context(), duplicate, key.authority); policy.Reason(err) != "bundle_verification_failed" {
		t.Fatalf("duplicate-key err = %v", err)
	}

	newBundle := signedBundle(t, 8, key, allowPolicy)
	newActivation, err := engine.Load(t.Context(), newBundle, key.authority)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Load(t.Context(), newBundle, key.authority); policy.Reason(err) != "bundle_revision_stale" {
		t.Fatalf("replay err = %v", err)
	}
	decision, err = engine.Evaluate(t.Context(), request, key.authority)
	if policy.Code(err) != policy.Denied || decision.ReasonCode != "policy_state_stale" {
		t.Fatalf("stale = %+v, err = %v, new = %+v", decision, err, newActivation)
	}
}

func TestPolicyDenialTimeoutAndPreDispatchRevocation(t *testing.T) {
	clock := &fixedClock{now: time.Date(2026, 8, 25, 23, 30, 0, 0, time.UTC)}
	audit := &auditMemory{}
	engine, _ := New(audit, clock)
	key := newBundleKey(t, 3)
	activation, err := engine.Load(t.Context(), signedBundle(t, 7, key, allowPolicy), key.authority)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest(t, activation.PolicyDigest, activation.PolicyRevision)
	request.Actor.Permissions = []string{"case.read"}
	decision, err := engine.Evaluate(t.Context(), request, key.authority)
	if policy.Code(err) != policy.Denied || decision.ReasonCode != "policy_denied" || len(audit.events) != 2 {
		t.Fatalf("policy denial = %+v, events = %d, err = %v", decision, len(audit.events), err)
	}

	request.Actor.Permissions, request.Phase = []string{"action.request"}, policy.PreDispatch
	rotated := key.authority
	rotated.KeyRevision++
	decision, err = engine.Evaluate(t.Context(), request, rotated)
	if policy.Code(err) != policy.Denied || decision.ReasonCode != "policy_signer_revoked" {
		t.Fatalf("pre-dispatch revocation = %+v, err = %v", decision, err)
	}
	sameRevisionWrongKey := newBundleKey(t, key.authority.KeyRevision).authority
	decision, err = engine.Evaluate(t.Context(), request, sameRevisionWrongKey)
	if policy.Code(err) != policy.Denied || decision.ReasonCode != "policy_signer_revoked" {
		t.Fatalf("same-revision key replacement = %+v, err = %v", decision, err)
	}

	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	decision, err = engine.Evaluate(expired, request, key.authority)
	if policy.Code(err) != policy.Timeout || decision.Outcome != "timeout" || decision.ReasonCode != "request_timeout" {
		t.Fatalf("timeout = %+v, err = %v", decision, err)
	}
	decision, err = engine.Evaluate(t.Context(), request, key.authority)
	if err != nil || decision.Outcome != "allowed" {
		t.Fatalf("fresh recovery = %+v, err = %v", decision, err)
	}
}

func TestSignedBundleData(t *testing.T) {
	clock := &fixedClock{now: time.Date(2026, 8, 25, 23, 30, 0, 0, time.UTC)}
	audit := &auditMemory{}
	engine, _ := New(audit, clock)
	key := newBundleKey(t, 3)
	source := strings.Replace(allowPolicy,
		`input.runtime.validator_state == "qualified"`,
		`input.runtime.validator_state == "qualified"
	data.flags.enabled == true`, 1)
	var envelope signedBundleEnvelope
	if err := json.Unmarshal(signedBundle(t, 7, key, source), &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Bundle.Data = map[string]any{"flags": map[string]any{"enabled": true}}
	contents := signPolicyBundle(t, envelope.Bundle, key)
	activation, err := engine.Load(t.Context(), contents, key.authority)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest(t, activation.PolicyDigest, activation.PolicyRevision)
	if decision, err := engine.Evaluate(t.Context(), request, key.authority); err != nil || decision.Outcome != "allowed" {
		t.Fatalf("data decision = %+v, err = %v", decision, err)
	}
}

func TestConcurrentActivationCannotRollBackRevision(t *testing.T) {
	engine, err := New(&auditMemory{}, &fixedClock{now: time.Date(2026, 8, 25, 23, 30, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	key := newBundleKey(t, 3)
	seven, eight := signedBundle(t, 7, key, allowPolicy), signedBundle(t, 8, key, allowPolicy)
	var wait sync.WaitGroup
	wait.Add(2)
	for _, contents := range [][]byte{seven, eight} {
		go func() {
			defer wait.Done()
			_, _ = engine.Load(context.Background(), contents, key.authority)
		}()
	}
	wait.Wait()
	request := validRequest(t, digest(eight), 8)
	decision, err := engine.Evaluate(t.Context(), request, key.authority)
	if err != nil || decision.PolicyRevision != 8 || decision.PolicyDigest != digest(eight) {
		t.Fatalf("highest revision = %+v, err = %v", decision, err)
	}
}

func TestFailClosedPolicyOutputAuditAndContext(t *testing.T) {
	clock := &fixedClock{now: time.Date(2026, 8, 25, 23, 30, 0, 0, time.UTC)}
	audit := &auditMemory{}
	engine, _ := New(audit, clock)
	key := newBundleKey(t, 3)
	invalidOutput := strings.Replace(allowPolicy, `"approval_required": true}`, `"approval_required": true, "extra": true}`, 1)
	contents := signedBundle(t, 7, key, invalidOutput)
	activation, err := engine.Load(t.Context(), contents, key.authority)
	if err != nil {
		t.Fatal(err)
	}
	request := validRequest(t, activation.PolicyDigest, activation.PolicyRevision)
	decision, err := engine.Evaluate(t.Context(), request, key.authority)
	if policy.Code(err) != policy.Denied || decision.ReasonCode != "policy_output_invalid" {
		t.Fatalf("output = %+v, err = %v", decision, err)
	}

	audit.fail = true
	decision, err = engine.Evaluate(t.Context(), request, key.authority)
	if policy.Code(err) != policy.Unavailable || decision.Outcome != "unavailable" || decision.ReasonCode != "audit_unavailable" {
		t.Fatalf("audit = %+v, err = %v", decision, err)
	}

	audit.fail = false
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	decision, err = engine.Evaluate(canceled, request, key.authority)
	if policy.Code(err) != policy.Canceled || decision.Outcome != "canceled" || decision.DecisionDigest == "" {
		t.Fatalf("cancel = %+v, err = %v", decision, err)
	}
	decision, err = engine.Evaluate(t.Context(), request, key.authority)
	if policy.Code(err) != policy.Denied || decision.ReasonCode != "policy_output_invalid" {
		t.Fatalf("recovery = %+v, err = %v", decision, err)
	}
}

func TestUnsignedWrongKeyUnsafeBuiltinAndAuditActivationDeny(t *testing.T) {
	clock := &fixedClock{now: time.Date(2026, 8, 25, 23, 30, 0, 0, time.UTC)}
	audit := &auditMemory{}
	engine, _ := New(audit, clock)
	key, wrong := newBundleKey(t, 3), newBundleKey(t, 3)
	contents := signedBundle(t, 7, key, allowPolicy)
	if _, err := engine.Load(t.Context(), contents, wrong.authority); policy.Code(err) != policy.Denied {
		t.Fatalf("wrong-key err = %v", err)
	}
	unsafe := strings.Replace(allowPolicy, `input.schema_version == "coh.policy-input/v1"`, `http.send({"method":"get","url":"https://example.invalid"})`, 1)
	if _, err := engine.Load(t.Context(), signedBundle(t, 7, key, unsafe), key.authority); policy.Reason(err) != "bundle_verification_failed" && policy.Reason(err) != "bundle_compile_failed" {
		t.Fatalf("unsafe err = %v", err)
	}
	audit.fail = true
	if _, err := engine.Load(t.Context(), contents, key.authority); policy.Reason(err) != "audit_unavailable" {
		t.Fatalf("activation audit err = %v", err)
	}
	audit.fail = false
	request := validRequest(t, digest(contents), 7)
	decision, err := engine.Evaluate(t.Context(), request, key.authority)
	if policy.Code(err) != policy.Denied || decision.ReasonCode != "policy_unavailable" {
		t.Fatalf("unpublished activation = %+v, err = %v", decision, err)
	}
}

func loadedEngine(t *testing.T) (*Engine, bundleKey, policy.Activation) {
	t.Helper()
	engine, err := New(&auditMemory{}, &fixedClock{now: time.Date(2026, 8, 25, 23, 30, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	key := newBundleKey(t, 3)
	activation, err := engine.Load(t.Context(), signedBundle(t, 7, key, allowPolicy), key.authority)
	if err != nil {
		t.Fatal(err)
	}
	return engine, key, activation
}

func digest(value []byte) string {
	var envelope signedBundleEnvelope
	if err := json.Unmarshal(value, &envelope); err != nil {
		return ""
	}
	return envelope.BundleDigest
}
