package estop

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const (
	orgID     = "018f47a6-4b2c-7a1e-8a12-123456789abc"
	tenantID  = "018f47a6-4b2c-7a1e-8a12-123456789abd"
	caseID    = "018f47a6-4b2c-7a1e-8a12-123456789abe"
	actorID   = "018f47a6-4b2c-7a1e-8a12-123456789abf"
	requestID = "018f47a6-4b2c-7a1e-8a12-123456789ac0"
)

func TestCommandCanonicalContract(t *testing.T) {
	command := validCommand()
	encoded, _ := json.Marshal(command)
	decoded, err := DecodeCommand(encoded)
	if err != nil || decoded != command {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	digest, err := CommandDigest(command)
	if err != nil || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	unknown := append(encoded[:len(encoded)-1], []byte(`,"unknown":true}`)...)
	if _, err = DecodeCommand(unknown); Code(err) != InvalidInput {
		t.Fatalf("unknown err=%v", err)
	}
	duplicate := []byte(strings.Replace(string(encoded), `"actor_id":`, `"actor_id":"duplicate","actor_id":`, 1))
	if _, err = DecodeCommand(duplicate); Code(err) != InvalidInput {
		t.Fatalf("duplicate err=%v", err)
	}
}

func TestScopeAndAuthorityDenials(t *testing.T) {
	now := time.Date(2026, 8, 26, 5, 0, 0, 0, time.UTC)
	authority := validAuthority(now)
	if err := ValidateAuthority(authority, now); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Authority)
		reason string
	}{
		{"actor", func(value *Authority) { value.ActorActive = false }, "actor_revoked"},
		{"authorization", func(value *Authority) { value.AuthorizationAllowed = false }, "authorization_denied"},
		{"policy", func(value *Authority) { value.PolicyAllowed = false }, "policy_denied"},
		{"stale", func(value *Authority) { value.ObservedAt = now.Add(-time.Minute) }, "authority_stale"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := authority
			test.mutate(&changed)
			if err := ValidateAuthority(changed, now); Reason(err) != test.reason {
				t.Fatalf("reason=%q err=%v", Reason(err), err)
			}
		})
	}
	global := validCommand().Scope
	global.CaseID = caseID
	if err := ValidateScope(global); Reason(err) != "global_scope_invalid" {
		t.Fatalf("global err=%v", err)
	}
	caseScope := Scope{Kind: "case", OrganizationID: orgID, TenantID: tenantID}
	if err := ValidateScope(caseScope); Reason(err) != "case_scope_invalid" {
		t.Fatalf("case err=%v", err)
	}
}

func TestStateAcknowledgementAndDecision(t *testing.T) {
	now := time.Date(2026, 8, 26, 5, 0, 0, 0, time.UTC)
	command, authority := validCommand(), validAuthority(now)
	digest, _ := CommandDigest(command)
	state := State{SchemaVersion: StateSchemaVersion, ContractVersion: ContractVersion, Scope: command.Scope,
		Epoch: 1, Active: true, RequestID: command.RequestID, RequestDigest: digest, ActorID: actorID,
		ActorRevision: authority.ActorRevision, ReasonCode: command.ReasonCode,
		AuthorizationDecisionDigest: authority.AuthorizationDecisionDigest,
		PolicyDecisionDigest:        authority.PolicyDecisionDigest, ActivatedAt: now}
	if err := ValidateState(state); err != nil {
		t.Fatal(err)
	}
	ack := Acknowledgement{SchemaVersion: AckSchemaVersion, ContractVersion: ContractVersion,
		Scope: command.Scope, Epoch: 1, ControlID: "runner-egress", ControlKind: "egress", Outcome: "applied",
		ReasonCode: "control_applied", EvidenceDigest: digestOf("evidence"), StartedAt: now,
		CompletedAt: now.Add(time.Millisecond), ElapsedNanos: int64(time.Millisecond), ObjectiveNanos: int64(EgressCutObjective)}
	if err := ValidateAcknowledgement(ack); err != nil {
		t.Fatal(err)
	}
	first := FinalizeDecision(Decision{Event: "activation", Outcome: "allowed", ReasonCode: "stop_activated",
		Scope: command.Scope, OccurredAt: now})
	changed := first
	changed.ReasonCode = "changed"
	changed = FinalizeDecision(changed)
	if first.SchemaVersion != DecisionSchemaVersion || first.DecisionDigest == changed.DecisionDigest {
		t.Fatalf("first=%#v changed=%#v", first, changed)
	}
}

func validCommand() Command {
	return Command{SchemaVersion: CommandSchemaVersion, ContractVersion: ContractVersion,
		RequestID: requestID, IdempotencyKey: "stop-1", Scope: Scope{Kind: "global", OrganizationID: orgID, TenantID: tenantID},
		ActorID: actorID, ReasonCode: "operator_emergency"}
}

func validAuthority(now time.Time) Authority {
	return Authority{Scope: validCommand().Scope, ActorID: actorID, ActorRevision: 3, ActorActive: true,
		AuthorizationAllowed: true, AuthorizationDecisionDigest: digestOf("authorization"), PolicyAllowed: true,
		PolicyDecisionDigest: digestOf("policy"), ObservedAt: now}
}

func digestOf(value string) string {
	sum := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
