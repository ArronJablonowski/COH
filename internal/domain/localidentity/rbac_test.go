package localidentity

import (
	"encoding/json"
	"strings"
	"testing"
)

const (
	testOrganizationID = "0198d6c4-0b68-7c4f-908d-bb21b4e5ac9e"
	testTenantID       = "0198d6c4-22dc-7b3c-af2c-75c1b8eb4f16"
	testCaseID         = "0198d6c4-7618-7d31-8e0a-9da53cae8ca2"
	testActorID        = "0198d6c4-1111-7111-8111-111111111111"
	testRequestID      = "0198d6c4-2222-7222-8222-222222222222"
	testDigest         = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testPublicKey      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func TestRolePermissionMatrix(t *testing.T) {
	tests := []struct {
		role    Role
		allowed Permission
		denied  Permission
		tier    ActionTier
	}{
		{Analyst, QueryExecute, ApprovalDecide, ""},
		{Approver, ApprovalDecide, ActionRequest, T2},
		{Administrator, ConfigurationManage, ApprovalDecide, ""},
		{Auditor, AuditRead, CaseWrite, ""},
		{Service, ServiceInvoke, ConfigurationManage, ""},
	}
	for _, test := range tests {
		t.Run(string(test.role), func(t *testing.T) {
			actor := validActor(test.role)
			allowed := validRequest(test.allowed, test.tier)
			decision, err := EvaluateRBAC(actor, allowed)
			if err != nil || decision.Outcome != "allowed" || decision.ReasonCode != "role_scope_allowed" {
				t.Fatalf("allowed decision = %+v, err = %v", decision, err)
			}
			deniedTier := ActionTier("")
			if test.denied == ActionRequest {
				deniedTier = T1
			}
			if test.denied == ApprovalDecide {
				deniedTier = T2
			}
			decision, err = EvaluateRBAC(actor, validRequest(test.denied, deniedTier))
			if Code(err) != Denied || decision.Outcome != "denied" || decision.ReasonCode != "role_permission_denied" {
				t.Fatalf("denied decision = %+v, err = %v", decision, err)
			}
		})
	}
}

func TestRolesAreIndependentlyAssignableAndDoNotImplyApproval(t *testing.T) {
	actor := validActor(Administrator, Analyst)
	for _, permission := range []Permission{ConfigurationManage, QueryExecute} {
		if decision, err := EvaluateRBAC(actor, validRequest(permission, "")); err != nil || decision.Outcome != "allowed" {
			t.Fatalf("permission %q decision = %+v, err = %v", permission, decision, err)
		}
	}
	decision, err := EvaluateRBAC(actor, validRequest(ApprovalDecide, T3))
	if Code(err) != Denied || decision.ReasonCode != "role_permission_denied" {
		t.Fatalf("administrator implied approval: decision = %+v, err = %v", decision, err)
	}
}

func TestOrganizationTenantCaseAndActorIsolation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
		reason string
	}{
		{"organization", func(value *Request) { value.Context.OrganizationID = "0198d6c4-3333-7333-8333-333333333333" }, "identity_scope_mismatch"},
		{"actor", func(value *Request) { value.Context.ActorID = "0198d6c4-3333-7333-8333-333333333333" }, "identity_scope_mismatch"},
		{"tenant", func(value *Request) { value.Context.TenantID = "0198d6c4-3333-7333-8333-333333333333" }, "case_scope_denied"},
		{"case", func(value *Request) { value.Context.CaseID = "0198d6c4-3333-7333-8333-333333333333" }, "case_scope_denied"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest(EvidenceRead, "")
			test.mutate(&request)
			decision, err := EvaluateRBAC(validActor(Analyst), request)
			if Code(err) != Denied || decision.ReasonCode != test.reason {
				t.Fatalf("decision = %+v, err = %v", decision, err)
			}
		})
	}
}

func TestInactiveInvalidAndAmbiguousActorsDeny(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Actor)
		reason string
	}{
		{"inactive", func(value *Actor) { value.Active = false }, "actor_revoked"},
		{"missing-key", func(value *Actor) { value.PublicKey = "" }, "actor_invalid"},
		{"mixed-service", func(value *Actor) { value.Roles = []Role{Analyst, Service} }, "actor_invalid"},
		{"duplicate-role", func(value *Actor) { value.Roles = []Role{Analyst, Analyst} }, "actor_invalid"},
		{"unsorted-case", func(value *Actor) {
			value.Grants[0].CaseIDs = []string{"0198d6c4-9999-7999-8999-999999999999", testCaseID}
		}, "actor_invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actor := validActor(Analyst)
			test.mutate(&actor)
			decision, err := EvaluateRBAC(actor, validRequest(CaseRead, ""))
			if Code(err) != Denied || decision.ReasonCode != test.reason {
				t.Fatalf("decision = %+v, err = %v", decision, err)
			}
		})
	}
}

func TestRequestRequiresCompleteContextAndConsistentTier(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
		code   ErrorCode
		reason string
	}{
		{"missing-case", func(value *Request) { value.Context.CaseID = "" }, InvalidInput, "request_identity"},
		{"unknown-channel", func(value *Request) { value.Channel = "websocket" }, InvalidInput, "request_channel"},
		{"unknown-permission", func(value *Request) { value.Permission = "root" }, Denied, "unknown_permission"},
		{"action-without-tier", func(value *Request) { value.Permission = ActionRequest }, InvalidInput, "action_tier_required"},
		{"read-with-tier", func(value *Request) { value.ActionTier = T1 }, InvalidInput, "unexpected_action_tier"},
		{"approval-at-t1", func(value *Request) { value.Permission = ApprovalDecide; value.ActionTier = T1 }, InvalidInput, "approval_tier"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validRequest(CaseRead, "")
			test.mutate(&request)
			decision, err := EvaluateRBAC(validActor(Analyst), request)
			if Code(err) != test.code || decision.ReasonCode != test.reason {
				t.Fatalf("decision = %+v, err = %v", decision, err)
			}
		})
	}
}

func TestDecisionIsDeterministicAndRedacted(t *testing.T) {
	actor := validActor(Analyst)
	request := validRequest(ActionRequest, T3)
	first, err := EvaluateRBAC(actor, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := EvaluateRBAC(actor, request)
	if err != nil || first != second {
		t.Fatalf("decision replay differs: first=%+v second=%+v err=%v", first, second, err)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), actor.PublicKey) || strings.Contains(string(encoded), actor.Name) {
		t.Fatalf("decision exposes actor credential metadata: %s", encoded)
	}
	request.PayloadDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	changed, err := EvaluateRBAC(actor, request)
	if err != nil || changed.DecisionDigest == first.DecisionDigest {
		t.Fatalf("payload tamper not bound: first=%+v changed=%+v err=%v", first, changed, err)
	}
}

func validActor(roles ...Role) Actor {
	return Actor{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		ID: testActorID, OrganizationID: testOrganizationID, Name: "analyst.one",
		Roles: roles, Grants: []ScopeGrant{{TenantID: testTenantID, CaseIDs: []string{testCaseID}}},
		PublicKey: testPublicKey, Revision: 1, Active: true,
	}
}

func validRequest(permission Permission, tier ActionTier) Request {
	return Request{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion,
		RequestID: testRequestID, IdempotencyKey: "request-one", PayloadDigest: testDigest, Channel: API,
		Context:    Context{OrganizationID: testOrganizationID, TenantID: testTenantID, CaseID: testCaseID, ActorID: testActorID},
		Permission: permission, ActionTier: tier,
	}
}
