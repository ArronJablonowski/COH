package credentiallease

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

type Decision struct {
	SchemaVersion               string    `json:"schema_version"`
	ContractVersion             string    `json:"contract_version"`
	Event                       string    `json:"event"`
	Outcome                     string    `json:"outcome"`
	ReasonCode                  string    `json:"reason_code"`
	LeaseID                     string    `json:"lease_id,omitempty"`
	RequestID                   string    `json:"request_id"`
	OrganizationID              string    `json:"organization_id"`
	TenantID                    string    `json:"tenant_id"`
	CaseID                      string    `json:"case_id"`
	ActorID                     string    `json:"actor_id"`
	ActorRevision               uint64    `json:"actor_revision"`
	TaskID                      string    `json:"task_id"`
	ActionDigest                string    `json:"action_digest"`
	TargetScopeDigest           string    `json:"target_scope_digest"`
	Operation                   string    `json:"operation"`
	AudienceKind                string    `json:"audience_kind"`
	AudienceID                  string    `json:"audience_id"`
	TransportIdentityDigest     string    `json:"transport_identity_digest"`
	AudienceRevision            uint64    `json:"audience_revision"`
	CredentialClass             string    `json:"credential_class"`
	CredentialReferenceDigest   string    `json:"credential_reference_digest,omitempty"`
	AuthorizationDecisionDigest string    `json:"authorization_decision_digest"`
	PolicyDecisionDigest        string    `json:"policy_decision_digest"`
	ApprovalDecisionDigest      string    `json:"approval_decision_digest,omitempty"`
	SecretDecisionDigest        string    `json:"secret_decision_digest,omitempty"`
	IssuedAt                    time.Time `json:"issued_at,omitempty"`
	ExpiresAt                   time.Time `json:"expires_at,omitempty"`
	OccurredAt                  time.Time `json:"occurred_at"`
	DecisionDigest              string    `json:"decision_digest"`
}

func NewDispatchDecision(bound IssuanceRequest, authority IssuanceAuthority, leaseID, outcome, reason, referenceDigest, secretDecisionDigest string, issuedAt, expiresAt, occurredAt time.Time) Decision {
	decision := NewIssuanceDecision(bound, authority, leaseID, outcome, reason, referenceDigest, issuedAt, expiresAt)
	decision.Event = "lease_dispatch"
	decision.OccurredAt = occurredAt
	decision.SecretDecisionDigest = secretDecisionDigest
	decision.DecisionDigest = decisionDigest(decision)
	return decision
}

func NewRevocationDecision(bound IssuanceRequest, authority IssuanceAuthority, leaseID, outcome, reason, referenceDigest string, issuedAt, expiresAt, occurredAt time.Time) Decision {
	decision := NewIssuanceDecision(bound, authority, leaseID, outcome, reason, referenceDigest, issuedAt, expiresAt)
	decision.Event = "lease_revocation"
	decision.OccurredAt = occurredAt
	decision.DecisionDigest = decisionDigest(decision)
	return decision
}

func NewIssuanceDecision(request IssuanceRequest, authority IssuanceAuthority, leaseID, outcome, reason, referenceDigest string, issuedAt, expiresAt time.Time) Decision {
	decision := Decision{
		SchemaVersion: SchemaVersion, ContractVersion: ContractVersion, Event: "lease_issuance",
		Outcome: outcome, ReasonCode: reason, LeaseID: leaseID, RequestID: request.RequestID,
		OrganizationID: request.Context.OrganizationID, TenantID: request.Context.TenantID,
		CaseID: request.Context.CaseID, ActorID: request.Context.ActorID, ActorRevision: authority.ActorRevision,
		TaskID: request.TaskID, ActionDigest: request.ActionDigest, TargetScopeDigest: targetScopeDigest(request.TargetDigests),
		Operation: request.Operation, AudienceKind: request.Audience.Kind, AudienceID: request.Audience.ID,
		TransportIdentityDigest: request.Audience.TransportIdentityDigest, AudienceRevision: authority.Audience.Revision,
		CredentialClass: request.CredentialClass, CredentialReferenceDigest: referenceDigest,
		AuthorizationDecisionDigest: authority.AuthorizationDecisionDigest, PolicyDecisionDigest: authority.PolicyDecisionDigest,
		ApprovalDecisionDigest: authority.ApprovalDecisionDigest, IssuedAt: issuedAt, ExpiresAt: expiresAt, OccurredAt: issuedAt,
	}
	decision.DecisionDigest = decisionDigest(decision)
	return decision
}

func targetScopeDigest(targets []string) string {
	encoded, _ := json.Marshal(targets)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decisionDigest(decision Decision) string {
	decision.DecisionDigest = ""
	encoded, _ := json.Marshal(decision)
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}
