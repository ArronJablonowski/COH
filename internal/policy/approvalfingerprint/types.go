// Package approvalfingerprint binds approval identity to exact verified action
// and policy-decision bytes.
package approvalfingerprint

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/policy"
)

const (
	SchemaVersion   = "coh.approval-fingerprint/v1"
	ContractVersion = "1.0.0"
	HashDomain      = "COH-APPROVAL-FINGERPRINT-V1\x00"
	auditTimeout    = 5 * time.Second
)

type Fingerprint struct {
	SchemaVersion        string  `json:"schema_version"`
	ContractVersion      string  `json:"contract_version"`
	FingerprintDigest    string  `json:"fingerprint_digest"`
	ManifestDigest       string  `json:"manifest_digest"`
	PolicyDecisionDigest string  `json:"policy_decision_digest"`
	OrganizationID       string  `json:"organization_id"`
	TenantID             string  `json:"tenant_id"`
	CaseID               string  `json:"case_id"`
	RequestorActorID     string  `json:"requestor_actor_id"`
	ActionOwnerActorID   string  `json:"action_owner_actor_id"`
	PolicyDigest         string  `json:"policy_digest"`
	PolicyRevision       uint64  `json:"policy_revision"`
	ROEDigest            *string `json:"roe_digest"`
	ValidFrom            string  `json:"valid_from"`
	ValidUntil           string  `json:"valid_until"`
	MaximumUseCount      uint32  `json:"maximum_use_count"`
}

type AuditEvent struct {
	Operation            string `json:"operation"`
	Outcome              string `json:"outcome"`
	ReasonCode           string `json:"reason_code"`
	FingerprintDigest    string `json:"fingerprint_digest,omitempty"`
	ManifestDigest       string `json:"manifest_digest,omitempty"`
	PolicyDecisionDigest string `json:"policy_decision_digest,omitempty"`
	OccurredAt           string `json:"occurred_at"`
	EventID              string `json:"event_id"`
	OrganizationID       string `json:"organization_id,omitempty"`
	TenantID             string `json:"tenant_id,omitempty"`
	CaseID               string `json:"case_id,omitempty"`
	ActorID              string `json:"actor_id,omitempty"`
	ActorRevision        uint64 `json:"actor_revision,omitempty"`
}

type AuditSink interface {
	AppendApprovalFingerprintEvent(context.Context, AuditEvent) error
}

type Engine struct {
	audit AuditSink
	clock policy.Clock
}

func New(audit AuditSink, clock policy.Clock) (*Engine, error) {
	if audit == nil || clock == nil {
		return nil, policy.NewError(policy.InvalidInput, "fingerprint_dependencies")
	}
	return &Engine{audit: audit, clock: clock}, nil
}
