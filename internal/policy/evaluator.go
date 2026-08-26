// Package policy owns authorization decisions and policy-domain behavior.
// It is independent of transports and concrete adapters.
package policy

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
)

const (
	SchemaVersion   = "coh.policy-decision/v1"
	ContractVersion = "1.0.0"
)

type Phase string

const (
	IntentCreated Phase = "intent_created"
	PreDispatch   Phase = "pre_dispatch"
)

// ActorAuthority is a fresh identity snapshot supplied by trusted broker
// composition. Roles and permissions are sorted, unique, non-secret tokens.
type ActorAuthority struct {
	ActorID        string
	OrganizationID string
	TenantID       string
	CaseID         string
	Revision       uint64
	Active         bool
	Roles          []string
	Permissions    []string
}

// RuntimeAuthority contains current capability facts that cannot be asserted
// by a workflow or by the signed policy itself.
type RuntimeAuthority struct {
	DataRoute             string
	ValidatorState        string
	ToolRegistered        bool
	TargetsAuthorized     bool
	TenantAuthorized      bool
	DataRouteAuthorized   bool
	CapabilityFieldsKnown bool
	EmergencyStopActive   bool
}

// BundleAuthority is the current out-of-band policy signing authority. The
// public key is raw Ed25519 material and is never copied into decisions.
type BundleAuthority struct {
	KeyID       string
	KeyRevision uint64
	Algorithm   string
	Active      bool
	PublicKey   ed25519.PublicKey
}

// Request binds one evaluation to a verified canonical action and fresh
// identity/capability authority. The engine supplies broker-owned time.
type Request struct {
	EvaluationID string
	Phase        Phase
	Manifest     actionmanifest.VerifiedEnvelope
	Actor        ActorAuthority
	Runtime      RuntimeAuthority
}

// Decision is safe audit and approval input. It contains no policy source,
// public key, credential, raw target, raw argument, or model-controlled text.
type Decision struct {
	SchemaVersion       string `json:"schema_version"`
	ContractVersion     string `json:"contract_version"`
	EvaluationID        string `json:"evaluation_id"`
	DecisionDigest      string `json:"decision_digest"`
	InputDigest         string `json:"input_digest"`
	Outcome             string `json:"outcome"`
	ReasonCode          string `json:"reason_code"`
	Phase               Phase  `json:"phase"`
	ManifestDigest      string `json:"manifest_digest"`
	PolicyDigest        string `json:"policy_digest"`
	PolicyRevision      uint64 `json:"policy_revision"`
	BundleID            string `json:"bundle_id"`
	SignerKeyID         string `json:"signer_key_id"`
	SignerKeyRevision   uint64 `json:"signer_key_revision"`
	ActorID             string `json:"actor_id"`
	ActorRevision       uint64 `json:"actor_revision"`
	ApprovalRequired    bool   `json:"approval_required"`
	EvaluatedAt         string `json:"evaluated_at"`
	AuditOrganizationID string `json:"-"`
	AuditTenantID       string `json:"-"`
	AuditCaseID         string `json:"-"`
}

// Activation is the safe result of verifying, compiling, and atomically
// publishing one signed OPA snapshot bundle.
type Activation struct {
	BundleID          string `json:"bundle_id"`
	PolicyDigest      string `json:"policy_digest"`
	PolicyRevision    uint64 `json:"policy_revision"`
	SignerKeyID       string `json:"signer_key_id"`
	SignerKeyRevision uint64 `json:"signer_key_revision"`
	ActivatedAt       string `json:"activated_at"`
}

type AuditEvent struct {
	Kind           string      `json:"kind"`
	Activation     *Activation `json:"activation,omitempty"`
	Decision       *Decision   `json:"decision,omitempty"`
	EventID        string      `json:"event_id"`
	OrganizationID string      `json:"organization_id"`
	TenantID       string      `json:"tenant_id"`
	CaseID         string      `json:"case_id,omitempty"`
	ActorID        string      `json:"actor_id,omitempty"`
	ActorRevision  uint64      `json:"actor_revision,omitempty"`
	OccurredAt     string      `json:"occurred_at"`
}

type AuditSink interface {
	AppendPolicyEvent(context.Context, AuditEvent) error
}

type Clock interface {
	Now() time.Time
}

// Evaluator is the narrow policy port consumed only by the broker boundary.
// Workflows and transports cannot import or receive it.
type Evaluator interface {
	Evaluate(context.Context, Request, BundleAuthority) (Decision, error)
}
