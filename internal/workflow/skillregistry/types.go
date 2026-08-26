// Package skillregistry admits signed, independently reviewed skill packages
// and exposes only immutable references from the currently promoted version.
package skillregistry

import (
	"context"
	"crypto/ed25519"
	"time"
)

const (
	ManifestSchemaVersion = "coh.skill-manifest/v1"
	EnvelopeSchemaVersion = "coh.signed-skill-manifest/v1"
	CommandSchemaVersion  = "coh.skill-change/v1"
	SignedCommandVersion  = "coh.signed-skill-change/v1"
	StateSchemaVersion    = "coh.skill-registry-state/v1"
	PolicySchemaVersion   = "coh.skill-policy-decision/v1"
	ResolveSchemaVersion  = "coh.skill-resolution-request/v1"
	AccessSchemaVersion   = "coh.skill-access-decision/v1"
	ContractVersion       = "1.0.0"
	SignatureAlgorithm    = "ed25519"
	ManifestDomain        = "COH-SIGNED-SKILL-MANIFEST-V1\x00"
	ReviewDomain          = "COH-REVIEWED-SKILL-MANIFEST-V1\x00"
	CommandDomain         = "COH-SIGNED-SKILL-CHANGE-V1\x00"
	MaximumInputBytes     = 1 << 20
	MaximumValidity       = 366 * 24 * time.Hour
	MaximumResources      = 128
	MaximumPermissions    = 64
)

type Resource struct {
	Name           string `json:"name"`
	Digest         string `json:"digest"`
	MediaType      string `json:"media_type"`
	Classification string `json:"classification"`
	Length         int64  `json:"length"`
}

type Manifest struct {
	SchemaVersion          string     `json:"schema_version"`
	ContractVersion        string     `json:"contract_version"`
	ManifestID             string     `json:"manifest_id"`
	SkillName              string     `json:"skill_name"`
	SkillVersion           string     `json:"skill_version"`
	OwnerActorID           string     `json:"owner_actor_id"`
	PublisherActorID       string     `json:"publisher_actor_id"`
	ContentDigest          string     `json:"content_digest"`
	Resources              []Resource `json:"resources"`
	Permissions            []string   `json:"permissions"`
	TestSuiteDigest        string     `json:"test_suite_digest"`
	TestEvidenceDigest     string     `json:"test_evidence_digest"`
	ThreatModelDigest      string     `json:"threat_model_digest"`
	PreviousManifestDigest string     `json:"previous_manifest_digest"`
	ReviewID               string     `json:"review_id"`
	ReviewRevision         uint64     `json:"review_revision"`
	ReviewDecision         string     `json:"review_decision"`
	ReviewerActorIDs       []string   `json:"reviewer_actor_ids"`
	ReviewEvidenceDigest   string     `json:"review_evidence_digest"`
	ReviewedAt             time.Time  `json:"reviewed_at"`
	ValidFrom              time.Time  `json:"valid_from"`
	ValidUntil             time.Time  `json:"valid_until"`
}

type DetachedSignature struct {
	ActorID            string `json:"actor_id"`
	KeyID              string `json:"key_id"`
	KeyRevision        uint64 `json:"key_revision"`
	ApprovalRevision   uint64 `json:"approval_revision"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Signature          string `json:"signature"`
}

type Envelope struct {
	SchemaVersion      string              `json:"schema_version"`
	ContractVersion    string              `json:"contract_version"`
	Manifest           Manifest            `json:"manifest"`
	ManifestDigest     string              `json:"manifest_digest"`
	PublisherSignature DetachedSignature   `json:"publisher_signature"`
	ReviewSignatures   []DetachedSignature `json:"review_signatures"`
}

type ChangeAction string

const (
	Promote  ChangeAction = "promote"
	Rollback ChangeAction = "rollback"
	Revoke   ChangeAction = "revoke"
)

type ChangeCommand struct {
	SchemaVersion         string       `json:"schema_version"`
	ContractVersion       string       `json:"contract_version"`
	CommandID             string       `json:"command_id"`
	Action                ChangeAction `json:"action"`
	OrganizationID        string       `json:"organization_id"`
	TenantID              string       `json:"tenant_id"`
	CaseID                string       `json:"case_id"`
	TaskID                string       `json:"task_id"`
	ActorID               string       `json:"actor_id"`
	SkillName             string       `json:"skill_name"`
	TargetManifestDigest  string       `json:"target_manifest_digest"`
	ExpectedCurrentDigest string       `json:"expected_current_digest"`
	ExpectedRevision      uint64       `json:"expected_revision"`
	ReasonDigest          string       `json:"reason_digest"`
	CreatedAt             time.Time    `json:"created_at"`
	Deadline              time.Time    `json:"deadline"`
}

type SignedChange struct {
	SchemaVersion   string            `json:"schema_version"`
	ContractVersion string            `json:"contract_version"`
	Command         ChangeCommand     `json:"command"`
	CommandDigest   string            `json:"command_digest"`
	Signature       DetachedSignature `json:"signature"`
}

type Status string

const (
	Promoted Status = "promoted"
	Revoked  Status = "revoked"
)

type State struct {
	SchemaVersion            string       `json:"schema_version"`
	ContractVersion          string       `json:"contract_version"`
	OrganizationID           string       `json:"organization_id"`
	TenantID                 string       `json:"tenant_id"`
	SkillName                string       `json:"skill_name"`
	Status                   Status       `json:"status"`
	CurrentManifestDigest    string       `json:"current_manifest_digest"`
	PreviousManifestDigest   string       `json:"previous_manifest_digest"`
	LastAction               ChangeAction `json:"last_action"`
	LastCommandDigest        string       `json:"last_command_digest"`
	IdempotencyDigest        string       `json:"idempotency_digest"`
	PolicyDecisionDigest     string       `json:"policy_decision_digest"`
	ReviewEvidenceDigest     string       `json:"review_evidence_digest"`
	AuditReceiptDigest       string       `json:"audit_receipt_digest"`
	PreviousProvenanceDigest string       `json:"previous_provenance_digest"`
	ProvenanceDigest         string       `json:"provenance_digest"`
	CreatedAt                time.Time    `json:"created_at"`
	UpdatedAt                time.Time    `json:"updated_at"`
	Revision                 uint64       `json:"revision"`
}

type Version struct {
	OrganizationID string
	TenantID       string
	ManifestID     string
	ManifestDigest string
	Envelope       []byte
	CreatedAt      time.Time
}

// SigningAuthority is a current, independently resolved authority snapshot.
// A signed document cannot grant authority to its own signers.
type SigningAuthority struct {
	ActorID          string
	KeyID            string
	KeyRevision      uint64
	ApprovalRevision uint64
	Active           bool
	Approved         bool
	PublicKey        ed25519.PublicKey
}

type ReviewAuthority struct {
	ReviewID       string
	Revision       uint64
	Decision       string
	ReviewerIDs    []string
	EvidenceDigest string
	Active         bool
}

type PolicyDecision struct {
	SchemaVersion   string       `json:"schema_version"`
	ContractVersion string       `json:"contract_version"`
	DecisionID      string       `json:"decision_id"`
	DecisionDigest  string       `json:"decision_digest"`
	PolicyDigest    string       `json:"policy_digest"`
	OrganizationID  string       `json:"organization_id"`
	TenantID        string       `json:"tenant_id"`
	CaseID          string       `json:"case_id"`
	TaskID          string       `json:"task_id"`
	ActorID         string       `json:"actor_id"`
	Action          ChangeAction `json:"action"`
	SkillName       string       `json:"skill_name"`
	ManifestDigest  string       `json:"manifest_digest"`
	Outcome         string       `json:"outcome"`
	Revision        uint64       `json:"revision"`
	IssuedAt        time.Time    `json:"issued_at"`
	ExpiresAt       time.Time    `json:"expires_at"`
}

type ChangeRequest struct {
	IdempotencyKey string
	SignedCommand  []byte
	SignedManifest []byte
	Signer         SigningAuthority
	Publisher      SigningAuthority
	Reviewers      []SigningAuthority
	Review         ReviewAuthority
	Policy         PolicyDecision
}

type ResolveRequest struct {
	SchemaVersion          string    `json:"schema_version"`
	ContractVersion        string    `json:"contract_version"`
	RequestID              string    `json:"request_id"`
	OrganizationID         string    `json:"organization_id"`
	TenantID               string    `json:"tenant_id"`
	CaseID                 string    `json:"case_id"`
	TaskID                 string    `json:"task_id"`
	ActorID                string    `json:"actor_id"`
	SkillName              string    `json:"skill_name"`
	ExpectedManifestDigest string    `json:"expected_manifest_digest"`
	RequiredPermission     string    `json:"required_permission"`
	PolicyDigest           string    `json:"policy_digest"`
	Deadline               time.Time `json:"deadline"`
}

type AccessDecision struct {
	SchemaVersion   string    `json:"schema_version"`
	ContractVersion string    `json:"contract_version"`
	DecisionID      string    `json:"decision_id"`
	DecisionDigest  string    `json:"decision_digest"`
	PolicyDigest    string    `json:"policy_digest"`
	OrganizationID  string    `json:"organization_id"`
	TenantID        string    `json:"tenant_id"`
	CaseID          string    `json:"case_id"`
	TaskID          string    `json:"task_id"`
	ActorID         string    `json:"actor_id"`
	SkillName       string    `json:"skill_name"`
	ManifestDigest  string    `json:"manifest_digest"`
	Permission      string    `json:"permission"`
	Outcome         string    `json:"outcome"`
	Revision        uint64    `json:"revision"`
	IssuedAt        time.Time `json:"issued_at"`
	ExpiresAt       time.Time `json:"expires_at"`
}

type ResolutionAuthority struct {
	Publisher SigningAuthority
	Reviewers []SigningAuthority
	Review    ReviewAuthority
}

type ResolvedSkill struct {
	SkillName        string
	SkillVersion     string
	ManifestDigest   string
	ContentDigest    string
	Resources        []Resource
	Permissions      []string
	OwnerActorID     string
	ReviewID         string
	ReviewRevision   uint64
	ProvenanceDigest string
}

type AuditAction string

const Resolve AuditAction = "resolve"

type AuditEvent struct {
	EventID        string
	OrganizationID string
	TenantID       string
	CaseID         string
	TaskID         string
	ActorID        string
	Action         AuditAction
	SkillName      string
	ManifestDigest string
	CommandDigest  string
	PolicyDigest   string
	ReviewDigest   string
	Outcome        string
	OccurredAt     time.Time
}

type AuditReceipt struct {
	EventID       string
	EventDigest   string
	ReceiptDigest string
}

type Store interface {
	LoadState(context.Context, string, string, string) (State, bool, error)
	LoadVersion(context.Context, string, string, string) (Version, bool, error)
	Commit(context.Context, string, *State, State, *Version) (State, bool, error)
}

type Auditor interface {
	Append(context.Context, AuditEvent) (AuditReceipt, error)
}

type Clock interface{ Now() time.Time }

type Registry interface {
	Change(context.Context, ChangeRequest) (State, error)
	Resolve(context.Context, ResolveRequest, AccessDecision, ResolutionAuthority) (ResolvedSkill, error)
}
