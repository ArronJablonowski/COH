package skillregistry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type manifestWire struct {
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
	ReviewedAt             string     `json:"reviewed_at"`
	ValidFrom              string     `json:"valid_from"`
	ValidUntil             string     `json:"valid_until"`
}

type commandWire struct {
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
	CreatedAt             string       `json:"created_at"`
	Deadline              string       `json:"deadline"`
}

type envelopeWire struct {
	SchemaVersion      string              `json:"schema_version"`
	ContractVersion    string              `json:"contract_version"`
	Manifest           manifestWire        `json:"manifest"`
	ManifestDigest     string              `json:"manifest_digest"`
	PublisherSignature DetachedSignature   `json:"publisher_signature"`
	ReviewSignatures   []DetachedSignature `json:"review_signatures"`
}

type signedChangeWire struct {
	SchemaVersion   string            `json:"schema_version"`
	ContractVersion string            `json:"contract_version"`
	Command         commandWire       `json:"command"`
	CommandDigest   string            `json:"command_digest"`
	Signature       DetachedSignature `json:"signature"`
}

type policyWire struct {
	SchemaVersion   string       `json:"schema_version"`
	ContractVersion string       `json:"contract_version"`
	DecisionID      string       `json:"decision_id"`
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
	IssuedAt        string       `json:"issued_at"`
	ExpiresAt       string       `json:"expires_at"`
}

type accessWire struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	DecisionID      string `json:"decision_id"`
	PolicyDigest    string `json:"policy_digest"`
	OrganizationID  string `json:"organization_id"`
	TenantID        string `json:"tenant_id"`
	CaseID          string `json:"case_id"`
	TaskID          string `json:"task_id"`
	ActorID         string `json:"actor_id"`
	SkillName       string `json:"skill_name"`
	ManifestDigest  string `json:"manifest_digest"`
	Permission      string `json:"permission"`
	Outcome         string `json:"outcome"`
	Revision        uint64 `json:"revision"`
	IssuedAt        string `json:"issued_at"`
	ExpiresAt       string `json:"expires_at"`
}

type stateProvenanceWire struct {
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
	CreatedAt                string       `json:"created_at"`
	UpdatedAt                string       `json:"updated_at"`
	Revision                 uint64       `json:"revision"`
}

type auditWire struct {
	EventID        string      `json:"event_id"`
	OrganizationID string      `json:"organization_id"`
	TenantID       string      `json:"tenant_id"`
	CaseID         string      `json:"case_id"`
	TaskID         string      `json:"task_id"`
	ActorID        string      `json:"actor_id"`
	Action         AuditAction `json:"action"`
	SkillName      string      `json:"skill_name"`
	ManifestDigest string      `json:"manifest_digest"`
	CommandDigest  string      `json:"command_digest"`
	PolicyDigest   string      `json:"policy_digest"`
	ReviewDigest   string      `json:"review_digest"`
	Outcome        string      `json:"outcome"`
	OccurredAt     string      `json:"occurred_at"`
}

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(InvalidInput, "canonical_encoding_failed", false, err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(InvalidInput, "canonical_encoding_failed", false, err)
	}
	return canonical, nil
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func canonicalManifest(value Manifest) ([]byte, string, error) {
	if err := validateManifest(value); err != nil {
		return nil, "", err
	}
	canonical, err := canonicalValue(manifestToWire(value))
	if err != nil {
		return nil, "", err
	}
	return canonical, digestBytes(canonical), nil
}

// CanonicalManifest returns the exact signing bytes and their SHA-256 digest.
func CanonicalManifest(value Manifest) ([]byte, string, error) {
	return canonicalManifest(cloneManifest(value))
}

func canonicalCommand(value ChangeCommand) ([]byte, string, error) {
	if err := validateCommand(value); err != nil {
		return nil, "", err
	}
	canonical, err := canonicalValue(commandToWire(value))
	if err != nil {
		return nil, "", err
	}
	return canonical, digestBytes(canonical), nil
}

// CanonicalChangeCommand returns the exact owner-signing bytes and digest.
func CanonicalChangeCommand(value ChangeCommand) ([]byte, string, error) {
	return canonicalCommand(value)
}

func canonicalEnvelope(value Envelope) ([]byte, error) {
	return canonicalValue(envelopeWire{
		SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		Manifest: manifestToWire(value.Manifest), ManifestDigest: value.ManifestDigest,
		PublisherSignature: value.PublisherSignature,
		ReviewSignatures:   append([]DetachedSignature(nil), value.ReviewSignatures...),
	})
}

// CanonicalEnvelope returns the exact immutable envelope storage bytes.
func CanonicalEnvelope(value Envelope) ([]byte, error) {
	return canonicalEnvelope(value)
}

func canonicalSignedChange(value SignedChange) ([]byte, error) {
	return canonicalValue(signedChangeWire{
		SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		Command: commandToWire(value.Command), CommandDigest: value.CommandDigest, Signature: value.Signature,
	})
}

// CanonicalSignedChange returns strict transport bytes for a signed command.
func CanonicalSignedChange(value SignedChange) ([]byte, error) {
	return canonicalSignedChange(value)
}

func manifestToWire(value Manifest) manifestWire {
	return manifestWire{
		SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		ManifestID: value.ManifestID, SkillName: value.SkillName, SkillVersion: value.SkillVersion,
		OwnerActorID: value.OwnerActorID, PublisherActorID: value.PublisherActorID,
		ContentDigest: value.ContentDigest, Resources: append([]Resource(nil), value.Resources...),
		Permissions: append([]string(nil), value.Permissions...), TestSuiteDigest: value.TestSuiteDigest,
		TestEvidenceDigest: value.TestEvidenceDigest, ThreatModelDigest: value.ThreatModelDigest,
		PreviousManifestDigest: value.PreviousManifestDigest, ReviewID: value.ReviewID,
		ReviewRevision: value.ReviewRevision, ReviewDecision: value.ReviewDecision,
		ReviewerActorIDs:     append([]string(nil), value.ReviewerActorIDs...),
		ReviewEvidenceDigest: value.ReviewEvidenceDigest, ReviewedAt: formatTime(value.ReviewedAt),
		ValidFrom: formatTime(value.ValidFrom), ValidUntil: formatTime(value.ValidUntil),
	}
}

func commandToWire(value ChangeCommand) commandWire {
	return commandWire{
		SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		CommandID: value.CommandID, Action: value.Action, OrganizationID: value.OrganizationID,
		TenantID: value.TenantID, CaseID: value.CaseID, TaskID: value.TaskID, ActorID: value.ActorID,
		SkillName: value.SkillName, TargetManifestDigest: value.TargetManifestDigest,
		ExpectedCurrentDigest: value.ExpectedCurrentDigest, ExpectedRevision: value.ExpectedRevision,
		ReasonDigest: value.ReasonDigest, CreatedAt: formatTime(value.CreatedAt), Deadline: formatTime(value.Deadline),
	}
}

func policyDecisionDigest(value PolicyDecision) (string, error) {
	wire := policyWire{
		SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		DecisionID: value.DecisionID, PolicyDigest: value.PolicyDigest,
		OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID,
		TaskID: value.TaskID, ActorID: value.ActorID, Action: value.Action, SkillName: value.SkillName,
		ManifestDigest: value.ManifestDigest, Outcome: value.Outcome, Revision: value.Revision,
		IssuedAt: formatTime(value.IssuedAt), ExpiresAt: formatTime(value.ExpiresAt),
	}
	canonical, err := canonicalValue(wire)
	if err != nil {
		return "", err
	}
	return digestBytes(append([]byte("COH-SKILL-POLICY-DECISION-V1\x00"), canonical...)), nil
}

// DigestPolicyDecision binds every policy field except its self-digest.
func DigestPolicyDecision(value PolicyDecision) (string, error) {
	return policyDecisionDigest(value)
}

func accessDecisionDigest(value AccessDecision) (string, error) {
	wire := accessWire{
		SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		DecisionID: value.DecisionID, PolicyDigest: value.PolicyDigest,
		OrganizationID: value.OrganizationID, TenantID: value.TenantID, CaseID: value.CaseID,
		TaskID: value.TaskID, ActorID: value.ActorID, SkillName: value.SkillName,
		ManifestDigest: value.ManifestDigest, Permission: value.Permission, Outcome: value.Outcome,
		Revision: value.Revision, IssuedAt: formatTime(value.IssuedAt), ExpiresAt: formatTime(value.ExpiresAt),
	}
	canonical, err := canonicalValue(wire)
	if err != nil {
		return "", err
	}
	return digestBytes(append([]byte("COH-SKILL-ACCESS-DECISION-V1\x00"), canonical...)), nil
}

// DigestAccessDecision binds every access field except its self-digest.
func DigestAccessDecision(value AccessDecision) (string, error) {
	return accessDecisionDigest(value)
}

func provenanceDigest(value State) (string, error) {
	wire := stateProvenanceWire{
		SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		OrganizationID: value.OrganizationID, TenantID: value.TenantID, SkillName: value.SkillName,
		Status: value.Status, CurrentManifestDigest: value.CurrentManifestDigest,
		PreviousManifestDigest: value.PreviousManifestDigest, LastAction: value.LastAction,
		LastCommandDigest: value.LastCommandDigest, IdempotencyDigest: value.IdempotencyDigest,
		PolicyDecisionDigest: value.PolicyDecisionDigest, ReviewEvidenceDigest: value.ReviewEvidenceDigest,
		AuditReceiptDigest: value.AuditReceiptDigest, PreviousProvenanceDigest: value.PreviousProvenanceDigest,
		CreatedAt: formatTime(value.CreatedAt), UpdatedAt: formatTime(value.UpdatedAt), Revision: value.Revision,
	}
	canonical, err := canonicalValue(wire)
	if err != nil {
		return "", err
	}
	return digestBytes(append([]byte("COH-SKILL-REGISTRY-PROVENANCE-V1\x00"), canonical...)), nil
}

func auditEventDigest(value AuditEvent) (string, error) {
	if err := validateAuditEvent(value); err != nil {
		return "", err
	}
	wire := auditWire{
		EventID: value.EventID, OrganizationID: value.OrganizationID, TenantID: value.TenantID,
		CaseID: value.CaseID, TaskID: value.TaskID, ActorID: value.ActorID, Action: value.Action,
		SkillName: value.SkillName, ManifestDigest: value.ManifestDigest, CommandDigest: value.CommandDigest,
		PolicyDigest: value.PolicyDigest, ReviewDigest: value.ReviewDigest, Outcome: value.Outcome,
		OccurredAt: formatTime(value.OccurredAt),
	}
	canonical, err := canonicalValue(wire)
	if err != nil {
		return "", err
	}
	return digestBytes(append([]byte("COH-SKILL-REGISTRY-AUDIT-V1\x00"), canonical...)), nil
}

// DigestAuditEvent returns the exact digest an Auditor receipt must bind.
func DigestAuditEvent(value AuditEvent) (string, error) {
	return auditEventDigest(value)
}

func idempotencyDigest(value string) string {
	return digestBytes(append([]byte("COH-SKILL-REGISTRY-IDEMPOTENCY-V1\x00"), []byte(value)...))
}

func formatTime(value time.Time) string { return value.UTC().Format(timestampLayout) }

func cloneManifest(value Manifest) Manifest {
	cloned := value
	cloned.Resources = append([]Resource(nil), value.Resources...)
	cloned.Permissions = append([]string(nil), value.Permissions...)
	cloned.ReviewerActorIDs = append([]string(nil), value.ReviewerActorIDs...)
	return cloned
}

func cloneState(value State) State { return value }

func cloneVersion(value Version) Version {
	value.Envelope = append([]byte(nil), value.Envelope...)
	return value
}

func cloneResolved(value ResolvedSkill) ResolvedSkill {
	value.Resources = append([]Resource(nil), value.Resources...)
	value.Permissions = append([]string(nil), value.Permissions...)
	return value
}
