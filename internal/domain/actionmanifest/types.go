// Package actionmanifest defines the canonical signed action identity consumed
// by policy, approval, audit, lease, and broker boundaries.
package actionmanifest

import (
	"crypto/ed25519"
	"time"
)

const (
	ManifestSchemaVersion = "coh.action-manifest/v1"
	EnvelopeSchemaVersion = "coh.signed-action/v1"
	ContractVersion       = "1.0.0"
	SignatureDomain       = "COH-SIGNED-ACTION-V1\x00"
	MaximumInputBytes     = 64 << 10
	MaximumValidity       = 24 * time.Hour
)

type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type Manifest struct {
	SchemaVersion             string   `json:"schema_version"`
	ContractVersion           string   `json:"contract_version"`
	ManifestID                string   `json:"manifest_id"`
	WorkflowTaskID            string   `json:"workflow_task_id"`
	OrganizationID            string   `json:"organization_id"`
	TenantID                  string   `json:"tenant_id"`
	CaseID                    string   `json:"case_id"`
	RequestorActorID          string   `json:"requestor_actor_id"`
	ActionOwnerActorID        string   `json:"action_owner_actor_id"`
	ActionType                string   `json:"action_type"`
	Operation                 string   `json:"operation"`
	ActionTier                string   `json:"action_tier"`
	TargetDigests             []string `json:"target_digests"`
	ExclusionDigests          []string `json:"exclusion_digests"`
	ArgumentsDigest           string   `json:"arguments_digest"`
	Tool                      Tool     `json:"tool"`
	PayloadDigest             string   `json:"payload_digest"`
	PolicyDigest              string   `json:"policy_digest"`
	PolicyRevision            uint64   `json:"policy_revision"`
	ROEDigest                 *string  `json:"roe_digest"`
	CredentialClass           string   `json:"credential_class"`
	CredentialReferenceDigest *string  `json:"credential_reference_digest"`
	ExecutionZone             string   `json:"execution_zone"`
	IsolationProfileDigest    string   `json:"isolation_profile_digest"`
	ValidFrom                 string   `json:"valid_from"`
	ValidUntil                string   `json:"valid_until"`
	ManifestNonce             string   `json:"manifest_nonce"`
	MaximumUseCount           uint32   `json:"maximum_use_count"`
	RollbackDigest            *string  `json:"rollback_digest"`
	SafetyWatchActorID        *string  `json:"safety_watch_actor_id"`
}

type Envelope struct {
	SchemaVersion      string   `json:"schema_version"`
	ContractVersion    string   `json:"contract_version"`
	Manifest           Manifest `json:"manifest"`
	ManifestDigest     string   `json:"manifest_digest"`
	SignerActorID      string   `json:"signer_actor_id"`
	SignerKeyRevision  uint64   `json:"signer_key_revision"`
	KeyID              string   `json:"key_id"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	Signature          string   `json:"signature"`
}

type SignerAuthority struct {
	ActorID     string
	KeyID       string
	KeyRevision uint64
	Active      bool
	PublicKey   ed25519.PublicKey
}

type ValidatedManifest struct {
	Digest   string
	manifest Manifest
	bytes    []byte
}

func (validated ValidatedManifest) Value() Manifest { return cloneManifest(validated.manifest) }

func (validated ValidatedManifest) CanonicalBytes() []byte {
	return append([]byte(nil), validated.bytes...)
}

type VerifiedEnvelope struct {
	ManifestDigest    string
	SignerActorID     string
	SignerKeyRevision uint64
	KeyID             string
	manifest          Manifest
	manifestBytes     []byte
	envelopeBytes     []byte
}

func (verified VerifiedEnvelope) Manifest() Manifest { return cloneManifest(verified.manifest) }

func (verified VerifiedEnvelope) CanonicalManifestBytes() []byte {
	return append([]byte(nil), verified.manifestBytes...)
}

func (verified VerifiedEnvelope) CanonicalEnvelopeBytes() []byte {
	return append([]byte(nil), verified.envelopeBytes...)
}
