// Package profilecomposition verifies signed, data-only profile layers used by
// the COH command composition root. Verification never grants action authority.
package profilecomposition

import (
	"crypto/ed25519"
	"errors"
	"time"
)

const (
	EnvelopeSchemaVersion = "coh.signed-profile-layer/v1"
	LayerSchemaVersion    = "coh.profile-layer/v1"
	ContractVersion       = "1.0.0"
	SignatureAlgorithm    = "ed25519"
	MaximumInputBytes     = 4 << 20
	MaximumTrustAge       = 5 * time.Minute

	layerDigestDomain = "COH-PROFILE-LAYER-V1\x00"
	signatureDomain   = "COH-SIGNED-PROFILE-LAYER-V1\x00"
)

type ArtifactRef struct {
	ID       string `json:"id"`
	Revision uint64 `json:"revision"`
	Digest   string `json:"digest"`
}

type Target struct {
	DeploymentKinds   []string `json:"deployment_kinds"`
	ConnectivityModes []string `json:"connectivity_modes"`
	Platforms         []string `json:"platforms"`
	Surfaces          []string `json:"surfaces"`
}

type Limits struct {
	MaxConcurrency   uint64 `json:"max_concurrency"`
	MaxContextBytes  uint64 `json:"max_context_bytes"`
	MaxDurationMS    uint64 `json:"max_duration_ms"`
	MaxEvidenceBytes uint64 `json:"max_evidence_bytes"`
	MaxModelTokens   uint64 `json:"max_model_tokens"`
	MaxToolCalls     uint64 `json:"max_tool_calls"`
}

type Features struct {
	ExternalConnectivity bool `json:"external_connectivity"`
	ExtensionLifecycle   bool `json:"extension_lifecycle"`
	ModelInference       bool `json:"model_inference"`
	Retrieval            bool `json:"retrieval"`
	ToolDispatch         bool `json:"tool_dispatch"`
}

type Contribution struct {
	DeploymentProfile   ArtifactRef   `json:"deployment_profile"`
	CapabilityBundles   []ArtifactRef `json:"capability_bundles"`
	PolicyBundles       []ArtifactRef `json:"policy_bundles"`
	EndpointReferences  []string      `json:"endpoint_references"`
	Permissions         []string      `json:"permissions"`
	Limits              Limits        `json:"limits"`
	Features            Features      `json:"features"`
	OfflineBundleDigest string        `json:"offline_bundle_digest"`
}

type Parent struct {
	LayerID     string `json:"layer_id"`
	Revision    uint64 `json:"revision"`
	LayerDigest string `json:"layer_digest"`
}

type Layer struct {
	SchemaVersion               string       `json:"schema_version"`
	ContractVersion             string       `json:"contract_version"`
	LayerID                     string       `json:"layer_id"`
	Name                        string       `json:"name"`
	Kind                        string       `json:"kind"`
	Revision                    uint64       `json:"revision"`
	Precedence                  uint64       `json:"precedence"`
	PredecessorDigest           string       `json:"predecessor_digest"`
	RollbackAuthorizationDigest string       `json:"rollback_authorization_digest"`
	Target                      Target       `json:"target"`
	Parents                     []Parent     `json:"parents"`
	Contribution                Contribution `json:"contribution"`
	IssuedAt                    string       `json:"issued_at"`
	NotBefore                   string       `json:"not_before"`
	ExpiresAt                   string       `json:"expires_at"`
}

type Signature struct {
	Role        string `json:"role"`
	SignerID    string `json:"signer_id"`
	KeyID       string `json:"key_id"`
	KeyRevision uint64 `json:"key_revision"`
	Algorithm   string `json:"algorithm"`
	SignedAt    string `json:"signed_at"`
	Signature   string `json:"signature"`
}

type Envelope struct {
	SchemaVersion   string      `json:"schema_version"`
	ContractVersion string      `json:"contract_version"`
	Layer           Layer       `json:"layer"`
	LayerDigest     string      `json:"layer_digest"`
	Signatures      []Signature `json:"signatures"`
}

// TrustSnapshot is supplied by the command composition root and has no JSON
// representation. It contains verification metadata, not signing authority.
type TrustSnapshot struct {
	ScopeOrganizationID string
	Environment         string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	TrustRevision       uint64
	Records             []SigningAuthority
}

type SigningAuthority struct {
	Role               string
	SignerID           string
	KeyID              string
	KeyRevision        uint64
	TrustRevision      uint64
	RevocationRevision uint64
	ValidFrom          time.Time
	ValidUntil         time.Time
	Active             bool
	Revoked            bool
	PublicKey          ed25519.PublicKey
}

func (TrustSnapshot) MarshalJSON() ([]byte, error) {
	return nil, errors.New("profile composition trust snapshot is not serializable")
}

func (*TrustSnapshot) UnmarshalJSON([]byte) error {
	return errors.New("profile composition trust snapshot is not accepted from JSON")
}
