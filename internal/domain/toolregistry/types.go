// Package toolregistry defines signed, reviewed tool manifests and the
// immutable registry used to resolve exact execution capabilities.
package toolregistry

import (
	"crypto/ed25519"
	"time"
)

const (
	ManifestSchemaVersion = "coh.tool-manifest/v1"
	EnvelopeSchemaVersion = "coh.signed-tool-manifest/v1"
	ContractVersion       = "1.0.0"
	SignatureAlgorithm    = "ed25519"
	SignatureDomain       = "COH-SIGNED-TOOL-MANIFEST-V1\x00"
	MaximumInputBytes     = 1 << 20
	MaximumValidity       = 366 * 24 * time.Hour
)

type InputField struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Required     bool     `json:"required"`
	Minimum      *int64   `json:"minimum"`
	Maximum      *int64   `json:"maximum"`
	MaximumBytes uint32   `json:"maximum_bytes"`
	MaximumItems uint16   `json:"maximum_items"`
	Enum         []string `json:"enum"`
}

type ResourceLimits struct {
	WallTimeMilliseconds  uint64 `json:"wall_time_milliseconds"`
	CPUMilliseconds       uint64 `json:"cpu_milliseconds"`
	MemoryBytes           uint64 `json:"memory_bytes"`
	OutputBytes           uint64 `json:"output_bytes"`
	EphemeralStorageBytes uint64 `json:"ephemeral_storage_bytes"`
	ProcessCount          uint16 `json:"process_count"`
	OpenFileCount         uint32 `json:"open_file_count"`
}

type NetworkPolicy struct {
	Mode                  string   `json:"mode"`
	Protocols             []string `json:"protocols"`
	DNSMode               string   `json:"dns_mode"`
	PublicInternetAllowed bool     `json:"public_internet_allowed"`
	MetadataAllowed       bool     `json:"metadata_allowed"`
	MaximumConnections    uint32   `json:"maximum_connections"`
}

type Operation struct {
	Name               string         `json:"name"`
	InputSchemaVersion string         `json:"input_schema_version"`
	InputFields        []InputField   `json:"input_fields"`
	BaselineActionTier string         `json:"baseline_action_tier"`
	MaximumActionTier  string         `json:"maximum_action_tier"`
	IsolationClass     string         `json:"isolation_class"`
	CredentialClasses  []string       `json:"credential_classes"`
	ResourceLimits     ResourceLimits `json:"resource_limits"`
	NetworkPolicy      NetworkPolicy  `json:"network_policy"`
	CancellationMode   string         `json:"cancellation_mode"`
	RetryMode          string         `json:"retry_mode"`
}

type Manifest struct {
	SchemaVersion     string      `json:"schema_version"`
	ContractVersion   string      `json:"contract_version"`
	ManifestID        string      `json:"manifest_id"`
	ToolName          string      `json:"tool_name"`
	ToolVersion       string      `json:"tool_version"`
	ArtifactDigest    string      `json:"artifact_digest"`
	MaximumActionTier string      `json:"maximum_action_tier"`
	PublisherID       string      `json:"publisher_id"`
	ReviewID          string      `json:"review_id"`
	ReviewRevision    uint64      `json:"review_revision"`
	ReviewDecision    string      `json:"review_decision"`
	ReviewerActorIDs  []string    `json:"reviewer_actor_ids"`
	ThreatModelDigest string      `json:"threat_model_digest"`
	ReviewedAt        string      `json:"reviewed_at"`
	ValidFrom         string      `json:"valid_from"`
	ValidUntil        string      `json:"valid_until"`
	Operations        []Operation `json:"operations"`
}

type Envelope struct {
	SchemaVersion        string   `json:"schema_version"`
	ContractVersion      string   `json:"contract_version"`
	Manifest             Manifest `json:"manifest"`
	ManifestDigest       string   `json:"manifest_digest"`
	PublisherID          string   `json:"publisher_id"`
	PublisherKeyID       string   `json:"publisher_key_id"`
	PublisherKeyRevision uint64   `json:"publisher_key_revision"`
	SignatureAlgorithm   string   `json:"signature_algorithm"`
	Signature            string   `json:"signature"`
}

type PublisherAuthority struct {
	PublisherID      string
	KeyID            string
	KeyRevision      uint64
	ApprovalRevision uint64
	Active           bool
	Approved         bool
	PublicKey        ed25519.PublicKey
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
	ManifestDigest       string
	PublisherID          string
	PublisherKeyID       string
	PublisherKeyRevision uint64
	manifest             Manifest
	manifestBytes        []byte
	envelopeBytes        []byte
}

func (verified VerifiedEnvelope) Manifest() Manifest { return cloneManifest(verified.manifest) }
func (verified VerifiedEnvelope) CanonicalManifestBytes() []byte {
	return append([]byte(nil), verified.manifestBytes...)
}
func (verified VerifiedEnvelope) CanonicalEnvelopeBytes() []byte {
	return append([]byte(nil), verified.envelopeBytes...)
}

type ToolReference struct {
	Name           string
	Version        string
	ArtifactDigest string
}

type Admission struct {
	ManifestDigest            string
	ManifestID                string
	Tool                      ToolReference
	PublisherID               string
	PublisherKeyID            string
	PublisherKeyRevision      uint64
	PublisherApprovalRevision uint64
	ReviewID                  string
	ReviewRevision            uint64
	Replayed                  bool
}

type Capability struct {
	ManifestDigest   string
	ManifestID       string
	Tool             ToolReference
	Operation        Operation
	RequiredTier     string
	RuntimeCeiling   string
	EffectiveCeiling string
}

type Clock interface{ Now() time.Time }
