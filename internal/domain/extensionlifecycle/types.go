// Package extensionlifecycle verifies signed data-only extension manifests and
// administrator lifecycle intents. Verification never grants action authority.
package extensionlifecycle

import (
	"crypto/ed25519"
	"errors"
	"time"
)

const (
	EnvelopeSchemaVersion = "coh.signed-extension-manifest/v1"
	ManifestSchemaVersion = "coh.extension-manifest/v1"
	IntentSchemaVersion   = "coh.extension-activation-intent/v1"
	ContractVersion       = "1.0.0"
	SignatureAlgorithm    = "ed25519"
	MaximumInputBytes     = 4 << 20
	MaximumAuthorityAge   = 5 * time.Minute
	MaximumRevision       = uint64(1<<63 - 1)

	manifestDigestDomain         = "COH-EXTENSION-MANIFEST-V1\x00"
	publisherSignatureDomain     = "COH-PUBLISHED-EXTENSION-V1\x00"
	reviewerSignatureDomain      = "COH-REVIEWED-EXTENSION-V1\x00"
	ownerSignatureDomain         = "COH-OWNED-EXTENSION-V1\x00"
	intentDigestDomain           = "COH-EXTENSION-LIFECYCLE-INTENT-V1\x00"
	administratorSignatureDomain = "COH-SIGNED-EXTENSION-LIFECYCLE-V1\x00"
	permissionsDigestDomain      = "COH-EXTENSION-PERMISSIONS-V1\x00"
	scopeDigestDomain            = "COH-EXTENSION-SCOPE-V1\x00"
)

type CapabilityRef struct {
	CapabilityID      string `json:"capability_id"`
	CapabilityVersion string `json:"capability_version"`
}

type Registration struct {
	RegistrationID       string        `json:"registration_id"`
	Role                 string        `json:"role"`
	Capability           CapabilityRef `json:"capability"`
	ProviderID           string        `json:"provider_id"`
	Permissions          []string      `json:"permissions"`
	ScopeTypes           []string      `json:"scope_types"`
	ResourceLimitsDigest string        `json:"resource_limits_digest"`
}

type Manifest struct {
	SchemaVersion             string          `json:"schema_version"`
	ContractVersion           string          `json:"contract_version"`
	ExtensionID               string          `json:"extension_id"`
	ExtensionName             string          `json:"extension_name"`
	ExtensionVersion          string          `json:"extension_version"`
	ExtensionKind             string          `json:"extension_kind"`
	OwnerActorID              string          `json:"owner_actor_id"`
	OwnerModule               string          `json:"owner_module"`
	ArtifactDigest            string          `json:"artifact_digest"`
	SBOMDigest                string          `json:"sbom_digest"`
	ProvenanceDigest          string          `json:"provenance_digest"`
	TestEvidenceDigest        string          `json:"test_evidence_digest"`
	ThreatModelDigest         string          `json:"threat_model_digest"`
	PredecessorManifestDigest string          `json:"predecessor_manifest_digest"`
	DeclaredPermissions       []string        `json:"declared_permissions"`
	DeclaredScopeTypes        []string        `json:"declared_scope_types"`
	Dependencies              []CapabilityRef `json:"dependencies"`
	Registrations             []Registration  `json:"registrations"`
	MaximumActiveWork         uint64          `json:"maximum_active_work"`
	MaximumDrainDurationMS    uint64          `json:"maximum_drain_duration_ms"`
	ReviewDigest              string          `json:"review_digest"`
	ValidFrom                 string          `json:"valid_from"`
	ValidUntil                string          `json:"valid_until"`
}

type Signature struct {
	ActorID          string `json:"actor_id"`
	KeyID            string `json:"key_id"`
	KeyRevision      uint64 `json:"key_revision"`
	ApprovalRevision uint64 `json:"approval_revision"`
	Algorithm        string `json:"signature_algorithm"`
	Value            string `json:"signature"`
}

type Envelope struct {
	SchemaVersion      string      `json:"schema_version"`
	ContractVersion    string      `json:"contract_version"`
	Manifest           Manifest    `json:"manifest"`
	ManifestDigest     string      `json:"manifest_digest"`
	PublisherSignature Signature   `json:"publisher_signature"`
	ReviewSignatures   []Signature `json:"review_signatures"`
	OwnerSignature     Signature   `json:"owner_signature"`
}

type ActivationIntent struct {
	SchemaVersion                     string    `json:"schema_version"`
	ContractVersion                   string    `json:"contract_version"`
	RequestID                         string    `json:"request_id"`
	IdempotencyKey                    string    `json:"idempotency_key"`
	ActorID                           string    `json:"actor_id"`
	ActorKind                         string    `json:"actor_kind"`
	OrganizationID                    string    `json:"organization_id"`
	TenantID                          string    `json:"tenant_id"`
	ExtensionID                       string    `json:"extension_id"`
	ManifestDigest                    string    `json:"manifest_digest"`
	Operation                         string    `json:"operation"`
	Mode                              string    `json:"mode"`
	RequestedScopeDigest              string    `json:"requested_scope_digest"`
	RequestedPermissionsDigest        string    `json:"requested_permissions_digest"`
	ExpectedPredecessorManifestDigest string    `json:"expected_predecessor_manifest_digest"`
	RollbackAuthorizationDigest       string    `json:"rollback_authorization_digest"`
	ActiveProfileRevision             uint64    `json:"active_profile_revision"`
	ProfileBindingDigest              string    `json:"profile_binding_digest"`
	CompositionDigest                 string    `json:"composition_digest"`
	CapabilityGraphDigest             string    `json:"capability_graph_digest"`
	ExpectedLifecycleRevision         uint64    `json:"expected_lifecycle_revision"`
	ExpectedRegistryRevision          uint64    `json:"expected_registry_revision"`
	PolicyDecisionDigest              string    `json:"policy_decision_digest"`
	PromotionSnapshotDigest           string    `json:"promotion_snapshot_digest"`
	QualificationSnapshotDigest       string    `json:"qualification_snapshot_digest"`
	AuditAvailabilityDigest           string    `json:"audit_availability_digest"`
	EStopState                        string    `json:"estop_state"`
	EStopRevision                     uint64    `json:"estop_revision"`
	MaximumDrainDurationMS            uint64    `json:"maximum_drain_duration_ms"`
	IssuedAt                          string    `json:"issued_at"`
	DeadlineAt                        string    `json:"deadline_at"`
	IntentDigest                      string    `json:"intent_digest"`
	AdministratorSignature            Signature `json:"administrator_signature"`
}

type ExactScope struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
	CaseID         string `json:"case_id"`
	TaskID         string `json:"task_id"`
}

type SigningAuthority struct {
	Role               string
	ActorID            string
	KeyID              string
	KeyRevision        uint64
	ApprovalRevision   uint64
	AuthorityRevision  uint64
	RevocationRevision uint64
	ValidFrom          time.Time
	ValidUntil         time.Time
	Active             bool
	Revoked            bool
	PublicKey          ed25519.PublicKey
}

// AuthoritySnapshot is built by the command root. Its booleans are results of
// current trusted authorities, not caller assertions.
type AuthoritySnapshot struct {
	CreatedAt                   time.Time
	ExpiresAt                   time.Time
	AuthorityRevision           uint64
	RegistryRevision            uint64
	ManifestDigest              string
	ReviewDigest                string
	PromotionSnapshotDigest     string
	QualificationSnapshotDigest string
	PolicyDecisionDigest        string
	AuditAvailabilityDigest     string
	RollbackAuthorizationDigest string
	ProfileRevision             uint64
	ProfileBindingDigest        string
	CompositionDigest           string
	CapabilityGraphDigest       string
	EStopState                  string
	EStopRevision               uint64
	Scope                       ExactScope
	Permissions                 []string
	PromotionActive             bool
	ReviewActive                bool
	QualificationActive         bool
	PolicyAllowed               bool
	AuditAvailable              bool
	DependenciesQualified       bool
	ArtifactRevoked             bool
	RollbackAllowed             bool
	Records                     []SigningAuthority
}

func (AuthoritySnapshot) MarshalJSON() ([]byte, error) {
	return nil, errors.New("extension authority snapshot is not serializable")
}
func (*AuthoritySnapshot) UnmarshalJSON([]byte) error {
	return errors.New("extension authority snapshot is not accepted from JSON")
}
