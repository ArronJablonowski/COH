package extensionlifecycle

import "context"

const (
	TransitionSchema       = "coh.extension-lifecycle-transition/v1"
	HandleSchema           = "coh.extension-revocation-handle/v1"
	ReceiptSchema          = "coh.extension-registration-receipt/v1"
	ActiveExtensionSchema  = "coh.active-extension/v1"
	transitionDigestDomain = "COH-EXTENSION-LIFECYCLE-TRANSITION-V1\x00"
	handleDigestDomain     = "COH-EXTENSION-REVOCATION-HANDLE-V1\x00"
	receiptDigestDomain    = "COH-EXTENSION-REGISTRATION-RECEIPT-V1\x00"
	activeDigestDomain     = "COH-ACTIVE-EXTENSION-V1\x00"
)

type Direction string
type Phase string

const (
	ActivateDirection   Direction = "activate"
	DeactivateDirection Direction = "deactivate"
	PreparedPhase       Phase     = "prepared"
	ApplyingPhase       Phase     = "applying"
	UnwindingPhase      Phase     = "unwinding"
	ActivePhase         Phase     = "active"
	DrainingPhase       Phase     = "draining"
	RevokingPhase       Phase     = "revoking"
	InactivePhase       Phase     = "inactive"
)

type RevocationHandle struct {
	SchemaVersion       string `json:"schema_version"`
	ContractVersion     string `json:"contract_version"`
	HandleID            string `json:"handle_id"`
	ExtensionID         string `json:"extension_id"`
	ManifestDigest      string `json:"manifest_digest"`
	TransitionID        string `json:"transition_id"`
	RegistrationID      string `json:"registration_id"`
	RegistrationOrdinal uint64 `json:"registration_ordinal"`
	OrganizationID      string `json:"organization_id"`
	TenantID            string `json:"tenant_id"`
	ScopeDigest         string `json:"scope_digest"`
	RegistryRevision    uint64 `json:"registry_revision"`
	Generation          uint64 `json:"generation"`
	IssuedAt            string `json:"issued_at"`
	HandleDigest        string `json:"handle_digest,omitempty"`
}

type RegistrationReceipt struct {
	SchemaVersion        string           `json:"schema_version"`
	ContractVersion      string           `json:"contract_version"`
	ReceiptID            string           `json:"receipt_id"`
	IdempotencyKey       string           `json:"idempotency_key"`
	ExtensionID          string           `json:"extension_id"`
	ManifestDigest       string           `json:"manifest_digest"`
	TransitionID         string           `json:"transition_id"`
	RegistrationID       string           `json:"registration_id"`
	RegistrationOrdinal  uint64           `json:"registration_ordinal"`
	Role                 string           `json:"role"`
	CapabilityID         string           `json:"capability_id"`
	CapabilityVersion    string           `json:"capability_version"`
	ProviderID           string           `json:"provider_id"`
	OrganizationID       string           `json:"organization_id"`
	TenantID             string           `json:"tenant_id"`
	ScopeDigest          string           `json:"scope_digest"`
	PermissionsDigest    string           `json:"permissions_digest"`
	ResourceLimitsDigest string           `json:"resource_limits_digest"`
	RegistryRevision     uint64           `json:"registry_revision"`
	Generation           uint64           `json:"generation"`
	State                string           `json:"state"`
	RevocationHandle     RevocationHandle `json:"revocation_handle"`
	RegisteredAt         string           `json:"registered_at"`
	RevokedAt            string           `json:"revoked_at"`
	EffectAuditDigest    string           `json:"effect_audit_digest"`
	ReceiptDigest        string           `json:"receipt_digest,omitempty"`
}

type Transition struct {
	SchemaVersion              string    `json:"schema_version"`
	ContractVersion            string    `json:"contract_version"`
	TransitionID               string    `json:"transition_id"`
	IntentDigest               string    `json:"intent_digest"`
	ExtensionID                string    `json:"extension_id"`
	ManifestDigest             string    `json:"manifest_digest"`
	OrganizationID             string    `json:"organization_id"`
	TenantID                   string    `json:"tenant_id"`
	Direction                  Direction `json:"direction"`
	Phase                      Phase     `json:"phase"`
	Sequence                   uint64    `json:"sequence"`
	ExpectedLifecycleRevision  uint64    `json:"expected_lifecycle_revision"`
	RegistryRevision           uint64    `json:"registry_revision"`
	NextApplyOrdinal           uint64    `json:"next_apply_ordinal"`
	NextRevokeOrdinal          int64     `json:"next_revoke_ordinal"`
	RegistrationReceiptDigests []string  `json:"registration_receipt_digests"`
	AdmissionClosed            bool      `json:"admission_closed"`
	ActiveWorkCount            uint64    `json:"active_work_count"`
	TerminalWorkDigest         string    `json:"terminal_work_digest"`
	ActivationAuditDigest      string    `json:"activation_audit_digest"`
	TerminalAuditDigest        string    `json:"terminal_audit_digest"`
	FailureCode                string    `json:"failure_code"`
	CreatedAt                  string    `json:"created_at"`
	UpdatedAt                  string    `json:"updated_at"`
	TransitionDigest           string    `json:"transition_digest,omitempty"`
}

type ActiveExtension struct {
	SchemaVersion              string   `json:"schema_version"`
	ContractVersion            string   `json:"contract_version"`
	ExtensionID                string   `json:"extension_id"`
	ExtensionName              string   `json:"extension_name"`
	ExtensionVersion           string   `json:"extension_version"`
	ManifestDigest             string   `json:"manifest_digest"`
	TransitionID               string   `json:"transition_id"`
	LifecycleRevision          uint64   `json:"lifecycle_revision"`
	RegistryRevision           uint64   `json:"registry_revision"`
	OrganizationID             string   `json:"organization_id"`
	TenantID                   string   `json:"tenant_id"`
	ActiveProfileRevision      uint64   `json:"active_profile_revision"`
	ProfileBindingDigest       string   `json:"profile_binding_digest"`
	CompositionDigest          string   `json:"composition_digest"`
	CapabilityGraphDigest      string   `json:"capability_graph_digest"`
	RegistrationReceiptDigests []string `json:"registration_receipt_digests"`
	ActivationAuditDigest      string   `json:"activation_audit_digest"`
	ActivatedAt                string   `json:"activated_at"`
	ActiveDigest               string   `json:"active_digest,omitempty"`
}

type EffectRequest struct {
	EffectKey        string
	TransitionID     string
	ManifestDigest   string
	ExtensionID      string
	OrganizationID   string
	TenantID         string
	ScopeDigest      string
	Registration     Registration
	Ordinal          uint64
	RegistryRevision uint64
}

type EffectResult struct {
	ReceiptID         string
	HandleID          string
	Generation        uint64
	RegistryRevision  uint64
	EffectAuditDigest string
	RegisteredAt      string
}

type RevocationResult struct {
	RevokedAt         string
	EffectAuditDigest string
}

type ActivationResult struct {
	Transition Transition
	Active     ActiveExtension
	Replayed   bool
}

type DeactivationResult struct {
	Transition Transition
	Replayed   bool
}

type DrainRequest struct {
	TransitionID      string
	ExtensionID       string
	ManifestDigest    string
	OrganizationID    string
	TenantID          string
	MaximumDurationMS uint64
}

type DrainAttestation struct {
	TransitionID           string
	AdmissionsClosed       bool
	ActiveWork             uint64
	Durable                bool
	TerminalOutcomesDigest string
}

type ActivationStore interface {
	LoadManifest(context.Context, string) ([]byte, bool, error)
	PutManifest(context.Context, string, string, []byte) error
	LoadActive(context.Context, string, string, string) (ActiveExtension, bool, error)
	LoadInactivePredecessor(context.Context, string, string, string, string, uint64) (Transition, bool, error)
	LoadTransition(context.Context, string) (Transition, bool, error)
	LoadReceipt(context.Context, string) (RegistrationReceipt, bool, error)
	CreateTransition(context.Context, Transition) (Transition, error)
	AdvanceTransition(context.Context, Transition, Transition) (Transition, error)
	CommitReceipt(context.Context, Transition, RegistrationReceipt, Transition) (Transition, error)
	CommitRevocation(context.Context, Transition, RegistrationReceipt, RegistrationReceipt, Transition) (Transition, error)
	PublishActive(context.Context, Transition, ActiveExtension, Transition) (Transition, error)
	RemoveActive(context.Context, Transition, ActiveExtension, Transition) (Transition, error)
}

// EffectPort stages registrations behind the inactive transition. Stage and
// Revoke are idempotent by EffectKey; Resolve closes lost-response ambiguity.
type EffectPort interface {
	Resolve(context.Context, EffectRequest) (EffectResult, bool, error)
	Stage(context.Context, EffectRequest) (EffectResult, error)
	Revoke(context.Context, EffectRequest, RevocationHandle) (RevocationResult, error)
}

type ActivationAuditPort interface {
	CommitActivation(context.Context, string, string, []string) (string, error)
	CommitDeactivation(context.Context, string, string, string, []string) (string, error)
}

// DeactivationGate atomically closes extension admission before it waits for
// work. It returns only after work drains or is boundedly canceled and every
// terminal outcome is durable.
type DeactivationGate interface {
	CloseAdmissionsAndDrain(context.Context, DrainRequest) (DrainAttestation, error)
}
