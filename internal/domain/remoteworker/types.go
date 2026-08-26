// Package remoteworker defines canonical remote-worker identity, capability,
// enrollment, runner-lease, dispatch, revocation, and decision contracts.
package remoteworker

import (
	"crypto/ed25519"
	"encoding/json"
	"time"
)

const (
	ContractVersion           = "1.0.0"
	AttestationSchemaVersion  = "coh.remote-worker-capability/v1"
	EnvelopeSchemaVersion     = "coh.signed-remote-worker-capability/v1"
	EnrollmentSchemaVersion   = "coh.remote-worker-enrollment/v1"
	LeaseSchemaVersion        = "coh.runner-lease/v1"
	DispatchSchemaVersion     = "coh.runner-dispatch/v1"
	RevocationSchemaVersion   = "coh.remote-worker-revocation/v1"
	DecisionSchemaVersion     = "coh.remote-worker-decision/v1"
	SignatureAlgorithm        = "ed25519"
	SignatureDomain           = "COH-REMOTE-WORKER-CAPABILITY-V1\x00"
	MaximumInputBytes         = 64 << 10
	MaximumAttestationAge     = 5 * time.Minute
	MaximumPeerObservationAge = 30 * time.Second
	MaximumLeaseTTLSeconds    = uint32(300)
)

type Scope struct {
	OrganizationID string `json:"organization_id"`
	TenantID       string `json:"tenant_id"`
}

// TransportIdentity is trusted transport state, never caller assertion.
// Remote workers use remote_mtls. local_socket_authenticated exists so local
// internal transports have an equally strict SEC-025 contract.
type TransportIdentity struct {
	Kind                   string
	IdentityDigest         string
	ObservedAt             time.Time
	MutualTLS              bool
	CertificateFingerprint string
	CertificateRevision    uint64
	CertificateNotBefore   time.Time
	CertificateNotAfter    time.Time
	URISAN                 string
	SocketPath             string
	SocketMode             uint32
	SocketOwnerUID         uint32
	SocketOwnerGID         uint32
	PeerUID                uint32
	PeerGID                uint32
	PeerPID                uint32
	PeerAuthenticated      bool
	PlatformPeerAuth       bool
}

type ResourceCapacity struct {
	WallTimeMilliseconds  uint64 `json:"wall_time_milliseconds"`
	CPUMilliseconds       uint64 `json:"cpu_milliseconds"`
	MemoryBytes           uint64 `json:"memory_bytes"`
	OutputBytes           uint64 `json:"output_bytes"`
	EphemeralStorageBytes uint64 `json:"ephemeral_storage_bytes"`
	ProcessCount          uint32 `json:"process_count"`
	OpenFileCount         uint32 `json:"open_file_count"`
}

// CapabilityAttestation is a signed software capability statement. It does
// not claim hardware-rooted TPM or TEE attestation.
type CapabilityAttestation struct {
	SchemaVersion           string           `json:"schema_version"`
	ContractVersion         string           `json:"contract_version"`
	Scope                   Scope            `json:"scope"`
	WorkerID                string           `json:"worker_id"`
	EnrollmentNonce         string           `json:"enrollment_nonce"`
	TransportIdentityDigest string           `json:"transport_identity_digest"`
	CertificateFingerprint  string           `json:"certificate_fingerprint"`
	CertificateRevision     uint64           `json:"certificate_revision"`
	PlatformOS              string           `json:"platform_os"`
	PlatformArchitecture    string           `json:"platform_architecture"`
	ExecutorDigest          string           `json:"executor_digest"`
	RuntimeDigest           string           `json:"runtime_digest"`
	ToolRegistryDigest      string           `json:"tool_registry_digest"`
	IsolationClasses        []string         `json:"isolation_classes"`
	MaximumActionTier       string           `json:"maximum_action_tier"`
	Resources               ResourceCapacity `json:"resources"`
	NetworkModes            []string         `json:"network_modes"`
	IssuedAt                string           `json:"issued_at"`
	ExpiresAt               string           `json:"expires_at"`
}

type SignedCapabilityAttestation struct {
	SchemaVersion          string                `json:"schema_version"`
	ContractVersion        string                `json:"contract_version"`
	Attestation            CapabilityAttestation `json:"attestation"`
	AttestationDigest      string                `json:"attestation_digest"`
	AttestationKeyID       string                `json:"attestation_key_id"`
	AttestationKeyRevision uint64                `json:"attestation_key_revision"`
	SignatureAlgorithm     string                `json:"signature_algorithm"`
	Signature              string                `json:"signature"`
}

type AttestationAuthority struct {
	Scope           Scope
	WorkerID        string
	EnrollmentNonce string
	KeyID           string
	KeyRevision     uint64
	Active          bool
	PublicKey       ed25519.PublicKey
	Transport       TransportIdentity
}

type VerifiedAttestation struct {
	Digest            string
	KeyID             string
	KeyRevision       uint64
	attestation       CapabilityAttestation
	canonicalBytes    []byte
	canonicalEnvelope []byte
}

func (verified VerifiedAttestation) Value() CapabilityAttestation {
	return cloneAttestation(verified.attestation)
}

func (verified VerifiedAttestation) CanonicalBytes() []byte {
	return append([]byte(nil), verified.canonicalBytes...)
}

func (verified VerifiedAttestation) CanonicalEnvelopeBytes() []byte {
	return append([]byte(nil), verified.canonicalEnvelope...)
}

type EnrollmentRequest struct {
	SchemaVersion     string          `json:"schema_version"`
	ContractVersion   string          `json:"contract_version"`
	RequestID         string          `json:"request_id"`
	IdempotencyKey    string          `json:"idempotency_key"`
	Scope             Scope           `json:"scope"`
	WorkerID          string          `json:"worker_id"`
	EnrollmentNonce   string          `json:"enrollment_nonce"`
	SignedAttestation json.RawMessage `json:"signed_attestation"`
}

// EnrollmentAuthority is supplied by authenticated control-plane state.
type EnrollmentAuthority struct {
	Scope                    Scope
	WorkerID                 string
	EnrollmentAllowed        bool
	EnrollmentDecisionDigest string
	ExpectedCurrentRevision  uint64
	ExpectedEnrollmentNonce  string
	AttestationKeyID         string
	AttestationKeyRevision   uint64
	AttestationPublicKey     ed25519.PublicKey
	Transport                TransportIdentity
}

type WorkerRecord struct {
	Scope                   Scope
	WorkerID                string
	Revision                uint64
	Active                  bool
	TransportIdentityDigest string
	CertificateFingerprint  string
	CertificateRevision     uint64
	AttestationDigest       string
	AttestationKeyID        string
	AttestationKeyRevision  uint64
	AttestationKeyDigest    string
	Attestation             CapabilityAttestation
	EnrolledAt              time.Time
	RevokedAt               time.Time
	RevocationReason        string
}

type LeaseScope struct {
	OrganizationID       string           `json:"organization_id"`
	TenantID             string           `json:"tenant_id"`
	CaseID               string           `json:"case_id"`
	ActorID              string           `json:"actor_id"`
	TaskID               string           `json:"task_id"`
	ActionDigest         string           `json:"action_digest"`
	TargetDigests        []string         `json:"target_digests"`
	ToolName             string           `json:"tool_name"`
	ToolVersion          string           `json:"tool_version"`
	ToolDigest           string           `json:"tool_digest"`
	ToolRegistryDigest   string           `json:"tool_registry_digest"`
	Operation            string           `json:"operation"`
	RequiredTier         string           `json:"required_tier"`
	IsolationClass       string           `json:"isolation_class"`
	Resources            ResourceCapacity `json:"resources"`
	NetworkMode          string           `json:"network_mode"`
	ResourcePolicyDigest string           `json:"resource_policy_digest"`
	NetworkPolicyDigest  string           `json:"network_policy_digest"`
}

type LeaseRequest struct {
	SchemaVersion       string     `json:"schema_version"`
	ContractVersion     string     `json:"contract_version"`
	RequestID           string     `json:"request_id"`
	IdempotencyKey      string     `json:"idempotency_key"`
	Scope               LeaseScope `json:"scope"`
	WorkerID            string     `json:"worker_id"`
	RequestedTTLSeconds uint32     `json:"requested_ttl_seconds"`
}

type LeaseAuthority struct {
	Scope                       LeaseScope
	ActorActive                 bool
	ActorRevision               uint64
	TaskActive                  bool
	EmergencyStopActive         bool
	AuthorizationAllowed        bool
	AuthorizationDecisionDigest string
	PolicyAllowed               bool
	PolicyDecisionDigest        string
	ApprovalRequired            bool
	ApprovalAllowed             bool
	ApprovalDecisionDigest      string
	Worker                      WorkerRecord
	Transport                   TransportIdentity
	ObservedAt                  time.Time
}

type DispatchRequest struct {
	SchemaVersion   string     `json:"schema_version"`
	ContractVersion string     `json:"contract_version"`
	LeaseID         string     `json:"lease_id"`
	Scope           LeaseScope `json:"scope"`
	WorkerID        string     `json:"worker_id"`
}

// DispatchEnvelope is delivered only after a capability has been atomically
// consumed and every current authority binding has been revalidated.
type DispatchEnvelope struct {
	LeaseID                     string
	Scope                       LeaseScope
	WorkerID                    string
	WorkerRevision              uint64
	CertificateRevision         uint64
	AttestationDigest           string
	AttestationKeyRevision      uint64
	AttestationKeyDigest        string
	AuthorizationDecisionDigest string
	PolicyDecisionDigest        string
	ApprovalDecisionDigest      string
	IssuedAt                    time.Time
	ExpiresAt                   time.Time
}

type RevocationRequest struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	RequestID       string `json:"request_id"`
	Kind            string `json:"kind"`
	Scope           Scope  `json:"scope"`
	WorkerID        string `json:"worker_id,omitempty"`
	LeaseID         string `json:"lease_id,omitempty"`
	Reason          string `json:"reason"`
}
