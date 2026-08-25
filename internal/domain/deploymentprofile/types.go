// Package deploymentprofile defines the versioned, side-effect-free startup
// profile contract. It validates operator declarations; it does not probe the
// host, qualify a platform, load credentials, or compose runtime services.
package deploymentprofile

import "context"

const (
	SchemaVersion   = "coh.deployment-profile/v1"
	ContractVersion = "1.0.0"
	MaximumBytes    = 64 << 10
)

type DeploymentKind string

const (
	NativeWorkstation DeploymentKind = "native_workstation"
	NativeServer      DeploymentKind = "native_server"
	Compose           DeploymentKind = "compose"
)

type ConnectivityMode string

const (
	Connected           ConnectivityMode = "connected"
	RestrictedConnected ConnectivityMode = "restricted_connected"
	AirGapped           ConnectivityMode = "air_gapped"
)

// Config contains references and security posture only. Secret values and
// credential material are not valid fields in this contract.
type Config struct {
	SchemaVersion   string        `json:"schema_version"`
	ContractVersion string        `json:"contract_version"`
	Change          ChangeControl `json:"change"`
	Deployment      Deployment    `json:"deployment"`
	Services        Services      `json:"services"`
	Isolation       Isolation     `json:"isolation"`
	Connectivity    Connectivity  `json:"connectivity"`
	Identities      Identities    `json:"identities"`
	Compose         ComposeSpec   `json:"compose"`
	AirGap          AirGapSpec    `json:"air_gap"`
}

type ChangeControl struct {
	OrganizationID       string `json:"organization_id"`
	ActorID              string `json:"actor_id"`
	Revision             uint64 `json:"revision"`
	PreviousConfigDigest string `json:"previous_config_digest"`
}

type Deployment struct {
	Kind         DeploymentKind `json:"kind"`
	OperatingSys string         `json:"os"`
	Architecture string         `json:"arch"`
}

type Services struct {
	Storage           string `json:"storage"`
	Workflow          string `json:"workflow"`
	Authentication    string `json:"authentication"`
	TransportSecurity string `json:"transport_security"`
	EvidenceStore     string `json:"evidence_store"`
}

type Isolation struct {
	ListenScope          string `json:"listen_scope"`
	DockerRequired       bool   `json:"docker_required"`
	DockerSocketMounted  bool   `json:"docker_socket_mounted"`
	DatabasePublic       bool   `json:"database_public"`
	WorkflowPublic       bool   `json:"workflow_public"`
	SecretsInEnvironment bool   `json:"secrets_in_environment"`
}

type Connectivity struct {
	Mode                ConnectivityMode `json:"mode"`
	EndpointReferences  []string         `json:"endpoint_references"`
	DNSAllowed          bool             `json:"dns_allowed"`
	InternetAllowed     bool             `json:"internet_allowed"`
	TelemetryAllowed    bool             `json:"telemetry_allowed"`
	UpdatesAllowed      bool             `json:"updates_allowed"`
	ExternalTimeAllowed bool             `json:"external_time_allowed"`
}

type Identities struct {
	ControlPlane string `json:"control_plane"`
	Workflow     string `json:"workflow"`
	Database     string `json:"database"`
}

type ComposeSpec struct {
	Enabled       bool              `json:"enabled"`
	Provider      string            `json:"provider"`
	ImageDigests  map[string]string `json:"image_digests"`
	MigrationsRun bool              `json:"migrations_run"`
	ValidatorsRun bool              `json:"validators_run"`
}

type AirGapSpec struct {
	BundleManifestDigest string `json:"bundle_manifest_digest"`
	SignedPackages       bool   `json:"signed_packages"`
	OCIArchives          bool   `json:"oci_archives"`
	Policies             bool   `json:"policies"`
	Validators           bool   `json:"validators"`
	SBOMs                bool   `json:"sboms"`
	Provenance           bool   `json:"provenance"`
	OfflineFeeds         bool   `json:"offline_feeds"`
	VerificationTools    bool   `json:"verification_tools"`
}

// Decision is safe to persist as audit input. It contains only enum-like
// reason data and digests; it never echoes operator-provided values.
type Decision struct {
	SchemaVersion   string           `json:"schema_version"`
	ContractVersion string           `json:"contract_version"`
	ConfigDigest    string           `json:"config_digest,omitempty"`
	DecisionDigest  string           `json:"decision_digest"`
	Outcome         string           `json:"outcome"`
	ReasonCode      string           `json:"reason_code"`
	OrganizationID  string           `json:"organization_id,omitempty"`
	ActorID         string           `json:"actor_id,omitempty"`
	Revision        uint64           `json:"revision,omitempty"`
	Deployment      DeploymentKind   `json:"deployment,omitempty"`
	Connectivity    ConnectivityMode `json:"connectivity,omitempty"`
	Replayed        bool             `json:"replayed"`
}

// AuthoritySnapshot is supplied by the authentication boundary. This package
// binds it to the profile change but does not authenticate the actor itself.
type AuthoritySnapshot struct {
	OrganizationID      string
	ActorID             string
	Active              bool
	CurrentRevision     uint64
	CurrentConfigDigest string
}

// AuditSink must durably accept the redacted decision before validation can
// authorize startup composition.
type AuditSink interface {
	AppendProfileDecision(context.Context, Decision) error
}
