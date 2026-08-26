// Package ociexecutor implements the optional least-privilege OCI execution boundary.
package ociexecutor

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/toolregistry"
)

const (
	MaximumRegistrations = 1024
	MaximumArguments     = 128
	MaximumArgumentBytes = 4096
	MaximumInputBytes    = 1 << 20
	MaximumMounts        = 16
)

type Resolver interface {
	ResolveOperation(context.Context, toolregistry.ToolReference, string, string, string,
		toolregistry.PublisherAuthority) (toolregistry.Capability, error)
}

type AuthorizationRequest struct {
	AttemptID      string
	OrganizationID string
	TenantID       string
	CaseID         string
	ActorID        string
	Tool           toolregistry.ToolReference
	Operation      string
	RequiredTier   string
	InputDigest    string
}

type DispatchAuthority struct {
	AuthorizationID string
	DecisionDigest  string
	Request         AuthorizationRequest
	RuntimeCeiling  string
	AuthorizedAt    string
	ValidUntil      string
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (DispatchAuthority, error)
}

type Clock interface{ Now() time.Time }

type EnvironmentVariable struct {
	Name  string
	Value string
}

// WritableMount is always an in-memory mount created by the runtime. Host
// paths, named volumes, devices, and sockets are intentionally unrepresentable.
type WritableMount struct {
	Destination string
	Bytes       uint64
}

// Registration is trusted deployment configuration. ImageDigest must be the
// signed tool artifact digest. Callers cannot choose an image or command.
type Registration struct {
	Tool             toolregistry.ToolReference
	Operation        string
	ImageRepository  string
	ImageDigest      string
	Entrypoint       string
	FixedArguments   []string
	HealthArguments  []string
	FixedEnvironment []EnvironmentVariable
	RunAsUser        uint32
	RunAsGroup       uint32
	WritableMounts   []WritableMount
}

type InputValue struct {
	Kind    string
	Boolean bool
	Integer int64
	String  string
	Strings []string
}

type Request struct {
	AttemptID      string
	OrganizationID string
	TenantID       string
	CaseID         string
	ActorID        string
	Tool           toolregistry.ToolReference
	Operation      string
	RequiredTier   string
	Publisher      toolregistry.PublisherAuthority
	Inputs         map[string]InputValue
}

type NetworkRequest struct {
	AttemptID       string
	OrganizationID  string
	TenantID        string
	CaseID          string
	ActorID         string
	AuthorizationID string
	AuthorityUntil  string
	Policy          toolregistry.NetworkPolicy
	PolicyDigest    string
}

// NetworkLease is returned by the broker-owned egress enforcer. EngineNetwork
// is an opaque pre-provisioned network name; the executor never constructs
// firewall policy itself or falls back to a default bridge.
type NetworkLease struct {
	LeaseID           string
	Request           NetworkRequest
	EngineNetwork     string
	EnforcementDigest string
	AuthorizedAt      string
	ValidUntil        string
	Cleanup           func() error
}

type NetworkBroker interface {
	Acquire(context.Context, NetworkRequest) (NetworkLease, error)
}

type ContainerPlan struct {
	AttemptID         string
	ImageReference    string
	ImageDigest       string
	Entrypoint        string
	Arguments         []string
	HealthArguments   []string
	Environment       []string
	Input             []byte
	RunAsUser         uint32
	RunAsGroup        uint32
	WorkingDirectory  string
	WritableMounts    []WritableMount
	Limits            toolregistry.ResourceLimits
	Network           toolregistry.NetworkPolicy
	EngineNetwork     string
	NetworkPolicyHash string
}

type StreamEvidence struct {
	Digest    string
	Length    uint64
	Truncated bool
}

type RuntimeResult struct {
	ExitCode            int
	TerminationSignal   string
	StandardOutput      []byte
	StandardError       []byte
	OutputTruncated     bool
	ResolvedImageDigest string
	ContainerSpecDigest string
	HealthCommandDigest string
	HealthOutcome       string
	RuntimeDigest       string
	CleanupComplete     bool
}

// Runtime must create, start, stop, and remove a container without a shell. It
// returns evidence proving image, spec, health, runtime, and cleanup bindings.
type Runtime interface {
	Execute(context.Context, ContainerPlan) (RuntimeResult, error)
}

type Provenance struct {
	AttemptID              string
	OrganizationID         string
	TenantID               string
	CaseID                 string
	ActorID                string
	AuthorizationID        string
	PolicyDecisionDigest   string
	ManifestDigest         string
	ManifestID             string
	Tool                   toolregistry.ToolReference
	Operation              string
	RequiredTier           string
	EffectiveCeiling       string
	ImageReferenceDigest   string
	ResolvedImageDigest    string
	EntrypointDigest       string
	ArgumentDigest         string
	EnvironmentDigest      string
	InputDigest            string
	MountDigest            string
	NetworkPolicyDigest    string
	NetworkEnforcementHash string
	ContainerSpecDigest    string
	HealthCommandDigest    string
	HealthOutcome          string
	RuntimeDigest          string
	StartedAt              string
	FinishedAt             string
	Outcome                string
	Reason                 string
	ExitCode               int
	TerminationSignal      string
	StandardOutput         StreamEvidence
	StandardError          StreamEvidence
	CleanupComplete        bool
	Replayed               bool
}

type Result struct {
	StandardOutput []byte
	StandardError  []byte
	Provenance     Provenance
}
