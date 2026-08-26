// Package nativeexecutor implements the low-risk native execution boundary.
package nativeexecutor

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
)

// Resolver is deliberately the signed registry's narrow operation surface.
// Execution never accepts a caller-constructed capability.
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

// Authorizer is broker-owned current policy authority. The executor calls it
// for every new attempt; callers cannot supply a policy ceiling in Request.
type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (DispatchAuthority, error)
}

type Clock interface{ Now() time.Time }

type EnvironmentVariable struct {
	Name  string
	Value string
}

// Registration is trusted deployment configuration. Inputs are encoded as
// canonical JSON on stdin; they can never become executable names or argv.
type Registration struct {
	Tool             toolregistry.ToolReference
	Operation        string
	ExecutablePath   string
	FixedArguments   []string
	FixedEnvironment []EnvironmentVariable
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

type PreparedArtifact struct {
	Path    string
	Digest  string
	Cleanup func() error
}

type ArtifactPreparer interface {
	Prepare(context.Context, string, string, uint64) (PreparedArtifact, error)
}

// Plan is an already-authorized, artifact-verified sandbox request. A sandbox
// implementation must enforce every supplied bound or return Denied before
// starting a process.
type Plan struct {
	ExecutablePath string
	ArtifactDigest string
	Arguments      []string
	Environment    []string
	Input          []byte
	Limits         toolregistry.ResourceLimits
	Network        toolregistry.NetworkPolicy
}

type SandboxResult struct {
	ExitCode          int
	TerminationSignal string
	StandardOutput    []byte
	StandardError     []byte
	OutputTruncated   bool
}

type Sandbox interface {
	Execute(context.Context, Plan) (SandboxResult, error)
}

type StreamEvidence struct {
	Digest    string
	Length    uint64
	Truncated bool
}

type Provenance struct {
	AttemptID            string
	OrganizationID       string
	TenantID             string
	CaseID               string
	ActorID              string
	AuthorizationID      string
	PolicyDecisionDigest string
	ManifestDigest       string
	ManifestID           string
	Tool                 toolregistry.ToolReference
	Operation            string
	RequiredTier         string
	EffectiveCeiling     string
	ArtifactDigest       string
	ArgumentDigest       string
	EnvironmentDigest    string
	InputDigest          string
	StartedAt            string
	FinishedAt           string
	Outcome              string
	Reason               string
	ExitCode             int
	TerminationSignal    string
	StandardOutput       StreamEvidence
	StandardError        StreamEvidence
	Replayed             bool
}

type Result struct {
	StandardOutput []byte
	StandardError  []byte
	Provenance     Provenance
}
