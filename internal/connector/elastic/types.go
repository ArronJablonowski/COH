// Package elastic implements the bounded Elastic discovery surface used by
// COH's read-only query broker.
package elastic

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const (
	AdapterContractVersion = "1.0.0"
	maximumResources       = 256
	maximumFields          = 4096
)

// Config is admitted deployment configuration. Resource IDs are COH logical
// names; expressions and vendor field names never cross the query SPI.
type Config struct {
	SourceID                string
	AdapterVersion          string
	Deployment              string
	Endpoint                string
	ExpectedClusterUUID     string
	MinimumMajorVersion     uint32
	MaximumMajorVersion     uint32
	QualifiedMinorVersions  []string
	TransportIdentityDigest string
	Resources               []Resource
	Fields                  []Field
	HardLimits              queryconnector.Limits
	CapabilityLifetime      time.Duration
}

type Resource struct {
	ID         string
	Expression string
}

type Field struct {
	VendorName string
	SchemaName string
}

// Client is deliberately narrower than HTTP or an Elastic SDK. Implementations
// own credential-lease consumption, authenticated TLS, response bounds, and
// redacted transport evidence.
type Client interface {
	Inspect(context.Context, CallBinding) (ClusterIdentity, CallReceipt, error)
	Resolve(context.Context, ResolveRequest) (ResolveResult, CallReceipt, error)
	FieldCapabilities(context.Context, FieldCapabilitiesRequest) (FieldCapabilitiesResult, CallReceipt, error)
}

type Clock interface {
	Now() time.Time
}

type CallBinding struct {
	Scope     queryconnector.Scope
	Authority queryconnector.AuthorityBinding
	Operation string
	Targets   []string
}

type ClusterIdentity struct {
	ClusterUUID string
	Version     string
	BuildFlavor string
	BuildHash   string
	Snapshot    bool
}

type CallReceipt struct {
	RequestDigest       string
	ResponseDigest      string
	LeaseDecisionDigest string
	TransportDigest     string
}

type ResolveRequest struct {
	Binding    CallBinding
	Expression string
	Expand     string
}

type ResolveResult struct {
	Indices     []ResolvedTarget
	Aliases     []ResolvedAlias
	DataStreams []ResolvedDataStream
}

type ResolvedTarget struct {
	Name       string
	Attributes []string
}

type ResolvedAlias struct {
	Name    string
	Indices []string
}

type ResolvedDataStream struct {
	Name           string
	BackingIndices []string
}

type FieldCapabilitiesRequest struct {
	Binding           CallBinding
	Indices           []string
	Fields            []string
	AllowNoIndices    bool
	IgnoreUnavailable bool
	ExpandWildcards   string
	IncludeUnmapped   bool
}

type FieldCapabilitiesResult struct {
	Indices []string
	Fields  []FieldCapability
}

type FieldCapability struct {
	Name         string
	Type         string
	Indices      []string
	Searchable   bool
	Aggregatable bool
}
