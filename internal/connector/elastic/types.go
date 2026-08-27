// Package elastic implements the bounded Elastic discovery surface used by
// COH's read-only query broker.
package elastic

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/connector/elasticesql"
	"github.com/ArronJablonowski/COH/internal/connector/elasticquerydsl"
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
	SourceID                    string
	AdapterVersion              string
	Deployment                  string
	Endpoint                    string
	ExpectedClusterUUID         string
	ExpectedBuildFlavor         string
	MinimumMajorVersion         uint32
	MaximumMajorVersion         uint32
	QualifiedMinorVersions      []string
	TransportIdentityDigest     string
	Resources                   []Resource
	Fields                      []Field
	HardLimits                  queryconnector.Limits
	CapabilityLifetime          time.Duration
	MaximumSchemaEntriesPerPage int
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

type ESQLClient interface {
	ExecuteESQL(context.Context, ESQLRequest) (ESQLResult, CallReceipt, error)
}

type QueryDSLClient interface {
	ValidateQuery(context.Context, QueryValidationRequest) (QueryValidationResult, CallReceipt, error)
	OpenPIT(context.Context, OpenPITRequest) (PITResult, CallReceipt, error)
	SearchPIT(context.Context, SearchPITRequest) (SearchPITResult, CallReceipt, error)
	ClosePIT(context.Context, ClosePITRequest) (ClosePITResult, CallReceipt, error)
}

// CredentialSource resolves and consumes one broker-owned credential lease per
// call. Implementations must destroy the temporary bytes after consumer
// returns and return the immutable allowed decision digest.
type CredentialSource interface {
	Use(context.Context, CallBinding, func([]byte) error) (string, error)
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

type ESQLRequest struct {
	Binding CallBinding
	Indices []string
	Plan    elasticesql.ValidatedPlan
}

type ESQLResult struct {
	Columns        []elasticesql.Column
	Rows           []map[string]any
	TookMillis     uint64
	DocumentsFound uint64
	ValuesLoaded   uint64
	ResultDigest   string
}

type QueryValidationRequest struct {
	Binding CallBinding
	Indices []string
	Plan    elasticquerydsl.ValidatedPlan
}

type QueryValidationResult struct {
	Valid        bool
	TotalShards  uint64
	FailedShards uint64
	ResultDigest string
}

type OpenPITRequest struct {
	Binding   CallBinding
	Indices   []string
	Plan      elasticquerydsl.ValidatedPlan
	KeepAlive time.Duration
}

type PITResult struct {
	ID           string
	TotalShards  uint64
	FailedShards uint64
	PITDigest    string
}

type SearchPITRequest struct {
	Binding     CallBinding
	Indices     []string
	Plan        elasticquerydsl.ValidatedPlan
	PITID       string
	KeepAlive   time.Duration
	Size        uint64
	SearchAfter []any
}

type SearchHit struct {
	Row  map[string]any
	Sort []any
}

type SearchPITResult struct {
	PITID        string
	PITDigest    string
	Hits         []SearchHit
	TookMillis   uint64
	TotalShards  uint64
	ResultDigest string
}

type ClosePITRequest struct {
	Binding CallBinding
	Indices []string
	PITID   string
}

type ClosePITResult struct {
	Succeeded    bool
	Freed        uint64
	ResultDigest string
}
