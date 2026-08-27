package schemacache

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const (
	ContractVersion          = "1.0.0"
	SchemaVersion            = "coh.schema-cache-entry/v1"
	MaximumConfiguredEntries = 4096
	MaximumConfiguredBytes   = 256 << 20
	MaximumConfiguredTTL     = time.Hour
	MaximumLoadTimeout       = 2 * time.Minute
)

type Config struct {
	MaximumEntries    int
	MaximumTotalBytes int
	MaximumEntryBytes int
	TTL               time.Duration
	LoadTimeout       time.Duration
}

type Request struct {
	SchemaRequest queryconnector.SchemaRequest
	Capability    queryconnector.ValidatedCapability
}

// Loader is intentionally narrower than a connector or transport. The caller
// composes current authority before calling Cache.Get; the cache never creates
// or widens that authority.
type Loader interface {
	LoadSchema(context.Context, queryconnector.SchemaRequest) (queryconnector.ValidatedSchemaPage, error)
}

type Clock interface {
	Now() time.Time
}

type Snapshot struct {
	page           queryconnector.ValidatedSchemaPage
	identityDigest string
	cachedAt       time.Time
	expiresAt      time.Time
	hit            bool
}

func (snapshot Snapshot) Page() queryconnector.ValidatedSchemaPage { return snapshot.page }
func (snapshot Snapshot) IdentityDigest() string                   { return snapshot.identityDigest }
func (snapshot Snapshot) CachedAt() time.Time                      { return snapshot.cachedAt }
func (snapshot Snapshot) ExpiresAt() time.Time                     { return snapshot.expiresAt }
func (snapshot Snapshot) Hit() bool                                { return snapshot.hit }

type Invalidation struct {
	OrganizationID   string
	TenantID         string
	SourceID         string
	CapabilityDigest string
	AdapterVersion   string
	SchemaVersion    string
}
