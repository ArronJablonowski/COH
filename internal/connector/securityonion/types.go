// Package securityonion implements the bounded Security Onion Connect query
// boundary used by COH's read-only query broker.
package securityonion

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const ContractVersion = "1.0.0"

type Config struct {
	SourceID                string
	AdapterVersion          string
	Endpoint                string
	CredentialReference     string
	TLSRootDigest           string
	TransportIdentityDigest string
	Permissions             []string
	Resources               []Resource
	Fields                  []Field
	HardLimits              queryconnector.Limits
	MaximumInterval         time.Duration
	MaximumEventLimit       uint64
	MaximumMetricLimit      uint64
	MaximumOpenAPIBytes     uint64
	QualificationLifetime   time.Duration
}

type Resource struct{ ID string }

type Field struct {
	LogicalName string
	VendorName  string
	Type        string
	Exact       bool
	Range       bool
	Exists      bool
	Projectable bool
	Groupable   bool
	Sortable    bool
}

type Operation struct {
	Method             string
	Path               string
	RequiredParameters []string
	ResponseMediaType  string
	ResponseType       string
}

type Qualification struct {
	SourceID       string
	OpenAPIDigest  string
	OpenAPIVersion string
	SecurityScheme string
	Operations     []Operation
	ObservedAt     string
	ValidUntil     string
	Digest         string
}

type ValidatedQualification struct {
	value  Qualification
	digest string
}

func (value ValidatedQualification) Value() Qualification {
	result := value.value
	result.Operations = append([]Operation(nil), value.value.Operations...)
	for index := range result.Operations {
		result.Operations[index].RequiredParameters = append([]string(nil), value.value.Operations[index].RequiredParameters...)
	}
	return result
}

func (value ValidatedQualification) Digest() string { return value.digest }

type Clock interface{ Now() time.Time }

type Qualifier struct {
	config Config
	clock  Clock
}

func NewQualifier(config Config, clock Clock) (*Qualifier, error) {
	if err := validateConfig(config); err != nil || clock == nil {
		if err != nil {
			return nil, err
		}
		return nil, invalid("securityonion_clock_required")
	}
	return &Qualifier{config: cloneConfig(config), clock: clock}, nil
}

func (qualifier *Qualifier) Qualify(ctx context.Context, document []byte) (ValidatedQualification, error) {
	return qualifier.qualify(ctx, document)
}
