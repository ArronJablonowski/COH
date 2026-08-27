// Package elasticesql compiles a deliberately small ES|QL subset into a
// bounded, parameterized logical plan for the Elastic adapter.
package elasticesql

import (
	"context"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const (
	ContractVersion  = "1.0.0"
	ValidatorVersion = "elastic-esql-1.0.0"

	maximumInputBytes = 65536
	maximumTokens     = 4096
	maximumCommands   = 5
	maximumDepth      = 16
	maximumParameters = 256
)

type Definition struct {
	SourceID          string
	Resources         []string
	Fields            []FieldRule
	DefaultProjection []string
	StableSort        []SortField
	TimestampField    string
	TenantField       string
	SourceField       string
	HardMaximumRows   uint64
}

type FieldRule struct {
	Name        string
	VendorName  string
	Type        string
	Projectable bool
	Filterable  bool
	Sortable    bool
}

type SortField struct {
	Name      string
	Direction string
}

type Plan struct {
	QueryID           string
	SourceID          string
	ResourceID        string
	CanonicalPipeline string
	Parameters        []Parameter
	Projection        []string
	Sort              []SortField
	MaximumRows       uint64
	MandatoryFilter   map[string]any
	FilterDigest      string
	PlanDigest        string
}

type ValidatedPlan struct {
	value  Plan
	digest string
}

func (plan ValidatedPlan) Value() Plan {
	encoded, _ := json.Marshal(plan.value)
	var cloned Plan
	_ = json.Unmarshal(encoded, &cloned)
	return cloned
}

func (plan ValidatedPlan) Digest() string { return plan.digest }

type Parameter struct {
	Type  string
	Value any
}

type Compiler struct {
	definition Definition
}

func New(definition Definition) (*Compiler, error) {
	validated, err := validateDefinition(definition)
	if err != nil {
		return nil, err
	}
	return &Compiler{definition: validated}, nil
}

func (compiler *Compiler) Validate(ctx context.Context, query queryconnector.ValidatedQuery,
	schema queryconnector.ValidatedSchemaPage) (queryconnector.ValidatedValidation, *ValidatedPlan, error) {
	return compiler.validate(ctx, query, schema)
}
