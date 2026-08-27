// Package elasticquerydsl compiles a strict Query DSL-shaped JSON subset into
// an immutable bounded export plan for the Elastic adapter.
package elasticquerydsl

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const (
	ContractVersion  = "1.0.0"
	ValidatorVersion = "elastic-query-dsl-1.0.0"

	maximumInputBytes = 262144
	maximumDepth      = 16
	maximumClauses    = 1024
	maximumTerms      = 256
)

type Definition struct {
	SourceID         string
	Resources        []string
	Fields           []FieldRule
	Projection       []string
	StableSort       []SortField
	TimestampField   string
	TenantField      string
	SourceField      string
	HardMaximumRows  uint64
	HardMaximumPages uint32
	HardPageRows     uint64
}

type FieldRule struct {
	Name           string
	VendorName     string
	Type           string
	Projectable    bool
	Exact          bool
	Range          bool
	Exists         bool
	TextSearchable bool
	Sortable       bool
}

type SortField struct {
	Name       string
	VendorName string
	Type       string
	Direction  string
}

type Column struct {
	LogicalName string
	VendorName  string
	Type        string
}

type Plan struct {
	QueryID               string
	SourceID              string
	ResourceID            string
	CanonicalQuery        map[string]any
	CallerQueryDigest     string
	MandatoryFilterDigest string
	Columns               []Column
	Sort                  []SortField
	MaximumRows           uint64
	MaximumPages          uint32
	PageRows              uint64
	MaximumBytes          uint64
	MaximumDurationMillis uint64
	PlanDigest            string
}

type ValidatedPlan struct {
	value  Plan
	digest string
}

func (plan ValidatedPlan) Value() Plan {
	cloned := plan.value
	cloned.CanonicalQuery, _ = cloneValue(plan.value.CanonicalQuery).(map[string]any)
	cloned.Columns = append([]Column(nil), plan.value.Columns...)
	cloned.Sort = append([]SortField(nil), plan.value.Sort...)
	return cloned
}

func (plan ValidatedPlan) Digest() string { return plan.digest }

type Compiler struct{ definition Definition }

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

func cloneValue(value any) any {
	switch current := value.(type) {
	case map[string]any:
		cloned := make(map[string]any, len(current))
		for key, item := range current {
			cloned[key] = cloneValue(item)
		}
		return cloned
	case []any:
		cloned := make([]any, len(current))
		for index, item := range current {
			cloned[index] = cloneValue(item)
		}
		return cloned
	default:
		return current
	}
}
