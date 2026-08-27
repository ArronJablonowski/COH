// Package elasticesql compiles a deliberately small ES|QL subset into a
// bounded, parameterized logical plan for the Elastic adapter.
package elasticesql

import (
	"context"

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
	QueryID               string
	SourceID              string
	ResourceID            string
	CanonicalPipeline     string
	Parameters            []Parameter
	Projection            []string
	Columns               []Column
	Sort                  []SortField
	MaximumRows           uint64
	MaximumBytes          uint64
	MaximumDurationMillis uint64
	MandatoryFilter       map[string]any
	FilterDigest          string
	PlanDigest            string
}

type Column struct {
	LogicalName string
	VendorName  string
	Type        string
}

type ValidatedPlan struct {
	value  Plan
	digest string
}

func (plan ValidatedPlan) Value() Plan {
	cloned := plan.value
	cloned.Parameters = append([]Parameter(nil), plan.value.Parameters...)
	cloned.Projection = append([]string(nil), plan.value.Projection...)
	cloned.Columns = append([]Column(nil), plan.value.Columns...)
	cloned.Sort = append([]SortField(nil), plan.value.Sort...)
	cloned.MandatoryFilter, _ = cloneValue(plan.value.MandatoryFilter).(map[string]any)
	return cloned
}

func (plan ValidatedPlan) Digest() string { return plan.digest }

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
