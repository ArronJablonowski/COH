package securityonion

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const OQLValidatorVersion = "security-onion-oql-1.0.0"

type OQLColumn struct {
	LogicalName string
	VendorName  string
	Type        string
}

type OQLPlan struct {
	QueryID               string
	SourceID              string
	ResourceID            string
	Mode                  string
	RenderedQuery         string
	CallerFilterDigest    string
	MandatoryFilterDigest string
	Range                 string
	Zone                  string
	Format                string
	Columns               []OQLColumn
	TimestampColumn       string
	GroupBy               []OQLColumn
	EventLimit            uint64
	MetricLimit           uint64
	MaximumBytes          uint64
	MaximumDurationMillis uint64
	QualificationDigest   string
	PlanDigest            string
}

type ValidatedOQLPlan struct {
	value  OQLPlan
	digest string
}

func (plan ValidatedOQLPlan) Value() OQLPlan {
	value := plan.value
	value.Columns = append([]OQLColumn(nil), plan.value.Columns...)
	value.GroupBy = append([]OQLColumn(nil), plan.value.GroupBy...)
	return value
}

func (plan ValidatedOQLPlan) Digest() string { return plan.digest }

type OQLCompiler struct {
	config Config
	clock  Clock
}

func NewOQLCompiler(config Config, clock Clock) (*OQLCompiler, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if clock == nil {
		return nil, invalid("securityonion_oql_clock_required")
	}
	return &OQLCompiler{config: cloneConfig(config), clock: clock}, nil
}

func (compiler *OQLCompiler) Validate(ctx context.Context, query queryconnector.ValidatedQuery,
	schema queryconnector.ValidatedSchemaPage, qualification ValidatedQualification) (
	queryconnector.ValidatedValidation, *ValidatedOQLPlan, error) {
	return compiler.validateOQL(ctx, query, schema, qualification)
}
