package elasticesql

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (compiler *Compiler) validate(ctx context.Context, query queryconnector.ValidatedQuery,
	schema queryconnector.ValidatedSchemaPage) (queryconnector.ValidatedValidation, *ValidatedPlan, error) {
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedValidation{}, nil, err
	}
	if compiler == nil {
		return queryconnector.ValidatedValidation{}, nil,
			queryconnector.NewError(queryconnector.InvalidInput, "esql_compiler_required", nil)
	}
	queryValue, schemaValue := query.Value(), schema.Value()
	if query.Digest() == "" || schema.Digest() == "" || queryValue.Language != "esql" ||
		queryValue.Scope.SourceID != compiler.definition.SourceID || len(queryValue.Scope.ResourceIDs) != 1 ||
		queryValue.SchemaDigest != schemaValue.SchemaDigest || !schemaValue.Complete || schemaValue.NextCursor != nil {
		return compiler.denied(ctx, query, "esql_binding_invalid", ""), nil, nil
	}
	if err := compiler.validateSchema(queryValue.Scope.ResourceIDs[0], schemaValue); err != nil {
		return compiler.denied(ctx, query, reason(err), ""), nil, nil
	}
	parsed, err := parse(ctx, compiler.definition, queryValue.NativeText)
	if err != nil {
		var semantic *denial
		if errors.As(err, &semantic) {
			return compiler.denied(ctx, query, semantic.reason, ""), nil, nil
		}
		return queryconnector.ValidatedValidation{}, nil, err
	}
	if parsed.resource != queryValue.Scope.ResourceIDs[0] {
		return compiler.denied(ctx, query, "esql_resource_scope_mismatch", ""), nil, nil
	}
	plan, err := compiler.buildPlan(ctx, query, parsed)
	if err != nil {
		var semantic *denial
		if errors.As(err, &semantic) {
			return compiler.denied(ctx, query, semantic.reason, ""), nil, nil
		}
		return queryconnector.ValidatedValidation{}, nil, err
	}
	validated := &ValidatedPlan{value: plan, digest: plan.PlanDigest}
	return compiler.accepted(ctx, query, plan.PlanDigest), validated, nil
}

func (compiler *Compiler) validateSchema(resource string, schema queryconnector.SchemaPage) error {
	if !slices.Contains(compiler.definition.Resources, resource) || len(schema.Entries) == 0 {
		return deny("esql_schema_scope_invalid")
	}
	allowed := make(map[string]string, len(compiler.definition.Fields))
	for _, field := range compiler.definition.Fields {
		allowed[field.Name] = field.Type
	}
	seen := make(map[string]struct{}, len(schema.Entries))
	for _, entry := range schema.Entries {
		if entry.ResourceID != resource {
			return deny("esql_schema_scope_invalid")
		}
		expected, ok := allowed[entry.Name]
		if !ok || expected != entry.Type {
			return deny("esql_schema_field_mismatch")
		}
		seen[entry.Name] = struct{}{}
	}
	for _, field := range compiler.definition.Fields {
		if _, ok := seen[field.Name]; !ok {
			return deny("esql_schema_field_missing")
		}
	}
	return nil
}

func (compiler *Compiler) buildPlan(ctx context.Context, query queryconnector.ValidatedQuery, parsed pipeline) (Plan, error) {
	queryValue := query.Value()
	projection := append([]string(nil), parsed.projection...)
	if len(projection) == 0 {
		projection = append(projection, compiler.definition.DefaultProjection...)
	}
	for _, stable := range compiler.definition.StableSort {
		if !slices.Contains(projection, stable.Name) {
			projection = append(projection, stable.Name)
		}
	}
	sortFields := append([]SortField(nil), parsed.sort...)
	for _, stable := range compiler.definition.StableSort {
		found := false
		for _, current := range sortFields {
			if current.Name == stable.Name {
				found = true
				break
			}
		}
		if !found {
			sortFields = append(sortFields, stable)
		}
	}
	if len(projection) > 256 || len(sortFields) > 8 {
		return Plan{}, deny("esql_output_shape_limit")
	}
	maximumRows := min(queryValue.Limits.MaximumRows, compiler.definition.HardMaximumRows)
	if parsed.limit > 0 {
		maximumRows = min(maximumRows, parsed.limit)
	}
	if maximumRows == 0 {
		return Plan{}, deny("esql_limit_invalid")
	}
	parameters := make([]Parameter, 0, 8)
	expressionText := ""
	if parsed.expression != nil {
		var err error
		expressionText, err = compiler.canonicalExpression(ctx, parsed.expression, &parameters)
		if err != nil {
			return Plan{}, err
		}
	}
	filter := compiler.mandatoryFilter(queryValue)
	filterDigest := digest("COH-ELASTIC-ESQL-FILTER-V1\x00", filter)
	pipelineText := compiler.canonicalPipeline(parsed.resource, expressionText, projection, sortFields, maximumRows)
	plan := Plan{QueryID: queryValue.QueryID, SourceID: queryValue.Scope.SourceID, ResourceID: parsed.resource,
		CanonicalPipeline: pipelineText, Parameters: parameters, Projection: projection, Sort: sortFields,
		MaximumRows: maximumRows, MandatoryFilter: filter, FilterDigest: filterDigest}
	plan.PlanDigest = digest("COH-ELASTIC-ESQL-PLAN-V1\x00", struct {
		QueryDigest  string
		SchemaDigest string
		Authority    queryconnector.AuthorityBinding
		Plan         Plan
	}{query.Digest(), queryValue.SchemaDigest, queryValue.Authority, plan})
	return plan, nil
}

func (compiler *Compiler) mandatoryFilter(query queryconnector.Query) map[string]any {
	filters := []any{map[string]any{"range": map[string]any{compiler.field(compiler.definition.TimestampField).VendorName: map[string]any{
		"format": "strict_date_optional_time_nanos", "gte": query.TimeRange.Start, "lt": query.TimeRange.End}}}}
	if compiler.definition.TenantField != "" {
		filters = append(filters, map[string]any{"term": map[string]any{compiler.field(compiler.definition.TenantField).VendorName: query.Scope.TenantID}})
	}
	if compiler.definition.SourceField != "" {
		filters = append(filters, map[string]any{"term": map[string]any{compiler.field(compiler.definition.SourceField).VendorName: query.Scope.SourceID}})
	}
	return map[string]any{"bool": map[string]any{"filter": filters}}
}

func (compiler *Compiler) canonicalExpression(ctx context.Context, value expression, parameters *[]Parameter) (string, error) {
	if err := contextError(ctx); err != nil {
		return "", err
	}
	if len(*parameters) >= maximumParameters {
		return "", deny("esql_parameter_limit")
	}
	switch current := value.(type) {
	case comparison:
		field := compiler.field(current.field)
		parameter, err := typedParameter(field.Type, current.value)
		if err != nil {
			return "", err
		}
		*parameters = append(*parameters, parameter)
		return field.VendorName + " " + current.operator + " ?", nil
	case logical:
		left, err := compiler.canonicalExpression(ctx, current.left, parameters)
		if err != nil {
			return "", err
		}
		right, err := compiler.canonicalExpression(ctx, current.right, parameters)
		if err != nil {
			return "", err
		}
		return "(" + left + " " + current.operator + " " + right + ")", nil
	case negation:
		child, err := compiler.canonicalExpression(ctx, current.child, parameters)
		if err != nil {
			return "", err
		}
		return "NOT (" + child + ")", nil
	default:
		return "", deny("esql_expression_invalid")
	}
}

func typedParameter(kind string, value any) (Parameter, error) {
	switch kind {
	case "string":
		return Parameter{Type: kind, Value: value}, nil
	case "integer":
		return Parameter{Type: kind, Value: value}, nil
	case "boolean":
		return Parameter{Type: kind, Value: value}, nil
	case "ip":
		text, ok := value.(string)
		if !ok || net.ParseIP(text) == nil {
			return Parameter{}, deny("esql_ip_invalid")
		}
		return Parameter{Type: kind, Value: text}, nil
	case "timestamp":
		text, ok := value.(string)
		if !ok {
			return Parameter{}, deny("esql_timestamp_invalid")
		}
		parsed, err := time.Parse(time.RFC3339Nano, text)
		if err != nil || parsed.Location() != time.UTC {
			return Parameter{}, deny("esql_timestamp_invalid")
		}
		return Parameter{Type: kind, Value: parsed.UTC().Format(time.RFC3339Nano)}, nil
	default:
		return Parameter{}, deny("esql_literal_type_unsupported")
	}
}

func (compiler *Compiler) field(name string) FieldRule {
	for _, field := range compiler.definition.Fields {
		if field.Name == name {
			return field
		}
	}
	return FieldRule{}
}

func (compiler *Compiler) canonicalPipeline(resource, expression string, projection []string, sortFields []SortField, limit uint64) string {
	var output strings.Builder
	output.WriteString("FROM ")
	output.WriteString(resource)
	if expression != "" {
		output.WriteString(" | WHERE ")
		output.WriteString(expression)
	}
	output.WriteString(" | KEEP ")
	vendorProjection := make([]string, len(projection))
	for index, name := range projection {
		vendorProjection[index] = compiler.field(name).VendorName
	}
	output.WriteString(strings.Join(vendorProjection, ", "))
	if len(sortFields) != 0 {
		output.WriteString(" | SORT ")
		for index, field := range sortFields {
			if index > 0 {
				output.WriteString(", ")
			}
			output.WriteString(compiler.field(field.Name).VendorName)
			output.WriteByte(' ')
			output.WriteString(field.Direction)
		}
	}
	output.WriteString(" | LIMIT ")
	output.WriteString(strconv.FormatUint(limit, 10))
	return output.String()
}

func (compiler *Compiler) accepted(ctx context.Context, query queryconnector.ValidatedQuery, provenance string) queryconnector.ValidatedValidation {
	return validation(ctx, query, "accepted", nil, provenance)
}

func (compiler *Compiler) denied(ctx context.Context, query queryconnector.ValidatedQuery, reasonCode, provenance string) queryconnector.ValidatedValidation {
	if provenance == "" {
		provenance = digest("COH-ELASTIC-ESQL-DENIAL-V1\x00", struct {
			Query  string
			Reason string
		}{query.Digest(), reasonCode})
	}
	return validation(ctx, query, "denied", []string{reasonCode}, provenance)
}

func validation(ctx context.Context, query queryconnector.ValidatedQuery, outcome string, reasons []string, provenance string) queryconnector.ValidatedValidation {
	value := queryconnector.ValidationResult{SchemaVersion: queryconnector.ValidationSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: query.Value().QueryID, Outcome: outcome,
		ReasonCodes: reasons, ValidatorVersion: ValidatorVersion, CanonicalQueryDigest: query.Digest(),
		ProvenanceDigest: provenance}
	encoded, _ := json.Marshal(value)
	validated, _ := queryconnector.DecodeValidation(ctx, encoded)
	return validated
}

func reason(err error) string {
	var semantic *denial
	if errors.As(err, &semantic) {
		return semantic.reason
	}
	return "esql_validation_unavailable"
}
