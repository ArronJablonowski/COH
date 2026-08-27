package elasticquerydsl

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

func (compiler *Compiler) validate(ctx context.Context, query queryconnector.ValidatedQuery,
	schema queryconnector.ValidatedSchemaPage) (queryconnector.ValidatedValidation, *ValidatedPlan, error) {
	if err := contextError(ctx); err != nil {
		return queryconnector.ValidatedValidation{}, nil, err
	}
	if compiler == nil {
		return queryconnector.ValidatedValidation{}, nil,
			queryconnector.NewError(queryconnector.InvalidInput, "querydsl_compiler_required", nil)
	}
	queryValue, schemaValue := query.Value(), schema.Value()
	if query.Digest() == "" || schema.Digest() == "" || queryValue.Language != "elastic-query-dsl" ||
		queryValue.Scope.SourceID != compiler.definition.SourceID || len(queryValue.Scope.ResourceIDs) != 1 ||
		queryValue.SchemaDigest != schemaValue.SchemaDigest || !schemaValue.Complete || schemaValue.NextCursor != nil {
		return compiler.denied(ctx, query, "querydsl_binding_invalid"), nil, nil
	}
	resource := queryValue.Scope.ResourceIDs[0]
	if err := compiler.validateSchema(resource, schemaValue); err != nil {
		return compiler.denied(ctx, query, err.(*denial).reason), nil, nil
	}
	parsed, err := parse(ctx, compiler.definition, queryValue.NativeText)
	if err != nil {
		var semantic *denial
		if errors.As(err, &semantic) {
			return compiler.denied(ctx, query, semantic.reason), nil, nil
		}
		return queryconnector.ValidatedValidation{}, nil, err
	}
	plan, err := compiler.buildPlan(ctx, query, resource, parsed)
	if err != nil {
		var semantic *denial
		if errors.As(err, &semantic) {
			return compiler.denied(ctx, query, semantic.reason), nil, nil
		}
		return queryconnector.ValidatedValidation{}, nil, err
	}
	validated := &ValidatedPlan{value: plan, digest: plan.PlanDigest}
	return validation(ctx, query, "accepted", nil, plan.PlanDigest), validated, nil
}

func (compiler *Compiler) validateSchema(resource string, schema queryconnector.SchemaPage) error {
	if !slices.Contains(compiler.definition.Resources, resource) || len(schema.Entries) == 0 {
		return deny("querydsl_schema_scope_invalid")
	}
	allowed := make(map[string]string, len(compiler.definition.Fields))
	for _, field := range compiler.definition.Fields {
		allowed[field.Name] = field.Type
	}
	seen := make(map[string]struct{}, len(schema.Entries))
	for _, entry := range schema.Entries {
		expected, ok := allowed[entry.Name]
		if entry.ResourceID != resource || !ok || expected != entry.Type {
			return deny("querydsl_schema_field_mismatch")
		}
		seen[entry.Name] = struct{}{}
	}
	for _, field := range compiler.definition.Fields {
		if _, ok := seen[field.Name]; !ok {
			return deny("querydsl_schema_field_missing")
		}
	}
	return nil
}

func (compiler *Compiler) buildPlan(ctx context.Context, query queryconnector.ValidatedQuery,
	resource string, caller node) (Plan, error) {
	if err := contextError(ctx); err != nil {
		return Plan{}, err
	}
	queryValue := query.Value()
	callerQuery := compiler.canonicalNode(caller)
	mandatory := compiler.mandatoryFilters(queryValue)
	filters := append([]any(nil), mandatory...)
	filters = append(filters, callerQuery)
	canonicalQuery := map[string]any{"bool": map[string]any{"filter": filters}}
	projection := append([]string(nil), compiler.definition.Projection...)
	for _, stable := range compiler.definition.StableSort {
		if !slices.Contains(projection, stable.Name) {
			projection = append(projection, stable.Name)
		}
	}
	if len(projection) > 256 {
		return Plan{}, deny("querydsl_output_shape_limit")
	}
	columns := make([]Column, len(projection))
	for index, name := range projection {
		field, _ := findField(compiler.definition, name)
		columns[index] = Column{LogicalName: field.Name, VendorName: field.VendorName, Type: field.Type}
	}
	sortFields := append([]SortField(nil), compiler.definition.StableSort...)
	sortFields = append(sortFields, SortField{Name: "_shard_doc", VendorName: "_shard_doc", Type: "integer", Direction: "ASC"})
	maximumRows := min(queryValue.Limits.MaximumRows, compiler.definition.HardMaximumRows)
	// A serial PIT page is the exporter's smallest independently bounded work
	// slice. Capping pages by the caller's slice budget keeps shared runtime
	// accounting fail closed without exposing vendor slicing controls.
	maximumPages := min(queryValue.Limits.MaximumPages, compiler.definition.HardMaximumPages,
		queryValue.Limits.MaximumSlices)
	pageRows := min(maximumRows, compiler.definition.HardPageRows)
	if maximumRows == 0 || maximumPages == 0 || pageRows == 0 {
		return Plan{}, deny("querydsl_limits_invalid")
	}
	plan := Plan{QueryID: queryValue.QueryID, SourceID: queryValue.Scope.SourceID, ResourceID: resource,
		CanonicalQuery: canonicalQuery, CallerQueryDigest: digest("COH-ELASTIC-QUERY-DSL-CALLER-V1\x00", callerQuery),
		MandatoryFilterDigest: digest("COH-ELASTIC-QUERY-DSL-FILTER-V1\x00", mandatory), Columns: columns,
		Sort: sortFields, MaximumRows: maximumRows, MaximumPages: maximumPages, PageRows: pageRows,
		MaximumBytes: queryValue.Limits.MaximumBytes, MaximumDurationMillis: queryValue.Limits.MaximumDurationMillis}
	plan.PlanDigest = digest("COH-ELASTIC-QUERY-DSL-PLAN-V1\x00", struct {
		QueryDigest  string
		SchemaDigest string
		Authority    queryconnector.AuthorityBinding
		Plan         Plan
	}{query.Digest(), queryValue.SchemaDigest, queryValue.Authority, plan})
	return plan, nil
}

func (compiler *Compiler) mandatoryFilters(query queryconnector.Query) []any {
	timestamp, _ := findField(compiler.definition, compiler.definition.TimestampField)
	filters := []any{map[string]any{"range": map[string]any{timestamp.VendorName: map[string]any{
		"format": "strict_date_optional_time_nanos", "gte": query.TimeRange.Start, "lt": query.TimeRange.End}}}}
	if compiler.definition.TenantField != "" {
		field, _ := findField(compiler.definition, compiler.definition.TenantField)
		filters = append(filters, map[string]any{"term": map[string]any{field.VendorName: query.Scope.TenantID}})
	}
	if compiler.definition.SourceField != "" {
		field, _ := findField(compiler.definition, compiler.definition.SourceField)
		filters = append(filters, map[string]any{"term": map[string]any{field.VendorName: query.Scope.SourceID}})
	}
	return filters
}

func (compiler *Compiler) canonicalNode(value node) map[string]any {
	switch value.kind {
	case "match_all":
		return map[string]any{"match_all": map[string]any{}}
	case "term":
		return map[string]any{"term": map[string]any{value.field.VendorName: value.value}}
	case "terms":
		return map[string]any{"terms": map[string]any{value.field.VendorName: append([]any(nil), value.values...)}}
	case "range":
		return map[string]any{"range": map[string]any{value.field.VendorName: cloneValue(value.bounds)}}
	case "exists":
		return map[string]any{"exists": map[string]any{"field": value.field.VendorName}}
	case "match":
		return map[string]any{"match": map[string]any{value.field.VendorName: map[string]any{"query": value.value, "operator": "and"}}}
	case "match_phrase":
		return map[string]any{"match_phrase": map[string]any{value.field.VendorName: map[string]any{"query": value.value, "slop": 0}}}
	case "bool":
		body := map[string]any{}
		if len(value.filter) > 0 {
			body["filter"] = compiler.canonicalNodes(value.filter)
		}
		if len(value.should) > 0 {
			body["should"], body["minimum_should_match"] = compiler.canonicalNodes(value.should), 1
		}
		if len(value.mustNot) > 0 {
			body["must_not"] = compiler.canonicalNodes(value.mustNot)
		}
		return map[string]any{"bool": body}
	default:
		return nil
	}
}

func (compiler *Compiler) canonicalNodes(values []node) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = compiler.canonicalNode(value)
	}
	slices.SortFunc(result, func(left, right any) int {
		leftEncoded, _ := json.Marshal(left)
		rightEncoded, _ := json.Marshal(right)
		return slices.Compare(leftEncoded, rightEncoded)
	})
	return result
}

func (compiler *Compiler) denied(ctx context.Context, query queryconnector.ValidatedQuery, reason string) queryconnector.ValidatedValidation {
	return validation(ctx, query, "denied", []string{reason}, digest("COH-ELASTIC-QUERY-DSL-DENIAL-V1\x00", struct{ Query, Reason string }{query.Digest(), reason}))
}

func validation(ctx context.Context, query queryconnector.ValidatedQuery, outcome string, reasons []string,
	provenance string) queryconnector.ValidatedValidation {
	value := queryconnector.ValidationResult{SchemaVersion: queryconnector.ValidationSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: query.Value().QueryID, Outcome: outcome,
		ReasonCodes: reasons, ValidatorVersion: ValidatorVersion, CanonicalQueryDigest: query.Digest(),
		ProvenanceDigest: provenance}
	encoded, _ := json.Marshal(value)
	result, _ := queryconnector.DecodeValidation(ctx, encoded)
	return result
}
