package securityonion

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

const connectRangeLayout = "2006/01/02 3:04:05.000000000 PM"

func (compiler *OQLCompiler) validateOQL(ctx context.Context, query queryconnector.ValidatedQuery,
	schema queryconnector.ValidatedSchemaPage, qualification ValidatedQualification) (
	queryconnector.ValidatedValidation, *ValidatedOQLPlan, error) {
	if err := oqlContextError(ctx); err != nil {
		return queryconnector.ValidatedValidation{}, nil, err
	}
	if compiler == nil {
		return queryconnector.ValidatedValidation{}, nil, invalid("securityonion_oql_compiler_required")
	}
	queryValue, schemaValue := query.Value(), schema.Value()
	if query.Digest() == "" || schema.Digest() == "" || queryValue.Language != "security-onion-oql" ||
		queryValue.Scope.SourceID != compiler.config.SourceID || len(queryValue.Scope.ResourceIDs) != 1 ||
		queryValue.SchemaDigest != schemaValue.SchemaDigest || !schemaValue.Complete || schemaValue.NextCursor != nil ||
		qualification.Digest() == "" || qualification.Value().SourceID != compiler.config.SourceID {
		return oqlValidation(ctx, query, "denied", []string{"securityonion_oql_binding_invalid"}, query.Digest()), nil, nil
	}
	now := compiler.clock.Now().UTC()
	validUntil, err := time.Parse(timestampLayout, qualification.Value().ValidUntil)
	if err != nil || !now.Before(validUntil) || qualification.Value().Digest != qualification.Digest() {
		return oqlValidation(ctx, query, "denied", []string{"securityonion_qualification_stale"}, query.Digest()), nil, nil
	}
	resource := queryValue.Scope.ResourceIDs[0]
	if err := compiler.validateOQLSchema(resource, schemaValue); err != nil {
		return oqlValidation(ctx, query, "denied", []string{err.(*oqlDenial).reason}, query.Digest()), nil, nil
	}
	document, err := parseOQL(ctx, compiler.config, queryValue.NativeText)
	if err != nil {
		var semantic *oqlDenial
		if errors.As(err, &semantic) {
			return oqlValidation(ctx, query, "denied", []string{semantic.reason}, query.Digest()), nil, nil
		}
		return queryconnector.ValidatedValidation{}, nil, err
	}
	plan, err := compiler.buildOQLPlan(query, qualification, resource, document)
	if err != nil {
		var semantic *oqlDenial
		if errors.As(err, &semantic) {
			return oqlValidation(ctx, query, "denied", []string{semantic.reason}, query.Digest()), nil, nil
		}
		return queryconnector.ValidatedValidation{}, nil, err
	}
	validated := &ValidatedOQLPlan{value: plan, digest: plan.PlanDigest}
	return oqlValidation(ctx, query, "accepted", nil, plan.PlanDigest), validated, nil
}

func (compiler *OQLCompiler) validateOQLSchema(resource string, schema queryconnector.SchemaPage) error {
	if !slices.ContainsFunc(compiler.config.Resources, func(value Resource) bool { return value.ID == resource }) || len(schema.Entries) == 0 {
		return denyOQL("securityonion_oql_schema_scope_invalid")
	}
	allowed := make(map[string]string, len(compiler.config.Fields))
	for _, field := range compiler.config.Fields {
		allowed[field.LogicalName] = field.Type
	}
	seen := map[string]struct{}{}
	for _, entry := range schema.Entries {
		expected, ok := allowed[entry.Name]
		if entry.ResourceID != resource || !ok || entry.Type != expected {
			return denyOQL("securityonion_oql_schema_field_mismatch")
		}
		seen[entry.Name] = struct{}{}
	}
	if len(seen) != len(allowed) {
		return denyOQL("securityonion_oql_schema_field_missing")
	}
	return nil
}

func (compiler *OQLCompiler) buildOQLPlan(query queryconnector.ValidatedQuery,
	qualification ValidatedQualification, resource string, document oqlDocument) (OQLPlan, error) {
	value := query.Value()
	start, startErr := time.Parse(timestampLayout, value.TimeRange.Start)
	end, endErr := time.Parse(timestampLayout, value.TimeRange.End)
	if startErr != nil || endErr != nil || !start.Before(end) || end.Sub(start) > compiler.config.MaximumInterval {
		return OQLPlan{}, denyOQL("securityonion_oql_range_invalid")
	}
	caller := renderOQLNode(document.filter)
	mandatory := compiler.mandatoryOQL(value)
	filters := append(append([]string(nil), mandatory...), caller)
	rendered := "(" + strings.Join(filters, ") AND (") + ")"
	var columns []OQLColumn
	groups := make([]OQLColumn, len(document.groupBy))
	for index, field := range document.groupBy {
		groups[index] = OQLColumn{LogicalName: field.LogicalName, VendorName: field.VendorName, Type: field.Type}
	}
	eventLimit, metricLimit := uint64(1), uint64(1)
	if document.mode == "events" {
		columns = compiler.oqlColumns(compiler.config.Projection)
		eventLimit = min(value.Limits.MaximumRows, compiler.config.MaximumEventLimit)
		pipelineFields := vendorNames(columns)
		rendered += " | table " + strings.Join(pipelineFields, " ") + " | sortby " + strings.Join(compiler.sortOQL(), " ")
	} else {
		metricLimit = min(value.Limits.MaximumRows, compiler.config.MaximumMetricLimit)
		rendered += " | groupby " + strings.Join(vendorNames(groups), " ")
	}
	if eventLimit == 0 || metricLimit == 0 || value.Limits.MaximumBytes == 0 || value.Limits.MaximumDurationMillis == 0 {
		return OQLPlan{}, denyOQL("securityonion_oql_limits_invalid")
	}
	plan := OQLPlan{QueryID: value.QueryID, SourceID: value.Scope.SourceID, ResourceID: resource, Mode: document.mode,
		RenderedQuery: rendered, CallerFilterDigest: hash("COH-SECURITY-ONION-OQL-CALLER-V1\x00", []byte(caller)),
		MandatoryFilterDigest: hash("COH-SECURITY-ONION-OQL-MANDATORY-V1\x00", mustJSONBytes(mandatory)),
		Range:                 start.UTC().Format(connectRangeLayout) + " - " + end.UTC().Format(connectRangeLayout), Zone: "UTC",
		Format: connectRangeLayout, Columns: columns, GroupBy: groups, EventLimit: eventLimit, MetricLimit: metricLimit,
		MaximumBytes:          min(value.Limits.MaximumBytes, compiler.config.HardLimits.MaximumBytes),
		MaximumDurationMillis: min(value.Limits.MaximumDurationMillis, compiler.config.HardLimits.MaximumDurationMillis),
		QualificationDigest:   qualification.Digest()}
	encoded, _ := json.Marshal(struct {
		Query, Schema string
		Authority     queryconnector.AuthorityBinding
		Plan          OQLPlan
	}{query.Digest(), value.SchemaDigest, value.Authority, plan})
	plan.PlanDigest = hash("COH-SECURITY-ONION-OQL-PLAN-V1\x00", encoded)
	return plan, nil
}

func (compiler *OQLCompiler) mandatoryOQL(query queryconnector.Query) []string {
	result := []string{}
	if compiler.config.TenantField != "" {
		field, _ := findOQLField(compiler.config, compiler.config.TenantField)
		result = append(result, field.VendorName+":"+renderOQLScalar(query.Scope.TenantID))
	}
	if compiler.config.SourceField != "" {
		field, _ := findOQLField(compiler.config, compiler.config.SourceField)
		result = append(result, field.VendorName+":"+renderOQLScalar(query.Scope.SourceID))
	}
	return result
}

func (compiler *OQLCompiler) oqlColumns(names []string) []OQLColumn {
	result := make([]OQLColumn, len(names))
	for index, name := range names {
		field, _ := findOQLField(compiler.config, name)
		result[index] = OQLColumn{LogicalName: name, VendorName: field.VendorName, Type: field.Type}
	}
	return result
}

func (compiler *OQLCompiler) sortOQL() []string {
	result := make([]string, len(compiler.config.StableSort))
	for index, name := range compiler.config.StableSort {
		field, _ := findOQLField(compiler.config, name)
		result[index] = field.VendorName + "^"
	}
	return result
}

func vendorNames(values []OQLColumn) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = values[index].VendorName
	}
	return result
}

func oqlValidation(ctx context.Context, query queryconnector.ValidatedQuery, outcome string,
	reasons []string, provenance string) queryconnector.ValidatedValidation {
	value := queryconnector.ValidationResult{SchemaVersion: queryconnector.ValidationSchemaVersion,
		ContractVersion: queryconnector.ContractVersion, QueryID: query.Value().QueryID, Outcome: outcome,
		ReasonCodes: reasons, ValidatorVersion: OQLValidatorVersion, CanonicalQueryDigest: query.Digest(),
		ProvenanceDigest: provenance}
	encoded, _ := json.Marshal(value)
	result, _ := queryconnector.DecodeValidation(ctx, encoded)
	return result
}

func mustJSONBytes(value any) []byte { encoded, _ := json.Marshal(value); return encoded }
