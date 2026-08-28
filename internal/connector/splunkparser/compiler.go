package splunkparser

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// CompileRequest contains only admitted configuration and authority. Query is
// parsed as the restricted logical SPL profile and can never carry native SPL.
type CompileRequest struct {
	Query                  string
	QueryID                string
	Definition             Definition
	ActorID                string
	AuthorizationDigest    string
	PolicyDecisionDigest   string
	AuditReservationDigest string
	CapabilityDigest       string
	SchemaDigest           string
	ScopeDigest            string
	Earliest               string
	Latest                 string
	MaximumRows            uint64
	MaximumBytes           uint64
	MaximumDurationMillis  uint64
	MandatoryTenantValue   string
	MandatorySourceValue   string
}

// Inspect returns the bounded logical resource selected by a structurally valid
// query. It exposes no literals or native text.
func Inspect(ctx context.Context, input string) (string, error) {
	query, err := parse(ctx, input)
	if err != nil {
		return "", err
	}
	return query.resourceID, nil
}

// Compile binds logical syntax to an admitted schema and returns an immutable,
// self-verifying native plan. No caller text is concatenated into native SPL.
func Compile(ctx context.Context, request CompileRequest) (Plan, error) {
	if err := validateCompileRequest(request); err != nil {
		return Plan{}, err
	}
	syntax, err := parse(ctx, request.Query)
	if err != nil {
		return Plan{}, err
	}
	definition := definitionIndex(request.Definition)
	typed, err := bindQuery(syntax, definition)
	if err != nil {
		return Plan{}, err
	}
	maximumRows := request.MaximumRows
	if syntax.hasHead && syntax.head < maximumRows {
		maximumRows = syntax.head
	}
	if err := typed.ensureOutputBounds(definition, maximumRows, false); err != nil {
		return Plan{}, err
	}
	mandatory := mandatoryFilters(request, definition)
	canonicalSPL := renderNative(typed, mandatory)
	if len(canonicalSPL) > MaximumInputBytes {
		return Plan{}, syntaxDenied("canonical_query_size_exceeded")
	}
	columns, aggregations := typed.outputContract()
	registry := builtinRegistry()
	plan := Plan{
		SchemaVersion: PlanVersion, ContractVersion: ContractVersion, ValidatorVersion: ValidatorVersion,
		QueryID: request.QueryID, SourceID: request.Definition.SourceID,
		ResourceIDs: []string{typed.resource.ID}, CanonicalSPL: canonicalSPL,
		Columns: columns, Aggregations: aggregations, Sort: typed.planSort(),
		Earliest: request.Earliest, Latest: request.Latest,
		MaximumRows: maximumRows, MaximumBytes: request.MaximumBytes, MaximumDurationMillis: request.MaximumDurationMillis,
		SubsearchCount: typed.subsearchCount(), CommandCount: typed.totalCommandCount(),
		QueryDigest:      hash("COH-SPLUNK-LOGICAL-QUERY-V1\x00", renderLogical(typed)),
		ScopeDigest:      request.ScopeDigest,
		CapabilityDigest: request.CapabilityDigest, SchemaDigest: request.SchemaDigest,
		Authority: AuthorityBinding{ActorID: request.ActorID, AuthorizationDigest: request.AuthorizationDigest,
			PolicyDecisionDigest: request.PolicyDecisionDigest, AuditReservationDigest: request.AuditReservationDigest},
		RegistryDigest: registry.Digest, ParserReceiptDigest: zeroDigest(),
		MandatoryFilterDigest: hash("COH-SPLUNK-MANDATORY-FILTERS-V1\x00", mandatory),
	}
	plan.PlanDigest = PlanDigest(plan)
	if err := validatePlan(plan); err != nil {
		return Plan{}, syntaxDenied("compiled_plan_invalid")
	}
	return plan, nil
}

func validateCompileRequest(request CompileRequest) error {
	if err := validateDefinition(request.Definition); err != nil {
		return syntaxDenied("definition_invalid")
	}
	earliest, earliestErr := time.Parse("2006-01-02T15:04:05.000000000Z", request.Earliest)
	latest, latestErr := time.Parse("2006-01-02T15:04:05.000000000Z", request.Latest)
	if !uuidPattern.MatchString(request.QueryID) || !uuidPattern.MatchString(request.ActorID) ||
		!validDigests(request.AuthorizationDigest, request.PolicyDecisionDigest, request.AuditReservationDigest,
			request.CapabilityDigest, request.SchemaDigest, request.ScopeDigest) || earliestErr != nil || latestErr != nil || !earliest.Before(latest) ||
		request.MaximumRows == 0 || request.MaximumRows > request.Definition.HardMaximumRows ||
		request.MaximumBytes == 0 || request.MaximumBytes > MaximumDocumentBytes ||
		request.MaximumDurationMillis == 0 || request.MaximumDurationMillis > 120000 {
		return syntaxDenied("compile_authority_invalid")
	}
	if request.Definition.TenantField != "" && !safeMandatoryValue(request.MandatoryTenantValue) {
		return syntaxDenied("mandatory_tenant_invalid")
	}
	if request.Definition.TenantField == "" && request.MandatoryTenantValue != "" {
		return syntaxDenied("mandatory_tenant_unconfigured")
	}
	if request.Definition.SourceField != "" && !safeMandatoryValue(request.MandatorySourceValue) {
		return syntaxDenied("mandatory_source_invalid")
	}
	if request.Definition.SourceField == "" && request.MandatorySourceValue != "" {
		return syntaxDenied("mandatory_source_unconfigured")
	}
	return nil
}

type indexedDefinition struct {
	definition Definition
	resources  map[string]ResourceRule
	fields     map[string]FieldRule
}

func definitionIndex(definition Definition) indexedDefinition {
	result := indexedDefinition{definition: definition, resources: make(map[string]ResourceRule, len(definition.Resources)), fields: make(map[string]FieldRule, len(definition.Fields))}
	for _, resource := range definition.Resources {
		result.resources[resource.ID] = resource
	}
	for _, field := range definition.Fields {
		result.fields[field.Name] = field
	}
	return result
}

type typedQuery struct {
	resource          ResourceRule
	predicate         *typedPredicate
	projectionCommand string
	projection        []FieldRule
	aggregations      []typedAggregation
	groupBy           []FieldRule
	sort              []typedSort
	head              uint64
	hasHead           bool
	commandCount      uint32
}

type typedPredicate struct {
	kind      predicateKind
	operator  string
	field     FieldRule
	literal   typedLiteral
	left      *typedPredicate
	right     *typedPredicate
	subsearch *typedQuery
}

type typedLiteral struct {
	kind      literalKind
	canonical string
}

type typedAggregation struct {
	function   string
	input      FieldRule
	hasInput   bool
	alias      string
	outputType string
}

type typedSort struct {
	logical   string
	vendor    string
	direction string
}

func bindQuery(syntax *syntaxQuery, definition indexedDefinition) (*typedQuery, error) {
	resource, ok := definition.resources[syntax.resourceID]
	if !ok {
		return nil, syntaxDenied("resource_unknown")
	}
	result := &typedQuery{resource: resource, projectionCommand: "fields", head: syntax.head, hasHead: syntax.hasHead, commandCount: syntax.commandCount}
	var err error
	result.predicate, err = bindPredicate(syntax.predicate, definition)
	if err != nil {
		return nil, err
	}
	if syntax.projection != nil {
		result.projectionCommand = syntax.projection.command
		result.projection, err = bindFields(syntax.projection.fields, definition, func(field FieldRule) bool { return field.Projectable }, "field_not_projectable")
	} else if len(syntax.aggregations) == 0 {
		result.projection, err = bindFields(definition.definition.DefaultProjection, definition, func(field FieldRule) bool { return field.Projectable }, "field_not_projectable")
	}
	if err != nil {
		return nil, err
	}
	result.aggregations, err = bindAggregations(syntax.aggregations, definition)
	if err != nil {
		return nil, err
	}
	result.groupBy, err = bindFields(syntax.groupBy, definition, func(field FieldRule) bool { return field.Projectable && field.Aggregatable }, "group_field_invalid")
	if err != nil {
		return nil, err
	}
	result.sort, err = bindSort(syntax.sort, result, definition)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func bindPredicate(value *syntaxPredicate, definition indexedDefinition) (*typedPredicate, error) {
	if value == nil {
		return nil, nil
	}
	result := &typedPredicate{kind: value.kind, operator: value.operator}
	var err error
	result.left, err = bindPredicate(value.left, definition)
	if err != nil {
		return nil, err
	}
	result.right, err = bindPredicate(value.right, definition)
	if err != nil {
		return nil, err
	}
	if value.kind == predicateComparison || value.kind == predicateSubsearch {
		if oneOf(value.field, "earliest", "latest", "_time") {
			return nil, syntaxDenied("inline_time_not_allowed")
		}
		field, ok := definition.fields[value.field]
		if !ok {
			return nil, syntaxDenied("field_unknown")
		}
		if !field.Filterable {
			return nil, syntaxDenied("field_not_filterable")
		}
		result.field = field
	}
	if value.kind == predicateComparison {
		result.literal, err = bindLiteral(value.literal, result.field, value.operator)
		if err != nil {
			return nil, err
		}
	}
	if value.kind == predicateSubsearch {
		result.subsearch, err = bindQuery(value.subsearch, definition)
		if err != nil {
			return nil, err
		}
		if len(result.subsearch.projection) != 1 || result.subsearch.projection[0].Type != result.field.Type {
			return nil, syntaxDenied("subsearch_type_mismatch")
		}
	}
	return result, nil
}

func bindLiteral(value syntaxLiteral, field FieldRule, operator string) (typedLiteral, error) {
	equalityOnly := !oneOf(field.Type, "integer", "bytes", "timestamp")
	if equalityOnly && !oneOf(operator, "=", "!=") {
		return typedLiteral{}, syntaxDenied("comparison_operator_invalid")
	}
	switch field.Type {
	case "string":
		if value.kind != literalString {
			return typedLiteral{}, syntaxDenied("literal_type_invalid")
		}
		return typedLiteral{kind: literalString, canonical: value.text}, nil
	case "boolean":
		if value.kind != literalBoolean {
			return typedLiteral{}, syntaxDenied("literal_type_invalid")
		}
		return typedLiteral{kind: literalBoolean, canonical: value.text}, nil
	case "integer", "bytes":
		if value.kind != literalInteger {
			return typedLiteral{}, syntaxDenied("literal_type_invalid")
		}
		parsed, err := strconv.ParseInt(value.text, 10, 64)
		if err != nil || field.Type == "bytes" && parsed < 0 {
			return typedLiteral{}, syntaxDenied("integer_literal_invalid")
		}
		return typedLiteral{kind: literalInteger, canonical: strconv.FormatInt(parsed, 10)}, nil
	case "timestamp":
		if value.kind != literalString {
			return typedLiteral{}, syntaxDenied("literal_type_invalid")
		}
		parsed, err := time.Parse(time.RFC3339Nano, value.text)
		if err != nil {
			return typedLiteral{}, syntaxDenied("timestamp_literal_invalid")
		}
		return typedLiteral{kind: literalString, canonical: parsed.UTC().Format("2006-01-02T15:04:05.000000000Z")}, nil
	case "ip":
		if value.kind != literalString {
			return typedLiteral{}, syntaxDenied("literal_type_invalid")
		}
		parsed, err := netip.ParseAddr(value.text)
		if err != nil {
			return typedLiteral{}, syntaxDenied("ip_literal_invalid")
		}
		return typedLiteral{kind: literalString, canonical: parsed.String()}, nil
	default:
		return typedLiteral{}, syntaxDenied("field_type_invalid")
	}
}

func safeMandatoryValue(value string) bool {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.ContainsRune(value, '`') {
		return false
	}
	for _, current := range []byte(value) {
		if current < 0x20 || current == 0x7f {
			return false
		}
	}
	return true
}

// BindParserReceipt finalizes a local candidate after the independent vendor
// parser succeeds. The returned plan digest binds that exact receipt.
func BindParserReceipt(candidate Plan, receiptDigest string) (Plan, error) {
	if err := validatePlan(candidate); err != nil || !digestPattern.MatchString(receiptDigest) || receiptDigest == zeroDigest() {
		return Plan{}, syntaxDenied("parser_receipt_invalid")
	}
	candidate.ParserReceiptDigest = receiptDigest
	candidate.PlanDigest = PlanDigest(candidate)
	if err := validatePlan(candidate); err != nil {
		return Plan{}, syntaxDenied("compiled_plan_invalid")
	}
	return candidate, nil
}

func zeroDigest() string { return "sha256:" + strings.Repeat("0", 64) }
