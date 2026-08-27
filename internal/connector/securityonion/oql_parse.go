package securityonion

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	maximumOQLInputBytes = 262144
	maximumOQLDepth      = 16
	maximumOQLClauses    = 1024
	maximumOQLTerms      = 256
)

type oqlDocument struct {
	mode    string
	filter  oqlNode
	groupBy []Field
}

type oqlNode struct {
	kind    string
	field   Field
	value   any
	values  []any
	bounds  map[string]any
	filter  []oqlNode
	should  []oqlNode
	mustNot []oqlNode
}

type oqlParseState struct{ clauses int }

func parseOQL(ctx context.Context, config Config, input string) (oqlDocument, error) {
	if err := oqlContextError(ctx); err != nil {
		return oqlDocument{}, err
	}
	if len(input) == 0 || len(input) > maximumOQLInputBytes || !utf8.ValidString(input) {
		return oqlDocument{}, denyOQL("securityonion_oql_input_invalid")
	}
	canonical, err := domaincontract.Canonicalize([]byte(input))
	if err != nil {
		return oqlDocument{}, denyOQL("securityonion_oql_json_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var raw map[string]any
	if decoder.Decode(&raw) != nil || len(raw) < 1 || len(raw) > 3 {
		return oqlDocument{}, denyOQL("securityonion_oql_document_invalid")
	}
	mode, ok := raw["mode"].(string)
	if !ok || (mode != "events" && mode != "metrics") {
		return oqlDocument{}, denyOQL("securityonion_oql_mode_invalid")
	}
	filter, ok := raw["filter"]
	if !ok {
		return oqlDocument{}, denyOQL("securityonion_oql_filter_invalid")
	}
	for key := range raw {
		if key != "mode" && key != "filter" && key != "group_by" {
			return oqlDocument{}, denyOQL("securityonion_oql_document_invalid")
		}
	}
	node, err := parseOQLNode(ctx, config, filter, 1, &oqlParseState{})
	if err != nil {
		return oqlDocument{}, err
	}
	groups, err := parseOQLGroups(config, mode, raw["group_by"])
	if err != nil {
		return oqlDocument{}, err
	}
	return oqlDocument{mode: mode, filter: node, groupBy: groups}, nil
}

func parseOQLNode(ctx context.Context, config Config, raw any, depth int, state *oqlParseState) (oqlNode, error) {
	if err := oqlContextError(ctx); err != nil {
		return oqlNode{}, err
	}
	state.clauses++
	if depth > maximumOQLDepth || state.clauses > maximumOQLClauses {
		return oqlNode{}, denyOQL("securityonion_oql_complexity_limit")
	}
	object, ok := raw.(map[string]any)
	if !ok || len(object) != 1 {
		return oqlNode{}, denyOQL("securityonion_oql_node_invalid")
	}
	for kind, body := range object {
		switch kind {
		case "match_all":
			if value, ok := body.(map[string]any); !ok || len(value) != 0 {
				return oqlNode{}, denyOQL("securityonion_oql_match_all_invalid")
			}
			return oqlNode{kind: kind}, nil
		case "term", "terms":
			return parseOQLTerm(config, kind, body)
		case "range":
			return parseOQLRange(config, body)
		case "exists":
			return parseOQLExists(config, body)
		case "bool":
			return parseOQLBool(ctx, config, body, depth, state)
		default:
			return oqlNode{}, denyOQL("securityonion_oql_operator_unsupported")
		}
	}
	return oqlNode{}, denyOQL("securityonion_oql_node_invalid")
}

func parseOQLTerm(config Config, kind string, body any) (oqlNode, error) {
	name, raw, err := singleOQLField(body)
	field, ok := findOQLField(config, name)
	if err != nil || !ok || !field.Exact {
		return oqlNode{}, denyOQL("securityonion_oql_exact_field_denied")
	}
	if kind == "term" {
		value, err := oqlScalar(field.Type, raw)
		return oqlNode{kind: kind, field: field, value: value}, err
	}
	input, ok := raw.([]any)
	if !ok || len(input) == 0 || len(input) > maximumOQLTerms {
		return oqlNode{}, denyOQL("securityonion_oql_terms_invalid")
	}
	values := make([]any, len(input))
	for index := range input {
		values[index], err = oqlScalar(field.Type, input[index])
		if err != nil {
			return oqlNode{}, err
		}
	}
	slices.SortFunc(values, func(a, b any) int { return strings.Compare(oqlScalarKey(a), oqlScalarKey(b)) })
	for index := 1; index < len(values); index++ {
		if oqlScalarKey(values[index-1]) == oqlScalarKey(values[index]) {
			return oqlNode{}, denyOQL("securityonion_oql_terms_duplicate")
		}
	}
	return oqlNode{kind: kind, field: field, values: values}, nil
}

func parseOQLRange(config Config, body any) (oqlNode, error) {
	name, raw, err := singleOQLField(body)
	field, ok := findOQLField(config, name)
	if err != nil || !ok || !field.Range {
		return oqlNode{}, denyOQL("securityonion_oql_range_field_denied")
	}
	object, ok := raw.(map[string]any)
	if !ok || len(object) == 0 || len(object) > 2 {
		return oqlNode{}, denyOQL("securityonion_oql_range_invalid")
	}
	bounds := make(map[string]any, len(object))
	for key, rawValue := range object {
		if key != "gt" && key != "gte" && key != "lt" && key != "lte" {
			return oqlNode{}, denyOQL("securityonion_oql_range_invalid")
		}
		bounds[key], err = oqlScalar(field.Type, rawValue)
		if err != nil {
			return oqlNode{}, err
		}
	}
	if (bounds["gt"] != nil && bounds["gte"] != nil) || (bounds["lt"] != nil && bounds["lte"] != nil) {
		return oqlNode{}, denyOQL("securityonion_oql_range_invalid")
	}
	lower, lowerInclusive := bounds["gt"], false
	if lower == nil {
		lower, lowerInclusive = bounds["gte"], true
	}
	upper, upperInclusive := bounds["lt"], false
	if upper == nil {
		upper, upperInclusive = bounds["lte"], true
	}
	if lower != nil && upper != nil {
		comparison := compareOQLScalars(field.Type, lower, upper)
		if comparison > 0 || comparison == 0 && (!lowerInclusive || !upperInclusive) {
			return oqlNode{}, denyOQL("securityonion_oql_range_contradictory")
		}
	}
	return oqlNode{kind: "range", field: field, bounds: bounds}, nil
}

func parseOQLExists(config Config, body any) (oqlNode, error) {
	object, ok := body.(map[string]any)
	name, nameOK := object["field"].(string)
	field, found := findOQLField(config, name)
	if !ok || len(object) != 1 || !nameOK || !found || !field.Exists {
		return oqlNode{}, denyOQL("securityonion_oql_exists_field_denied")
	}
	return oqlNode{kind: "exists", field: field}, nil
}

func parseOQLBool(ctx context.Context, config Config, body any, depth int, state *oqlParseState) (oqlNode, error) {
	object, ok := body.(map[string]any)
	if !ok || len(object) == 0 || len(object) > 4 {
		return oqlNode{}, denyOQL("securityonion_oql_bool_invalid")
	}
	for key := range object {
		if key != "filter" && key != "should" && key != "must_not" && key != "minimum_should_match" {
			return oqlNode{}, denyOQL("securityonion_oql_bool_invalid")
		}
	}
	result := oqlNode{kind: "bool"}
	var err error
	result.filter, err = parseOQLNodeList(ctx, config, object["filter"], depth, state)
	if err != nil {
		return oqlNode{}, err
	}
	result.should, err = parseOQLNodeList(ctx, config, object["should"], depth, state)
	if err != nil {
		return oqlNode{}, err
	}
	result.mustNot, err = parseOQLNodeList(ctx, config, object["must_not"], depth, state)
	if err != nil {
		return oqlNode{}, err
	}
	minimum, hasMinimum := object["minimum_should_match"]
	if len(result.should) > 0 {
		number, ok := minimum.(json.Number)
		if !hasMinimum || !ok || string(number) != "1" {
			return oqlNode{}, denyOQL("securityonion_oql_bool_invalid")
		}
	} else if hasMinimum {
		return oqlNode{}, denyOQL("securityonion_oql_bool_invalid")
	}
	if len(result.filter)+len(result.should)+len(result.mustNot) == 0 {
		return oqlNode{}, denyOQL("securityonion_oql_bool_invalid")
	}
	return result, nil
}

func parseOQLNodeList(ctx context.Context, config Config, raw any, depth int, state *oqlParseState) ([]oqlNode, error) {
	if raw == nil {
		return nil, nil
	}
	values, ok := raw.([]any)
	if !ok || len(values) == 0 || len(values) > maximumOQLClauses {
		return nil, denyOQL("securityonion_oql_bool_invalid")
	}
	result := make([]oqlNode, len(values))
	for index := range values {
		var err error
		result[index], err = parseOQLNode(ctx, config, values[index], depth+1, state)
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func parseOQLGroups(config Config, mode string, raw any) ([]Field, error) {
	if raw == nil {
		if mode == "metrics" {
			return nil, denyOQL("securityonion_oql_group_required")
		}
		return nil, nil
	}
	values, ok := raw.([]any)
	if !ok || mode != "metrics" || len(values) == 0 || len(values) > 8 {
		return nil, denyOQL("securityonion_oql_group_invalid")
	}
	result := make([]Field, len(values))
	seen := map[string]struct{}{}
	for index, rawName := range values {
		name, ok := rawName.(string)
		field, found := findOQLField(config, name)
		if !ok || !found || !field.Groupable {
			return nil, denyOQL("securityonion_oql_group_field_denied")
		}
		if _, exists := seen[name]; exists {
			return nil, denyOQL("securityonion_oql_group_invalid")
		}
		seen[name], result[index] = struct{}{}, field
	}
	return result, nil
}

func singleOQLField(raw any) (string, any, error) {
	object, ok := raw.(map[string]any)
	if !ok || len(object) != 1 {
		return "", nil, denyOQL("securityonion_oql_field_invalid")
	}
	for name, value := range object {
		return name, value, nil
	}
	return "", nil, denyOQL("securityonion_oql_field_invalid")
}

func oqlScalar(kind string, raw any) (any, error) {
	switch kind {
	case "string":
		value, ok := raw.(string)
		if !ok || value == "" || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return nil, denyOQL("securityonion_oql_literal_type_mismatch")
		}
		return value, nil
	case "integer":
		number, ok := raw.(json.Number)
		if !ok {
			return nil, denyOQL("securityonion_oql_literal_type_mismatch")
		}
		value, err := strconv.ParseInt(string(number), 10, 64)
		if err != nil {
			return nil, denyOQL("securityonion_oql_literal_type_mismatch")
		}
		return value, nil
	case "boolean":
		value, ok := raw.(bool)
		if !ok {
			return nil, denyOQL("securityonion_oql_literal_type_mismatch")
		}
		return value, nil
	case "timestamp":
		value, ok := raw.(string)
		parsed, err := time.Parse(timestampLayout, value)
		if !ok || err != nil || parsed.Format(timestampLayout) != value {
			return nil, denyOQL("securityonion_oql_timestamp_invalid")
		}
		return value, nil
	case "ip":
		value, ok := raw.(string)
		parsed := net.ParseIP(value)
		if !ok || parsed == nil || parsed.String() != value {
			return nil, denyOQL("securityonion_oql_ip_invalid")
		}
		return value, nil
	default:
		return nil, denyOQL("securityonion_oql_literal_type_mismatch")
	}
}

func findOQLField(config Config, name string) (Field, bool) {
	for _, field := range config.Fields {
		if field.LogicalName == name {
			return field, true
		}
	}
	return Field{}, false
}

func oqlScalarKey(value any) string { return toString(value) }

func compareOQLScalars(kind string, left, right any) int {
	if kind == "ip" {
		return netip.MustParseAddr(left.(string)).Compare(netip.MustParseAddr(right.(string)))
	}
	switch current := left.(type) {
	case int64:
		other := right.(int64)
		if current < other {
			return -1
		}
		if current > other {
			return 1
		}
		return 0
	case string:
		return strings.Compare(current, right.(string))
	default:
		return strings.Compare(toString(left), toString(right))
	}
}

func toString(value any) string {
	switch current := value.(type) {
	case string:
		return "s:" + current
	case int64:
		return "i:" + strconv.FormatInt(current, 10)
	case bool:
		return "b:" + strconv.FormatBool(current)
	default:
		return ""
	}
}
