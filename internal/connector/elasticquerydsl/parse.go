package elasticquerydsl

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func parse(ctx context.Context, definition Definition, input string) (node, error) {
	if err := contextError(ctx); err != nil {
		return node{}, err
	}
	if len(input) == 0 || len(input) > maximumInputBytes || !utf8.ValidString(input) {
		return node{}, deny("querydsl_input_invalid")
	}
	canonical, err := domaincontract.Canonicalize([]byte(input))
	if err != nil {
		return node{}, deny("querydsl_json_invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return node{}, deny("querydsl_json_invalid")
	}
	state := &parseState{}
	return parseNode(ctx, definition, value, 1, state)
}

func parseNode(ctx context.Context, definition Definition, value any, depth int, state *parseState) (node, error) {
	if err := contextError(ctx); err != nil {
		return node{}, err
	}
	state.clauses++
	if depth > maximumDepth || state.clauses > maximumClauses {
		return node{}, deny("querydsl_complexity_limit")
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 1 {
		return node{}, deny("querydsl_node_invalid")
	}
	for kind, body := range object {
		switch kind {
		case "match_all":
			if nested, ok := body.(map[string]any); !ok || len(nested) != 0 {
				return node{}, deny("querydsl_match_all_invalid")
			}
			return node{kind: kind}, nil
		case "term":
			return parseTerm(definition, body, false)
		case "terms":
			return parseTerm(definition, body, true)
		case "range":
			return parseRange(definition, body)
		case "exists":
			return parseExists(definition, body)
		case "match", "match_phrase":
			return parseText(definition, kind, body)
		case "bool":
			return parseBool(ctx, definition, body, depth, state)
		default:
			return node{}, deny("querydsl_operator_unsupported")
		}
	}
	return node{}, deny("querydsl_node_invalid")
}

func parseTerm(definition Definition, body any, multiple bool) (node, error) {
	fieldName, raw, err := singleField(body)
	if err != nil {
		return node{}, err
	}
	field, ok := findField(definition, fieldName)
	if !ok || !field.Exact {
		return node{}, deny("querydsl_exact_field_denied")
	}
	if !multiple {
		value, err := typedScalar(field.Type, raw)
		if err != nil {
			return node{}, err
		}
		return node{kind: "term", field: field, value: value}, nil
	}
	input, ok := raw.([]any)
	if !ok || len(input) == 0 || len(input) > maximumTerms {
		return node{}, deny("querydsl_terms_invalid")
	}
	values := make([]any, len(input))
	for index, rawValue := range input {
		values[index], err = typedScalar(field.Type, rawValue)
		if err != nil {
			return node{}, err
		}
	}
	slices.SortFunc(values, func(left, right any) int { return strings.Compare(scalarKey(left), scalarKey(right)) })
	for index := 1; index < len(values); index++ {
		if scalarKey(values[index-1]) == scalarKey(values[index]) {
			return node{}, deny("querydsl_terms_duplicate")
		}
	}
	return node{kind: "terms", field: field, values: values}, nil
}

func parseRange(definition Definition, body any) (node, error) {
	fieldName, raw, err := singleField(body)
	if err != nil {
		return node{}, err
	}
	field, ok := findField(definition, fieldName)
	if !ok || !field.Range {
		return node{}, deny("querydsl_range_field_denied")
	}
	object, ok := raw.(map[string]any)
	if !ok || len(object) == 0 || len(object) > 2 {
		return node{}, deny("querydsl_range_invalid")
	}
	bounds := make(map[string]any, len(object))
	for operator, rawValue := range object {
		if !oneOf(operator, "gt", "gte", "lt", "lte") {
			return node{}, deny("querydsl_range_invalid")
		}
		value, err := typedScalar(field.Type, rawValue)
		if err != nil {
			return node{}, err
		}
		bounds[operator] = value
	}
	if bounds["gt"] != nil && bounds["gte"] != nil || bounds["lt"] != nil && bounds["lte"] != nil {
		return node{}, deny("querydsl_range_invalid")
	}
	lower, lowerInclusive := bounds["gt"], false
	if bounds["gte"] != nil {
		lower, lowerInclusive = bounds["gte"], true
	}
	upper, upperInclusive := bounds["lt"], false
	if bounds["lte"] != nil {
		upper, upperInclusive = bounds["lte"], true
	}
	if lower != nil && upper != nil {
		compared := compareScalar(field.Type, lower, upper)
		if compared > 0 || compared == 0 && (!lowerInclusive || !upperInclusive) {
			return node{}, deny("querydsl_range_contradictory")
		}
	}
	return node{kind: "range", field: field, bounds: bounds}, nil
}

func parseExists(definition Definition, body any) (node, error) {
	object, ok := body.(map[string]any)
	if !ok || len(object) != 1 {
		return node{}, deny("querydsl_exists_invalid")
	}
	name, ok := object["field"].(string)
	if !ok {
		return node{}, deny("querydsl_exists_invalid")
	}
	field, found := findField(definition, name)
	if !found || !field.Exists {
		return node{}, deny("querydsl_exists_field_denied")
	}
	return node{kind: "exists", field: field}, nil
}

func parseText(definition Definition, kind string, body any) (node, error) {
	fieldName, raw, err := singleField(body)
	if err != nil {
		return node{}, err
	}
	field, ok := findField(definition, fieldName)
	if !ok || !field.TextSearchable {
		return node{}, deny("querydsl_text_field_denied")
	}
	object, ok := raw.(map[string]any)
	if !ok {
		return node{}, deny("querydsl_text_invalid")
	}
	text, ok := object["query"].(string)
	if !ok || strings.TrimSpace(text) == "" || len(text) > 8192 || !utf8.ValidString(text) {
		return node{}, deny("querydsl_text_invalid")
	}
	if kind == "match" {
		if len(object) != 2 || object["operator"] != "and" {
			return node{}, deny("querydsl_text_invalid")
		}
	} else if len(object) != 2 || !numberEquals(object["slop"], 0) {
		return node{}, deny("querydsl_text_invalid")
	}
	return node{kind: kind, field: field, value: text}, nil
}

func parseBool(ctx context.Context, definition Definition, body any, depth int, state *parseState) (node, error) {
	object, ok := body.(map[string]any)
	if !ok || len(object) == 0 || len(object) > 4 {
		return node{}, deny("querydsl_bool_invalid")
	}
	result := node{kind: "bool"}
	for key := range object {
		if !oneOf(key, "filter", "should", "must_not", "minimum_should_match") {
			return node{}, deny("querydsl_bool_invalid")
		}
	}
	var err error
	if raw, exists := object["filter"]; exists {
		result.filter, err = parseNodeArray(ctx, definition, raw, depth+1, state)
		if err != nil {
			return node{}, err
		}
	}
	if raw, exists := object["should"]; exists {
		result.should, err = parseNodeArray(ctx, definition, raw, depth+1, state)
		if err != nil {
			return node{}, err
		}
		if !numberEquals(object["minimum_should_match"], 1) {
			return node{}, deny("querydsl_bool_invalid")
		}
	} else if _, exists := object["minimum_should_match"]; exists {
		return node{}, deny("querydsl_bool_invalid")
	}
	if raw, exists := object["must_not"]; exists {
		result.mustNot, err = parseNodeArray(ctx, definition, raw, depth+1, state)
		if err != nil {
			return node{}, err
		}
	}
	if len(result.filter)+len(result.should)+len(result.mustNot) == 0 {
		return node{}, deny("querydsl_bool_invalid")
	}
	return result, nil
}

func parseNodeArray(ctx context.Context, definition Definition, raw any, depth int, state *parseState) ([]node, error) {
	values, ok := raw.([]any)
	if !ok || len(values) == 0 || len(values) > maximumClauses {
		return nil, deny("querydsl_bool_invalid")
	}
	result := make([]node, len(values))
	for index, value := range values {
		parsed, err := parseNode(ctx, definition, value, depth, state)
		if err != nil {
			return nil, err
		}
		result[index] = parsed
	}
	return result, nil
}

func singleField(body any) (string, any, error) {
	object, ok := body.(map[string]any)
	if !ok || len(object) != 1 {
		return "", nil, deny("querydsl_field_object_invalid")
	}
	for name, value := range object {
		if !namePattern.MatchString(name) {
			return "", nil, deny("querydsl_field_invalid")
		}
		return name, value, nil
	}
	return "", nil, deny("querydsl_field_object_invalid")
}

func typedScalar(kind string, raw any) (any, error) {
	switch kind {
	case "string":
		value, ok := raw.(string)
		if !ok || len(value) > 8192 || !utf8.ValidString(value) {
			return nil, deny("querydsl_literal_type_mismatch")
		}
		return value, nil
	case "boolean":
		value, ok := raw.(bool)
		if !ok {
			return nil, deny("querydsl_literal_type_mismatch")
		}
		return value, nil
	case "integer":
		number, ok := raw.(json.Number)
		if !ok {
			return nil, deny("querydsl_literal_type_mismatch")
		}
		value, err := strconv.ParseInt(number.String(), 10, 64)
		if err != nil {
			return nil, deny("querydsl_integer_invalid")
		}
		return value, nil
	case "ip":
		value, ok := raw.(string)
		parsed := net.ParseIP(value)
		if !ok || parsed == nil || value != parsed.String() {
			return nil, deny("querydsl_ip_invalid")
		}
		return value, nil
	case "timestamp":
		value, ok := raw.(string)
		if !ok {
			return nil, deny("querydsl_timestamp_invalid")
		}
		parsed, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || parsed.Location() != time.UTC || value != parsed.UTC().Format(time.RFC3339Nano) {
			return nil, deny("querydsl_timestamp_invalid")
		}
		return value, nil
	default:
		return nil, deny("querydsl_literal_type_unsupported")
	}
}

func compareScalar(kind string, left, right any) int {
	switch kind {
	case "integer":
		if left.(int64) < right.(int64) {
			return -1
		}
		if left.(int64) > right.(int64) {
			return 1
		}
	case "timestamp":
		leftTime, _ := time.Parse(time.RFC3339Nano, left.(string))
		rightTime, _ := time.Parse(time.RFC3339Nano, right.(string))
		if leftTime.Before(rightTime) {
			return -1
		}
		if leftTime.After(rightTime) {
			return 1
		}
	case "ip":
		return bytes.Compare(net.ParseIP(left.(string)).To16(), net.ParseIP(right.(string)).To16())
	}
	return 0
}

func numberEquals(value any, expected int64) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := strconv.ParseInt(number.String(), 10, 64)
	return err == nil && parsed == expected
}

func scalarKey(value any) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func findField(definition Definition, name string) (FieldRule, bool) {
	index, found := slices.BinarySearchFunc(definition.Fields, name, func(field FieldRule, name string) int {
		return strings.Compare(field.Name, name)
	})
	if !found {
		return FieldRule{}, false
	}
	return definition.Fields[index], true
}
