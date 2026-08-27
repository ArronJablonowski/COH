package elasticesql

import (
	"context"
	"math"
	"slices"
	"strings"
)

type parser struct {
	ctx        context.Context
	tokens     []token
	position   int
	definition Definition
	fields     map[string]FieldRule
	depth      int
}

func parse(ctx context.Context, definition Definition, input string) (pipeline, error) {
	tokens, err := tokenize(ctx, input)
	if err != nil {
		return pipeline{}, err
	}
	fields := make(map[string]FieldRule, len(definition.Fields))
	for _, field := range definition.Fields {
		fields[strings.ToLower(field.Name)] = field
	}
	current := &parser{ctx: ctx, tokens: tokens, definition: definition, fields: fields}
	return current.pipeline()
}

func (current *parser) pipeline() (pipeline, error) {
	if !current.consumeWord("FROM") {
		return pipeline{}, deny("esql_source_required")
	}
	resource, err := current.word("esql_resource_invalid")
	if err != nil || !slices.Contains(current.definition.Resources, strings.ToLower(resource)) {
		return pipeline{}, deny("esql_resource_denied")
	}
	result := pipeline{resource: strings.ToLower(resource)}
	lastOrder, commands := 0, 1
	for current.match(tokenPipe) {
		commands++
		if commands > maximumCommands {
			return pipeline{}, deny("esql_command_limit")
		}
		command, commandErr := current.word("esql_command_required")
		if commandErr != nil {
			return pipeline{}, commandErr
		}
		switch strings.ToUpper(command) {
		case "WHERE":
			if lastOrder >= 1 {
				return pipeline{}, deny("esql_command_order_invalid")
			}
			lastOrder = 1
			result.expression, err = current.orExpression()
		case "KEEP":
			if lastOrder >= 2 {
				return pipeline{}, deny("esql_command_order_invalid")
			}
			lastOrder = 2
			result.projection, err = current.fieldList(true, false)
		case "SORT":
			if lastOrder >= 3 {
				return pipeline{}, deny("esql_command_order_invalid")
			}
			lastOrder = 3
			result.sort, err = current.sortList()
		case "LIMIT":
			if lastOrder >= 4 {
				return pipeline{}, deny("esql_command_order_invalid")
			}
			lastOrder = 4
			result.limit, err = current.positiveLimit()
		default:
			return pipeline{}, deny("esql_command_unsupported")
		}
		if err != nil {
			return pipeline{}, err
		}
		if current.peek().kind != tokenPipe && current.peek().kind != tokenEOF {
			return pipeline{}, deny("esql_command_trailing_input")
		}
	}
	if current.peek().kind != tokenEOF {
		return pipeline{}, deny("esql_pipeline_invalid")
	}
	return result, nil
}

func (current *parser) orExpression() (expression, error) {
	left, err := current.andExpression()
	for err == nil && current.consumeWord("OR") {
		var right expression
		right, err = current.andExpression()
		left = logical{operator: "OR", left: left, right: right}
	}
	return left, err
}

func (current *parser) andExpression() (expression, error) {
	left, err := current.notExpression()
	for err == nil && current.consumeWord("AND") {
		var right expression
		right, err = current.notExpression()
		left = logical{operator: "AND", left: left, right: right}
	}
	return left, err
}

func (current *parser) notExpression() (expression, error) {
	if current.consumeWord("NOT") {
		current.depth++
		if current.depth > maximumDepth {
			return nil, deny("esql_expression_depth")
		}
		child, err := current.notExpression()
		current.depth--
		return negation{child: child}, err
	}
	if current.match(tokenLeftParen) {
		current.depth++
		if current.depth > maximumDepth {
			return nil, deny("esql_expression_depth")
		}
		child, err := current.orExpression()
		current.depth--
		if err != nil || !current.match(tokenRightParen) {
			return nil, deny("esql_parentheses_invalid")
		}
		return child, nil
	}
	return current.comparison()
}

func (current *parser) comparison() (expression, error) {
	name, err := current.word("esql_comparison_field_required")
	if err != nil {
		return nil, err
	}
	field, ok := current.fields[strings.ToLower(name)]
	if !ok || !field.Filterable || name != field.Name {
		return nil, deny("esql_filter_field_denied")
	}
	operator := current.peek()
	if !oneOf(operator.text, "==", "!=", "<", "<=", ">", ">=") {
		return nil, deny("esql_comparison_operator_required")
	}
	current.position++
	value, err := current.literal(field.Type)
	if err != nil {
		return nil, err
	}
	return comparison{field: field.Name, operator: operator.text, value: value}, nil
}

func (current *parser) fieldList(projectable, sortable bool) ([]string, error) {
	values := make([]string, 0, 8)
	for {
		name, err := current.word("esql_field_required")
		if err != nil {
			return nil, err
		}
		field, ok := current.fields[strings.ToLower(name)]
		if !ok || name != field.Name || (projectable && !field.Projectable) || (sortable && !field.Sortable) {
			return nil, deny("esql_field_denied")
		}
		if slices.Contains(values, field.Name) || len(values) >= 256 {
			return nil, deny("esql_field_list_invalid")
		}
		values = append(values, field.Name)
		if !current.match(tokenComma) {
			return values, nil
		}
	}
}

func (current *parser) sortList() ([]SortField, error) {
	values := make([]SortField, 0, 4)
	for {
		name, err := current.word("esql_field_required")
		if err != nil {
			return nil, err
		}
		field, ok := current.fields[strings.ToLower(name)]
		if !ok || name != field.Name || !field.Sortable {
			return nil, deny("esql_field_denied")
		}
		for _, existing := range values {
			if existing.Name == field.Name {
				return nil, deny("esql_sort_invalid")
			}
		}
		direction := "ASC"
		if current.peek().kind == tokenWord && oneOf(strings.ToUpper(current.peek().text), "ASC", "DESC") {
			direction = strings.ToUpper(current.peek().text)
			current.position++
		}
		values = append(values, SortField{Name: field.Name, Direction: direction})
		if len(values) > 8 {
			return nil, deny("esql_sort_invalid")
		}
		if !current.match(tokenComma) {
			return values, nil
		}
	}
}

func (current *parser) positiveLimit() (uint64, error) {
	value := current.peek()
	if value.kind != tokenInteger {
		return 0, deny("esql_limit_invalid")
	}
	current.position++
	integer := value.value.(int64)
	if integer <= 0 || uint64(integer) > math.MaxUint32 {
		return 0, deny("esql_limit_invalid")
	}
	return uint64(integer), nil
}

func (current *parser) literal(kind string) (any, error) {
	value := current.peek()
	switch kind {
	case "integer":
		if value.kind != tokenInteger {
			return nil, deny("esql_literal_type_mismatch")
		}
		current.position++
		return value.value, nil
	case "boolean":
		if value.kind != tokenWord || !oneOf(strings.ToLower(value.text), "true", "false") {
			return nil, deny("esql_literal_type_mismatch")
		}
		current.position++
		return strings.EqualFold(value.text, "true"), nil
	default:
		if value.kind != tokenString {
			return nil, deny("esql_literal_type_mismatch")
		}
		current.position++
		return value.value, nil
	}
}

func (current *parser) word(reason string) (string, error) {
	value := current.peek()
	if value.kind != tokenWord {
		return "", deny(reason)
	}
	current.position++
	return value.text, nil
}

func (current *parser) consumeWord(value string) bool {
	if current.peek().kind == tokenWord && strings.EqualFold(current.peek().text, value) {
		current.position++
		return true
	}
	return false
}

func (current *parser) match(kind tokenKind) bool {
	if current.peek().kind == kind {
		current.position++
		return true
	}
	return false
}

func (current *parser) peek() token { return current.tokens[current.position] }
