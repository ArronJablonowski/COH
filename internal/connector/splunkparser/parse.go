package splunkparser

import (
	"context"
	"strconv"
	"strings"
)

func parse(ctx context.Context, input string) (query *syntaxQuery, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if cancellation, ok := recovered.(parserCancellation); ok {
				query, err = nil, cancellation.err
				return
			}
			panic(recovered)
		}
	}()
	tokens, err := tokenize(ctx, input)
	if err != nil {
		return nil, err
	}
	state := &parser{ctx: ctx, tokens: tokens}
	query, err = state.parseQuery(0, "")
	if err != nil {
		return nil, err
	}
	if state.current().kind != tokenEOF {
		return nil, syntaxDenied("trailing_tokens")
	}
	return query, nil
}

type parser struct {
	ctx            context.Context
	tokens         []token
	position       int
	steps          uint32
	subsearches    uint32
	predicateNodes uint32
}

func (p *parser) parseQuery(depth uint32, rootResource string) (*syntaxQuery, error) {
	if depth > MaximumSubsearchDepth {
		return nil, syntaxDenied("subsearch_depth_exceeded")
	}
	if !p.takeKeyword("search") {
		return nil, syntaxDenied("explicit_search_required")
	}
	if !p.takeKeyword("resource") || !p.take(tokenEqual) {
		return nil, syntaxDenied("resource_selector_required")
	}
	resource, err := p.takeName("resource_invalid")
	if err != nil {
		return nil, err
	}
	if rootResource != "" && resource != rootResource {
		return nil, syntaxDenied("subsearch_resource_widening")
	}
	if rootResource == "" {
		rootResource = resource
	}
	query := &syntaxQuery{resourceID: resource, commandCount: 1}
	if !p.atBoundary() {
		query.predicate, err = p.parseOr(depth, rootResource)
		if err != nil {
			return nil, err
		}
		if predicateDepth(query.predicate) > MaximumPredicateDepth {
			return nil, syntaxDenied("predicate_depth_exceeded")
		}
	}
	for p.take(tokenPipe) {
		if query.commandCount >= MaximumCommands {
			return nil, syntaxDenied("command_limit_exceeded")
		}
		query.commandCount++
		command, err := p.takeCommand()
		if err != nil {
			return nil, err
		}
		if query.hasHead {
			return nil, syntaxDenied("pipeline_after_head")
		}
		switch command {
		case "fields", "table":
			if query.projection != nil || len(query.aggregations) != 0 || len(query.sort) != 0 {
				return nil, syntaxDenied("pipeline_order_invalid")
			}
			fields, err := p.parseNameList(MaximumProjection, "projection")
			if err != nil {
				return nil, err
			}
			query.projection = &syntaxProjection{command: command, fields: fields}
		case "stats":
			if query.projection != nil || len(query.aggregations) != 0 || len(query.sort) != 0 {
				return nil, syntaxDenied("pipeline_order_invalid")
			}
			query.aggregations, query.groupBy, err = p.parseStats()
			if err != nil {
				return nil, err
			}
		case "sort":
			if len(query.sort) != 0 {
				return nil, syntaxDenied("pipeline_order_invalid")
			}
			query.sort, err = p.parseSort()
			if err != nil {
				return nil, err
			}
		case "head":
			query.head, err = p.takePositiveInteger("head_invalid")
			if err != nil {
				return nil, err
			}
			query.hasHead = true
		default:
			return nil, syntaxDenied("pipeline_command_invalid")
		}
		if !p.atBoundary() {
			return nil, syntaxDenied("command_arguments_invalid")
		}
	}
	if depth > 0 {
		if query.projection == nil || len(query.projection.fields) != 1 || len(query.aggregations) != 0 || !query.hasHead || query.head > MaximumSubsearchRows {
			return nil, syntaxDenied("subsearch_shape_invalid")
		}
	}
	return query, nil
}

func (p *parser) parseOr(depth uint32, resource string) (*syntaxPredicate, error) {
	left, err := p.parseAnd(depth, resource)
	if err != nil {
		return nil, err
	}
	for p.takeKeyword("or") {
		right, err := p.parseAnd(depth, resource)
		if err != nil {
			return nil, err
		}
		left, err = p.newPredicate(&syntaxPredicate{kind: predicateOr, left: left, right: right})
		if err != nil {
			return nil, err
		}
	}
	return left, nil
}

func (p *parser) parseAnd(depth uint32, resource string) (*syntaxPredicate, error) {
	left, err := p.parseUnary(depth, resource)
	if err != nil {
		return nil, err
	}
	for p.takeKeyword("and") {
		right, err := p.parseUnary(depth, resource)
		if err != nil {
			return nil, err
		}
		left, err = p.newPredicate(&syntaxPredicate{kind: predicateAnd, left: left, right: right})
		if err != nil {
			return nil, err
		}
	}
	return left, nil
}

func (p *parser) parseUnary(depth uint32, resource string) (*syntaxPredicate, error) {
	if p.takeKeyword("not") {
		child, err := p.parseUnary(depth, resource)
		if err != nil {
			return nil, err
		}
		return p.newPredicate(&syntaxPredicate{kind: predicateNot, left: child})
	}
	if p.take(tokenLeftParen) {
		child, err := p.parseOr(depth, resource)
		if err != nil {
			return nil, err
		}
		if !p.take(tokenRightParen) {
			return nil, syntaxDenied("parenthesis_unmatched")
		}
		return child, nil
	}
	return p.parseComparison(depth, resource)
}

func (p *parser) parseComparison(depth uint32, resource string) (*syntaxPredicate, error) {
	field, err := p.takeName("predicate_field_invalid")
	if err != nil {
		return nil, err
	}
	if p.takeKeyword("in") {
		if !p.take(tokenLeftParen) || !p.take(tokenLeftBracket) {
			return nil, syntaxDenied("subsearch_syntax_invalid")
		}
		p.subsearches++
		if p.subsearches > MaximumSubsearches {
			return nil, syntaxDenied("subsearch_limit_exceeded")
		}
		subsearch, err := p.parseQuery(depth+1, resource)
		if err != nil {
			return nil, err
		}
		if !p.take(tokenRightBracket) || !p.take(tokenRightParen) {
			return nil, syntaxDenied("subsearch_unmatched")
		}
		return p.newPredicate(&syntaxPredicate{kind: predicateSubsearch, field: field, operator: "in", subsearch: subsearch})
	}
	operator, ok := p.takeComparisonOperator()
	if !ok {
		return nil, syntaxDenied("comparison_operator_required")
	}
	literal, err := p.takeLiteral()
	if err != nil {
		return nil, err
	}
	return p.newPredicate(&syntaxPredicate{kind: predicateComparison, field: field, operator: operator, literal: literal})
}

func (p *parser) parseNameList(maximum int, class string) ([]string, error) {
	values := make([]string, 0, 4)
	seen := map[string]struct{}{}
	for {
		value, err := p.takeName(class + "_field_invalid")
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[value]; duplicate {
			return nil, syntaxDenied(class + "_field_duplicate")
		}
		seen[value] = struct{}{}
		values = append(values, value)
		if len(values) > maximum {
			return nil, syntaxDenied(class + "_limit_exceeded")
		}
		if !p.take(tokenComma) {
			return values, nil
		}
	}
}

func (p *parser) parseStats() ([]syntaxAggregation, []string, error) {
	aggregations := make([]syntaxAggregation, 0, 2)
	aliases := map[string]struct{}{}
	for {
		if p.current().kind != tokenWord {
			return nil, nil, syntaxDenied("aggregation_function_invalid")
		}
		function := strings.ToLower(p.current().text)
		p.advance()
		if !oneOf(function, "avg", "count", "dc", "max", "min", "sum") {
			return nil, nil, syntaxDenied("aggregation_function_invalid")
		}
		input := ""
		var err error
		if p.take(tokenLeftParen) {
			if function != "count" || p.current().kind != tokenRightParen {
				input, err = p.takeName("aggregation_field_invalid")
				if err != nil {
					return nil, nil, err
				}
			}
			if !p.take(tokenRightParen) {
				return nil, nil, syntaxDenied("aggregation_parenthesis_unmatched")
			}
		} else if function != "count" {
			return nil, nil, syntaxDenied("aggregation_field_required")
		}
		if !p.takeKeyword("as") {
			return nil, nil, syntaxDenied("aggregation_alias_required")
		}
		alias, err := p.takeName("aggregation_alias_invalid")
		if err != nil {
			return nil, nil, err
		}
		if _, duplicate := aliases[alias]; duplicate {
			return nil, nil, syntaxDenied("aggregation_alias_duplicate")
		}
		aliases[alias] = struct{}{}
		aggregations = append(aggregations, syntaxAggregation{function: function, input: input, alias: alias})
		if len(aggregations) > MaximumAggregations {
			return nil, nil, syntaxDenied("aggregation_limit_exceeded")
		}
		if !p.take(tokenComma) {
			break
		}
	}
	var groups []string
	if p.takeKeyword("by") {
		var err error
		groups, err = p.parseNameList(MaximumGroupFields, "group")
		if err != nil {
			return nil, nil, err
		}
	}
	return aggregations, groups, nil
}

func (p *parser) parseSort() ([]syntaxSort, error) {
	values := make([]syntaxSort, 0, 2)
	seen := map[string]struct{}{}
	for {
		direction := ""
		if p.take(tokenPlus) {
			direction = "asc"
		} else if p.take(tokenMinus) {
			direction = "desc"
		} else {
			return nil, syntaxDenied("sort_direction_required")
		}
		field, err := p.takeName("sort_field_invalid")
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[field]; duplicate {
			return nil, syntaxDenied("sort_field_duplicate")
		}
		seen[field] = struct{}{}
		values = append(values, syntaxSort{field: field, direction: direction})
		if len(values) > MaximumSortFields {
			return nil, syntaxDenied("sort_limit_exceeded")
		}
		if !p.take(tokenComma) {
			return values, nil
		}
	}
}

func (p *parser) takeCommand() (string, error) {
	if p.current().kind != tokenWord {
		return "", syntaxDenied("pipeline_command_required")
	}
	command := strings.ToLower(p.current().text)
	p.advance()
	if oneOf(command, "fields", "head", "search", "sort", "stats", "table") {
		return command, nil
	}
	for _, prohibited := range prohibitedCommands {
		if command == prohibited.Name {
			return "", syntaxDenied("spl_command_" + prohibited.Class)
		}
	}
	return "", syntaxDenied("spl_command_unclassified")
}

func (p *parser) takeLiteral() (syntaxLiteral, error) {
	current := p.current()
	switch current.kind {
	case tokenString:
		p.advance()
		return syntaxLiteral{kind: literalString, text: current.text}, nil
	case tokenInteger:
		p.advance()
		return syntaxLiteral{kind: literalInteger, text: current.text}, nil
	case tokenMinus:
		p.advance()
		if p.current().kind != tokenInteger {
			return syntaxLiteral{}, syntaxDenied("integer_literal_invalid")
		}
		value := p.current().text
		p.advance()
		return syntaxLiteral{kind: literalInteger, text: "-" + value}, nil
	case tokenWord:
		if strings.EqualFold(current.text, "true") || strings.EqualFold(current.text, "false") {
			p.advance()
			return syntaxLiteral{kind: literalBoolean, text: strings.ToLower(current.text)}, nil
		}
	}
	return syntaxLiteral{}, syntaxDenied("literal_invalid")
}

func (p *parser) takeComparisonOperator() (string, bool) {
	operators := map[tokenKind]string{tokenEqual: "=", tokenNotEqual: "!=", tokenLess: "<", tokenLessEqual: "<=", tokenGreater: ">", tokenGreaterEqual: ">="}
	value, ok := operators[p.current().kind]
	if ok {
		p.advance()
	}
	return value, ok
}

func (p *parser) takePositiveInteger(reason string) (uint64, error) {
	if p.current().kind != tokenInteger {
		return 0, syntaxDenied(reason)
	}
	value, err := strconv.ParseUint(p.current().text, 10, 64)
	p.advance()
	if err != nil || value == 0 {
		return 0, syntaxDenied(reason)
	}
	return value, nil
}

func (p *parser) takeName(reason string) (string, error) {
	if p.current().kind != tokenWord || !namePattern.MatchString(p.current().text) {
		return "", syntaxDenied(reason)
	}
	value := p.current().text
	p.advance()
	return value, nil
}

func (p *parser) newPredicate(value *syntaxPredicate) (*syntaxPredicate, error) {
	p.predicateNodes++
	if p.predicateNodes > MaximumPredicateNodes {
		return nil, syntaxDenied("predicate_node_limit_exceeded")
	}
	return value, nil
}

func (p *parser) takeKeyword(keyword string) bool {
	if p.current().kind == tokenWord && strings.EqualFold(p.current().text, keyword) {
		p.advance()
		return true
	}
	return false
}

func (p *parser) take(kind tokenKind) bool {
	if p.current().kind == kind {
		p.advance()
		return true
	}
	return false
}

func (p *parser) atBoundary() bool {
	return oneOf(p.current().kind, tokenPipe, tokenRightBracket, tokenEOF)
}

func (p *parser) current() token { return p.tokens[p.position] }

func (p *parser) advance() {
	if p.position < len(p.tokens)-1 {
		p.position++
	}
	p.steps++
	if p.steps&63 == 0 {
		select {
		case <-p.ctx.Done():
			panic(parserCancellation{err: p.ctx.Err()})
		default:
		}
	}
}

type parserCancellation struct{ err error }

func predicateDepth(value *syntaxPredicate) int {
	if value == nil {
		return 0
	}
	left := predicateDepth(value.left)
	right := predicateDepth(value.right)
	return 1 + max(left, right)
}
