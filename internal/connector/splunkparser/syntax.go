package splunkparser

import (
	"errors"
	"fmt"
)

type syntaxQuery struct {
	resourceID   string
	predicate    *syntaxPredicate
	projection   *syntaxProjection
	aggregations []syntaxAggregation
	groupBy      []string
	sort         []syntaxSort
	head         uint64
	hasHead      bool
	commandCount uint32
}

type syntaxPredicate struct {
	kind      predicateKind
	operator  string
	field     string
	literal   syntaxLiteral
	left      *syntaxPredicate
	right     *syntaxPredicate
	subsearch *syntaxQuery
}

type predicateKind uint8

const (
	predicateComparison predicateKind = iota + 1
	predicateAnd
	predicateOr
	predicateNot
	predicateSubsearch
)

type syntaxLiteral struct {
	kind literalKind
	text string
}

type literalKind uint8

const (
	literalString literalKind = iota + 1
	literalInteger
	literalBoolean
)

type syntaxProjection struct {
	command string
	fields  []string
}

type syntaxAggregation struct {
	function string
	input    string
	alias    string
}

type syntaxSort struct {
	field     string
	direction string
}

// ParseError reports a stable denial reason without reflecting caller input.
type ParseError struct {
	Reason string
}

func (e *ParseError) Error() string { return fmt.Sprintf("splunk parser denied: %s", e.Reason) }

func parseReason(err error) string {
	var target *ParseError
	if errors.As(err, &target) {
		return target.Reason
	}
	return "parser_internal"
}

func syntaxDenied(reason string) error { return &ParseError{Reason: reason} }
