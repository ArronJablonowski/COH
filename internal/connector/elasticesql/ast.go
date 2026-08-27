package elasticesql

type pipeline struct {
	resource   string
	expression expression
	projection []string
	sort       []SortField
	limit      uint64
}

type expression interface{ expressionNode() }

type comparison struct {
	field    string
	operator string
	value    any
}

func (comparison) expressionNode() {}

type logical struct {
	operator string
	left     expression
	right    expression
}

func (logical) expressionNode() {}

type negation struct{ child expression }

func (negation) expressionNode() {}
