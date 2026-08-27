package elasticquerydsl

type node struct {
	kind    string
	field   FieldRule
	value   any
	values  []any
	bounds  map[string]any
	filter  []node
	should  []node
	mustNot []node
}

type parseState struct{ clauses int }
