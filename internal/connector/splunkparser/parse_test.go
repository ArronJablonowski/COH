package splunkparser

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestParseStructuralQueries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		input string
		check func(*testing.T, *syntaxQuery)
	}{
		{
			name:  "projection",
			input: `SEARCH resource=endpoint (action = "blocked" AND NOT host = "lab\"host") OR bytes >= -10 | fields action,event_time,host | sort -event_time,+host | head 100`,
			check: func(t *testing.T, query *syntaxQuery) {
				if query.resourceID != "endpoint" || query.projection.command != "fields" || len(query.projection.fields) != 3 || len(query.sort) != 2 || query.head != 100 || predicateDepth(query.predicate) != 4 {
					t.Fatalf("unexpected projection query: %#v", query)
				}
			},
		},
		{
			name:  "aggregation",
			input: `search resource=network action != "allowed" | STATS COUNT AS events,dc(host) AS hosts,sum(bytes) AS total_bytes BY action,source | sort -events | head 25`,
			check: func(t *testing.T, query *syntaxQuery) {
				if len(query.aggregations) != 3 || len(query.groupBy) != 2 || query.aggregations[1].function != "dc" || query.aggregations[1].input != "host" {
					t.Fatalf("unexpected aggregate query: %#v", query)
				}
			},
		},
		{
			name:  "recursive subsearch",
			input: `search resource=endpoint host IN ([ search resource=endpoint source IN ([ search resource=endpoint action = "blocked" | table source | head 5 ]) | table host | head 10 ]) | fields host | head 100`,
			check: func(t *testing.T, query *syntaxQuery) {
				if query.predicate.kind != predicateSubsearch || query.predicate.subsearch.predicate.kind != predicateSubsearch || query.predicate.subsearch.head != 10 {
					t.Fatalf("unexpected recursive query: %#v", query)
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			query, err := parse(context.Background(), test.input)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			test.check(t, query)
		})
	}
}

func TestParseDeniesMalformedOrUnsafeStructure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		input  string
		reason string
	}{
		{"implicit search", `resource=endpoint action="blocked"`, "explicit_search_required"},
		{"missing resource", `search action="blocked"`, "resource_selector_required"},
		{"uppercase identifier", `search resource=endpoint Host="lab"`, "predicate_field_invalid"},
		{"bare string", `search resource=endpoint host=lab`, "literal_invalid"},
		{"unmatched quote", `search resource=endpoint host="lab`, "string_unterminated"},
		{"invalid escape", `search resource=endpoint host="lab\q"`, "string_escape_invalid"},
		{"backtick", "search resource=endpoint `macro`", "backtick_not_allowed"},
		{"quoted backtick", "search resource=endpoint host=\"`macro`\"", "backtick_not_allowed"},
		{"single quote", `search resource=endpoint host='lab'`, "single_quote_not_allowed"},
		{"semicolon", `search resource=endpoint; delete`, "semicolon_not_allowed"},
		{"dollar", `search resource=endpoint host=$value$`, "dollar_substitution_not_allowed"},
		{"wildcard", `search resource=endpoint host=*`, "wildcard_not_allowed"},
		{"comment", `search resource=endpoint # comment`, "character_not_allowed"},
		{"implicit boolean", `search resource=endpoint host="a" action="b"`, "trailing_tokens"},
		{"dangling boolean", `search resource=endpoint host="a" AND`, "predicate_field_invalid"},
		{"unmatched parenthesis", `search resource=endpoint (host="a"`, "parenthesis_unmatched"},
		{"duplicate projection", `search resource=endpoint | fields host,host`, "projection_field_duplicate"},
		{"duplicate sort", `search resource=endpoint | sort +host,-host`, "sort_field_duplicate"},
		{"sort direction", `search resource=endpoint | sort host`, "sort_direction_required"},
		{"pipeline reorder", `search resource=endpoint | head 5 | fields host`, "pipeline_after_head"},
		{"pipeline repeat", `search resource=endpoint | fields host | table host`, "pipeline_order_invalid"},
		{"search pipeline", `search resource=endpoint | search host="a"`, "pipeline_command_invalid"},
		{"dangerous outer command", `search resource=endpoint | collect index=summary`, "spl_command_external_effect"},
		{"unknown command", `search resource=endpoint | customcommand value`, "spl_command_unclassified"},
		{"subsearch resource widening", `search resource=endpoint host IN ([ search resource=network | table host | head 5 ])`, "subsearch_resource_widening"},
		{"subsearch projection", `search resource=endpoint host IN ([ search resource=endpoint | table host,source | head 5 ])`, "subsearch_shape_invalid"},
		{"subsearch missing head", `search resource=endpoint host IN ([ search resource=endpoint | table host ])`, "subsearch_shape_invalid"},
		{"subsearch excessive head", `search resource=endpoint host IN ([ search resource=endpoint | table host | head 101 ])`, "subsearch_shape_invalid"},
		{"subsearch dangerous command", `search resource=endpoint host IN ([ search resource=endpoint | map search="x" | table host | head 5 ])`, "spl_command_dynamic_execution"},
		{"subsearch syntax", `search resource=endpoint host IN [ search resource=endpoint | table host | head 5 ]`, "subsearch_syntax_invalid"},
		{"trailing comma", `search resource=endpoint | fields host,`, "projection_field_invalid"},
		{"zero head", `search resource=endpoint | head 0`, "head_invalid"},
		{"aggregate alias missing", `search resource=endpoint | stats count`, "aggregation_alias_required"},
		{"aggregate duplicate alias", `search resource=endpoint | stats count AS events,sum(bytes) AS events`, "aggregation_alias_duplicate"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := parse(context.Background(), test.input)
			if err == nil || parseReason(err) != test.reason {
				t.Fatalf("reason = %q (%v), want %q", parseReason(err), err, test.reason)
			}
			if strings.Contains(err.Error(), test.input) {
				t.Fatal("denial reflected caller input")
			}
		})
	}
}

func TestParseHardLimits(t *testing.T) {
	t.Parallel()
	depth := `search resource=endpoint ` + strings.Repeat("NOT ", MaximumPredicateDepth) + `host="a"`
	tokens := `search resource=endpoint ` + strings.Repeat("( ", MaximumTokens)
	commands := `search resource=endpoint | fields host | sort +host | head 1 | fields host | sort +host | head 1 | fields host | head 1`
	subsearch := `search resource=endpoint | table host | head 1`
	subsearchCount := `search resource=endpoint host IN ([ ` + subsearch + ` ]) OR host IN ([ ` + subsearch + ` ]) OR host IN ([ ` + subsearch + ` ]) OR host IN ([ ` + subsearch + ` ]) OR host IN ([ ` + subsearch + ` ])`
	depthThree := `search resource=endpoint host IN ([ search resource=endpoint host IN ([ search resource=endpoint host IN ([ ` + subsearch + ` ]) | table host | head 1 ]) | table host | head 1 ])`
	tests := []struct{ name, input, reason string }{
		{"bytes", strings.Repeat("a", MaximumInputBytes+1), "input_size_invalid"},
		{"tokens", tokens, "token_limit_exceeded"},
		{"commands", commands, "pipeline_after_head"},
		{"predicate depth", depth, "predicate_depth_exceeded"},
		{"subsearch count", subsearchCount, "subsearch_limit_exceeded"},
		{"subsearch depth", depthThree, "subsearch_depth_exceeded"},
	}
	for _, test := range tests {
		_, err := parse(context.Background(), test.input)
		if err == nil || parseReason(err) != test.reason {
			t.Fatalf("%s: reason = %q (%v), want %q", test.name, parseReason(err), err, test.reason)
		}
	}
}

func TestParseHonorsCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := parse(ctx, `search resource=endpoint host="lab"`)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}

func TestTokenizerRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()
	_, err := tokenize(context.Background(), string([]byte{'s', 0xff}))
	if parseReason(err) != "input_encoding_invalid" {
		t.Fatalf("reason = %q", parseReason(err))
	}
}
