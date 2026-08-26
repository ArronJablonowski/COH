package opaengine

import (
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
)

var allowedBuiltins = []string{
	"and", "array.concat", "concat", "contains", "count", "endswith",
	"eq", "equal", "gt", "gte", "internal.member_2", "internal.member_3",
	"intersection", "lower", "lt", "lte", "neq", "object.get",
	"object.keys", "or", "set_diff", "startswith", "trim", "trim_prefix",
	"trim_space", "trim_suffix", "union", "upper",
}

func policyCapabilities() *ast.Capabilities {
	available := ast.CapabilitiesForThisVersion(ast.CapabilitiesRegoVersion(ast.RegoV1))
	selected := make([]*ast.Builtin, 0, len(allowedBuiltins))
	for _, builtin := range available.Builtins {
		if slices.Contains(allowedBuiltins, builtin.Name) {
			selected = append(selected, builtin)
		}
	}
	return &ast.Capabilities{
		Builtins: selected, FutureKeywords: available.FutureKeywords,
		Features: available.Features, AllowNet: []string{},
	}
}
