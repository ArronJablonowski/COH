package securityonion

import (
	"slices"
	"strconv"
	"strings"
)

func renderOQLNode(value oqlNode) string {
	switch value.kind {
	case "match_all":
		return "*"
	case "term":
		return value.field.VendorName + ":" + renderOQLScalar(value.value)
	case "terms":
		parts := make([]string, len(value.values))
		for index := range value.values {
			parts[index] = value.field.VendorName + ":" + renderOQLScalar(value.values[index])
		}
		return "(" + strings.Join(parts, " OR ") + ")"
	case "exists":
		return value.field.VendorName + ":*"
	case "range":
		lower, lowerInclusive := "*", true
		upper, upperInclusive := "*", true
		if item, ok := value.bounds["gt"]; ok {
			lower, lowerInclusive = renderOQLScalar(item), false
		} else if item, ok := value.bounds["gte"]; ok {
			lower = renderOQLScalar(item)
		}
		if item, ok := value.bounds["lt"]; ok {
			upper, upperInclusive = renderOQLScalar(item), false
		} else if item, ok := value.bounds["lte"]; ok {
			upper = renderOQLScalar(item)
		}
		left, right := "[", "]"
		if !lowerInclusive {
			left = "{"
		}
		if !upperInclusive {
			right = "}"
		}
		return value.field.VendorName + ":" + left + lower + " TO " + upper + right
	case "bool":
		parts := []string{}
		if len(value.filter) > 0 {
			parts = append(parts, joinOQLNodes(value.filter, " AND "))
		}
		if len(value.should) > 0 {
			parts = append(parts, joinOQLNodes(value.should, " OR "))
		}
		if len(value.mustNot) > 0 {
			parts = append(parts, "NOT "+joinOQLNodes(value.mustNot, " OR "))
		}
		return "(" + strings.Join(parts, ") AND (") + ")"
	default:
		return ""
	}
}

func joinOQLNodes(values []oqlNode, separator string) string {
	parts := make([]string, len(values))
	for index := range values {
		parts[index] = renderOQLNode(values[index])
	}
	slices.Sort(parts)
	return "(" + strings.Join(parts, separator) + ")"
}

func renderOQLScalar(value any) string {
	switch current := value.(type) {
	case int64:
		return strconv.FormatInt(current, 10)
	case bool:
		return strconv.FormatBool(current)
	case string:
		return `"` + escapeOQL(current) + `"`
	default:
		return `""`
	}
}

func escapeOQL(value string) string {
	var result strings.Builder
	for _, current := range value {
		if strings.ContainsRune(`+\-&|!(){}[]^"~*?:/`, current) {
			result.WriteByte('\\')
		}
		result.WriteRune(current)
	}
	return result.String()
}
