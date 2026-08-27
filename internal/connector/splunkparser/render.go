package splunkparser

import (
	"strconv"
	"strings"
)

type mandatoryFilter struct {
	Logical string `json:"logical"`
	Vendor  string `json:"vendor"`
	Value   string `json:"value"`
}

func mandatoryFilters(request CompileRequest, definition indexedDefinition) []mandatoryFilter {
	result := make([]mandatoryFilter, 0, 2)
	if name := definition.definition.TenantField; name != "" {
		field := definition.fields[name]
		result = append(result, mandatoryFilter{Logical: name, Vendor: field.VendorName, Value: request.MandatoryTenantValue})
	}
	if name := definition.definition.SourceField; name != "" {
		field := definition.fields[name]
		result = append(result, mandatoryFilter{Logical: name, Vendor: field.VendorName, Value: request.MandatorySourceValue})
	}
	return result
}

func renderNative(query *typedQuery, mandatory []mandatoryFilter) string {
	return renderQuery(query, mandatory, true)
}

func renderLogical(query *typedQuery) string {
	return renderQuery(query, nil, false)
}

func renderQuery(query *typedQuery, mandatory []mandatoryFilter, native bool) string {
	var builder strings.Builder
	if native {
		builder.WriteString("search index=")
		builder.WriteString(query.resource.VendorIndex)
		for _, filter := range mandatory {
			builder.WriteByte(' ')
			builder.WriteString(filter.Vendor)
			builder.WriteByte('=')
			writeQuoted(&builder, filter.Value)
		}
	} else {
		builder.WriteString("search resource=")
		builder.WriteString(query.resource.ID)
	}
	if query.predicate != nil {
		if native && len(mandatory) != 0 {
			builder.WriteString(" AND (")
			renderPredicate(&builder, query.predicate, mandatory, native)
			builder.WriteByte(')')
		} else {
			builder.WriteByte(' ')
			renderPredicate(&builder, query.predicate, mandatory, native)
		}
	}
	if len(query.aggregations) == 0 {
		builder.WriteString(" | ")
		builder.WriteString(query.projectionCommand)
		builder.WriteByte(' ')
		for index, field := range query.projection {
			if index > 0 {
				builder.WriteString(", ")
			}
			builder.WriteString(fieldName(field, native))
		}
	} else {
		builder.WriteString(" | stats ")
		for index, aggregation := range query.aggregations {
			if index > 0 {
				builder.WriteString(", ")
			}
			builder.WriteString(aggregation.function)
			if aggregation.hasInput {
				builder.WriteByte('(')
				builder.WriteString(fieldName(aggregation.input, native))
				builder.WriteByte(')')
			}
			builder.WriteString(" AS ")
			builder.WriteString(aggregation.alias)
		}
		if len(query.groupBy) != 0 {
			builder.WriteString(" BY ")
			for index, field := range query.groupBy {
				if index > 0 {
					builder.WriteString(", ")
				}
				builder.WriteString(fieldName(field, native))
			}
		}
	}
	if len(query.sort) != 0 {
		builder.WriteString(" | sort 0 ")
		for index, sort := range query.sort {
			if index > 0 {
				builder.WriteString(", ")
			}
			if sort.direction == "desc" {
				builder.WriteByte('-')
			} else {
				builder.WriteByte('+')
			}
			if native {
				builder.WriteString(sort.vendor)
			} else {
				builder.WriteString(sort.logical)
			}
		}
	}
	if query.hasHead {
		builder.WriteString(" | head ")
		builder.WriteString(strconv.FormatUint(query.head, 10))
	}
	return builder.String()
}

func renderPredicate(builder *strings.Builder, predicate *typedPredicate, mandatory []mandatoryFilter, native bool) {
	switch predicate.kind {
	case predicateAnd, predicateOr:
		builder.WriteByte('(')
		renderPredicate(builder, predicate.left, mandatory, native)
		if predicate.kind == predicateAnd {
			builder.WriteString(" AND ")
		} else {
			builder.WriteString(" OR ")
		}
		renderPredicate(builder, predicate.right, mandatory, native)
		builder.WriteByte(')')
	case predicateNot:
		builder.WriteString("NOT (")
		renderPredicate(builder, predicate.left, mandatory, native)
		builder.WriteByte(')')
	case predicateComparison:
		builder.WriteString(fieldName(predicate.field, native))
		builder.WriteByte(' ')
		builder.WriteString(predicate.operator)
		builder.WriteByte(' ')
		writeLiteral(builder, predicate.literal)
	case predicateSubsearch:
		builder.WriteString(fieldName(predicate.field, native))
		builder.WriteString(" IN ([ ")
		builder.WriteString(renderQuery(predicate.subsearch, mandatory, native))
		builder.WriteString(" ])")
	}
}

func writeLiteral(builder *strings.Builder, literal typedLiteral) {
	if literal.kind == literalString {
		writeQuoted(builder, literal.canonical)
		return
	}
	builder.WriteString(literal.canonical)
}

func writeQuoted(builder *strings.Builder, value string) {
	builder.WriteByte('"')
	for _, current := range value {
		if current == '\\' || current == '"' {
			builder.WriteByte('\\')
		}
		builder.WriteRune(current)
	}
	builder.WriteByte('"')
}

func fieldName(field FieldRule, native bool) string {
	if native {
		return field.VendorName
	}
	return field.Name
}

func builtinRegistry() CommandRegistry {
	registry := CommandRegistry{SchemaVersion: RegistryVersion, ContractVersion: ContractVersion, RegistryVersion: ValidatorVersion,
		AllowedCommands: append([]string(nil), allowedCommands...), ProhibitedCommands: append([]CommandRule(nil), prohibitedCommands...)}
	registry.Digest = RegistryDigest(registry)
	return registry
}
