package splunkparser

func bindFields(names []string, definition indexedDefinition, allowed func(FieldRule) bool, reason string) ([]FieldRule, error) {
	fields := make([]FieldRule, 0, len(names))
	for _, name := range names {
		field, ok := definition.fields[name]
		if !ok {
			return nil, syntaxDenied("field_unknown")
		}
		if !allowed(field) {
			return nil, syntaxDenied(reason)
		}
		fields = append(fields, field)
	}
	return fields, nil
}

func bindAggregations(values []syntaxAggregation, definition indexedDefinition) ([]typedAggregation, error) {
	result := make([]typedAggregation, 0, len(values))
	for _, value := range values {
		aggregation := typedAggregation{function: value.function, alias: value.alias, outputType: "integer"}
		if value.input != "" {
			field, ok := definition.fields[value.input]
			if !ok {
				return nil, syntaxDenied("field_unknown")
			}
			if !field.Aggregatable {
				return nil, syntaxDenied("field_not_aggregatable")
			}
			aggregation.input, aggregation.hasInput = field, true
		}
		switch value.function {
		case "count":
			aggregation.outputType = "integer"
		case "dc":
			if !aggregation.hasInput {
				return nil, syntaxDenied("aggregation_field_required")
			}
			aggregation.outputType = "integer"
		case "sum", "avg":
			if !aggregation.hasInput || !oneOf(aggregation.input.Type, "integer", "bytes") {
				return nil, syntaxDenied("aggregation_type_invalid")
			}
			aggregation.outputType = aggregation.input.Type
		case "min", "max":
			if !aggregation.hasInput || aggregation.input.Type == "boolean" {
				return nil, syntaxDenied("aggregation_type_invalid")
			}
			aggregation.outputType = aggregation.input.Type
		default:
			return nil, syntaxDenied("aggregation_function_invalid")
		}
		result = append(result, aggregation)
	}
	return result, nil
}

func bindSort(values []syntaxSort, query *typedQuery, definition indexedDefinition) ([]typedSort, error) {
	available := map[string]typedSort{}
	if len(query.aggregations) == 0 {
		for _, field := range query.projection {
			if field.Sortable {
				available[field.Name] = typedSort{logical: field.Name, vendor: field.VendorName}
			}
		}
	} else {
		for _, field := range query.groupBy {
			if field.Sortable {
				available[field.Name] = typedSort{logical: field.Name, vendor: field.VendorName}
			}
		}
		for _, aggregation := range query.aggregations {
			available[aggregation.alias] = typedSort{logical: aggregation.alias, vendor: aggregation.alias}
		}
	}
	result := make([]typedSort, 0, len(values))
	for _, value := range values {
		sort, ok := available[value.field]
		if !ok {
			if _, exists := definition.fields[value.field]; exists {
				return nil, syntaxDenied("sort_field_not_output_or_sortable")
			}
			return nil, syntaxDenied("sort_field_unknown")
		}
		sort.direction = value.direction
		result = append(result, sort)
	}
	return result, nil
}

func (q *typedQuery) ensureOutputBounds(definition indexedDefinition, maximumRows uint64, subsearch bool) error {
	if !q.hasHead {
		q.head, q.hasHead = maximumRows, true
	} else if q.head > maximumRows {
		q.head = maximumRows
	}
	if len(q.sort) == 0 {
		if len(q.aggregations) == 0 {
			if subsearch {
				field := q.projection[0]
				q.sort = append(q.sort, typedSort{logical: field.Name, vendor: field.VendorName, direction: "asc"})
				return q.walkSubsearches(func(nested *typedQuery) error {
					return nested.ensureOutputBounds(definition, nested.head, true)
				})
			}
			outputs := map[string]FieldRule{}
			for _, field := range q.projection {
				outputs[field.Name] = field
			}
			for _, stable := range definition.definition.StableSort {
				field, ok := outputs[stable.Name]
				if !ok || !field.Sortable {
					return syntaxDenied("stable_sort_not_output")
				}
				q.sort = append(q.sort, typedSort{logical: field.Name, vendor: field.VendorName, direction: stable.Direction})
			}
		} else if len(q.groupBy) != 0 {
			for _, field := range q.groupBy {
				q.sort = append(q.sort, typedSort{logical: field.Name, vendor: field.VendorName, direction: "asc"})
			}
		} else {
			for _, aggregation := range q.aggregations {
				q.sort = append(q.sort, typedSort{logical: aggregation.alias, vendor: aggregation.alias, direction: "asc"})
			}
		}
	}
	return q.walkSubsearches(func(subsearch *typedQuery) error {
		return subsearch.ensureOutputBounds(definition, subsearch.head, true)
	})
}

func (q *typedQuery) walkSubsearches(visit func(*typedQuery) error) error {
	var walkPredicate func(*typedPredicate) error
	walkPredicate = func(predicate *typedPredicate) error {
		if predicate == nil {
			return nil
		}
		if predicate.subsearch != nil {
			if err := visit(predicate.subsearch); err != nil {
				return err
			}
		}
		if err := walkPredicate(predicate.left); err != nil {
			return err
		}
		return walkPredicate(predicate.right)
	}
	return walkPredicate(q.predicate)
}

func (q *typedQuery) outputContract() ([]Column, []Aggregation) {
	if len(q.aggregations) == 0 {
		columns := make([]Column, 0, len(q.projection))
		for _, field := range q.projection {
			columns = append(columns, Column{LogicalName: field.Name, VendorName: field.VendorName, Type: field.Type, Nullable: true})
		}
		return columns, nil
	}
	columns := make([]Column, 0, len(q.groupBy)+len(q.aggregations))
	for _, field := range q.groupBy {
		columns = append(columns, Column{LogicalName: field.Name, VendorName: field.VendorName, Type: field.Type, Nullable: true})
	}
	aggregations := make([]Aggregation, 0, len(q.aggregations))
	for _, aggregation := range q.aggregations {
		inputLogical, inputVendor := "", ""
		if aggregation.hasInput {
			inputLogical, inputVendor = aggregation.input.Name, aggregation.input.VendorName
		}
		columns = append(columns, Column{LogicalName: aggregation.alias, VendorName: aggregation.alias, Type: aggregation.outputType, Nullable: aggregation.function != "count"})
		aggregations = append(aggregations, Aggregation{Function: aggregation.function, InputLogical: inputLogical,
			InputVendor: inputVendor, OutputName: aggregation.alias, OutputType: aggregation.outputType})
	}
	return columns, aggregations
}

func (q *typedQuery) planSort() []SortRule {
	result := make([]SortRule, 0, len(q.sort))
	for _, sort := range q.sort {
		result = append(result, SortRule{Name: sort.logical, Direction: sort.direction})
	}
	return result
}

func (q *typedQuery) subsearchCount() uint32 {
	var count uint32
	_ = q.walkSubsearches(func(subsearch *typedQuery) error {
		count++
		count += subsearch.subsearchCount()
		return nil
	})
	return count
}

func (q *typedQuery) totalCommandCount() uint32 {
	count := uint32(3)
	if len(q.sort) != 0 {
		count++
	}
	_ = q.walkSubsearches(func(subsearch *typedQuery) error {
		count += subsearch.totalCommandCount()
		return nil
	})
	return count
}
