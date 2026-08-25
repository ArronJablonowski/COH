package domaincontract

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"
)

type validationState struct {
	context context.Context
	visits  int
}

// Validate checks the common envelope and its registered per-kind payload,
// returning the canonical COH-CJ-1 representation.
func (validator *Validator) Validate(ctx context.Context, input []byte) ([]byte, error) {
	if validator == nil {
		return nil, schemaError("nil validator")
	}
	canonical, err := ValidateEnvelope(ctx, input)
	if err != nil {
		return nil, err
	}
	value, err := DecodeUnique(canonical)
	if err != nil {
		return nil, err
	}
	envelope := value.(map[string]any)
	kind := envelope["kind"].(string)
	target, exists := validator.kinds[kind]
	if !exists {
		return nil, deny("kind %q has no payload schema", kind)
	}
	state := &validationState{context: ctx}
	if err := validator.validateNode(state, target.document, target.document.definitions[target.name], envelope["data"], "$.data"); err != nil {
		return nil, err
	}
	return canonical, nil
}

func (validator *Validator) validateNode(state *validationState, document *schemaDocument, rawNode, value any, location string) error {
	state.visits++
	if state.visits > 100000 {
		return deny("%s: validation work limit", location)
	}
	if err := checkContext(state.context); err != nil {
		return err
	}
	node := rawNode.(map[string]any)
	if reference, exists := node["$ref"]; exists {
		name := strings.TrimPrefix(reference.(string), "#/$defs/")
		definition, ok := document.definitions[name]
		if !ok {
			return deny("%s: unresolved schema reference", location)
		}
		return validator.validateNode(state, document, definition, value, location)
	}
	if choices, exists := node["oneOf"]; exists {
		matches := 0
		for _, choice := range choices.([]any) {
			branch := *state
			err := validator.validateNode(&branch, document, choice, value, location)
			if errors.Is(err, ErrCancelled) {
				return err
			}
			if err == nil {
				matches++
			}
		}
		if matches != 1 {
			return deny("%s: oneOf matched %d choices", location, matches)
		}
		return nil
	}
	if enum, exists := node["enum"]; exists {
		if !enumContains(enum, value) {
			return deny("%s: value is outside enum", location)
		}
	}
	if expected, exists := node["type"]; exists && !matchesType(expected, value) {
		return deny("%s: expected %s", location, expected)
	}
	if err := validator.validateString(node, value, location); err != nil {
		return err
	}
	if err := validateNumber(node, value, location); err != nil {
		return err
	}
	if err := validator.validateArray(state, document, node, value, location); err != nil {
		return err
	}
	return validator.validateObject(state, document, node, value, location)
}

func (validator *Validator) validateString(node map[string]any, value any, location string) error {
	text, ok := value.(string)
	if !ok {
		return nil
	}
	length := int64(utf8.RuneCountInString(text))
	if limit, exists := node["minLength"]; exists && length < schemaInt(limit) {
		return deny("%s: string shorter than minimum", location)
	}
	if limit, exists := node["maxLength"]; exists && length > schemaInt(limit) {
		return deny("%s: string longer than maximum", location)
	}
	if pattern, exists := node["pattern"]; exists && !validator.patterns[pattern.(string)].MatchString(text) {
		return deny("%s: string does not match pattern", location)
	}
	return nil
}

func validateNumber(node map[string]any, value any, location string) error {
	number, ok := value.(json.Number)
	if !ok {
		return nil
	}
	actual, ok := new(big.Rat).SetString(number.String())
	if !ok {
		return deny("%s: invalid number", location)
	}
	for _, boundary := range []struct {
		name string
		less bool
	}{{"minimum", true}, {"maximum", false}} {
		limitValue, exists := node[boundary.name]
		if !exists {
			continue
		}
		limit, ok := new(big.Rat).SetString(limitValue.(json.Number).String())
		if !ok {
			return deny("%s: invalid schema number", location)
		}
		comparison := actual.Cmp(limit)
		if boundary.less && comparison < 0 || !boundary.less && comparison > 0 {
			return deny("%s: number outside %s", location, boundary.name)
		}
	}
	return nil
}

func (validator *Validator) validateArray(state *validationState, document *schemaDocument, node map[string]any, value any, location string) error {
	array, ok := value.([]any)
	if !ok {
		return nil
	}
	length := int64(len(array))
	if limit, exists := node["minItems"]; exists && length < schemaInt(limit) {
		return deny("%s: fewer than minimum items", location)
	}
	if limit, exists := node["maxItems"]; exists && length > schemaInt(limit) {
		return deny("%s: more than maximum items", location)
	}
	if itemSchema, exists := node["items"]; exists {
		for index, item := range array {
			if err := validator.validateNode(state, document, itemSchema, item, fmt.Sprintf("%s[%d]", location, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (validator *Validator) validateObject(state *validationState, document *schemaDocument, node map[string]any, value any, location string) error {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	properties, _ := node["properties"].(map[string]any)
	if required, exists := node["required"]; exists {
		for _, item := range required.([]any) {
			name := item.(string)
			if _, present := object[name]; !present {
				return deny("%s.%s: required property missing", location, name)
			}
		}
	}
	for name, item := range object {
		propertySchema, known := properties[name]
		if !known {
			if additional, exists := node["additionalProperties"]; exists && additional == false {
				return deny("%s.%s: additional property", location, name)
			}
			continue
		}
		if err := validator.validateNode(state, document, propertySchema, item, location+"."+name); err != nil {
			return err
		}
	}
	return nil
}

func enumContains(raw, value any) bool {
	for _, candidate := range raw.([]any) {
		if candidate == value {
			return true
		}
	}
	return false
}

func matchesType(raw, value any) bool {
	switch raw {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		number, ok := value.(json.Number)
		return ok && canonicalInteger(number.String())
	case "null":
		return value == nil
	default:
		return false
	}
}

func schemaInt(value any) int64 {
	number := value.(json.Number)
	result, _ := number.Int64()
	return result
}
