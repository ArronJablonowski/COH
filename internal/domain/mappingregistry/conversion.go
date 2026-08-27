package mappingregistry

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func applyOperation(rule Rule, input any, maxValueBytes uint32) (any, error) {
	var output any
	var err error
	switch rule.Operation {
	case Copy, TimestampReference:
		output = input
	case Constant:
		output, err = decodeScalar(rule.ConstantValue)
	case Enum:
		output, err = applyEnum(rule, input)
	case ToInteger:
		output, err = convertInteger(rule, input)
	case ToString:
		output, err = convertString(input)
	default:
		return nil, newError(InvalidInput, RuleInvalid, nil)
	}
	if err != nil {
		return nil, err
	}
	if !runtimeType(output, rule.OutputType) {
		return nil, newError(InvalidInput, TypeMismatch, nil)
	}
	key, err := scalarKey(output)
	if err != nil || len(key) > int(maxValueBytes) {
		return nil, newError(InvalidInput, TypeMismatch, err)
	}
	return output, nil
}

func applyEnum(rule Rule, input any) (any, error) {
	wanted, err := scalarKey(input)
	if err != nil {
		return nil, newError(InvalidInput, TypeMismatch, err)
	}
	for _, entry := range rule.EnumTable {
		source, err := decodeScalar(entry.Source)
		if err != nil {
			return nil, newError(InvalidInput, RuleInvalid, err)
		}
		key, err := scalarKey(source)
		if err != nil {
			return nil, newError(InvalidInput, RuleInvalid, err)
		}
		if key == wanted {
			return decodeScalar(entry.Target)
		}
	}
	return nil, newError(InvalidInput, TypeMismatch, nil)
}

func convertInteger(rule Rule, input any) (any, error) {
	text, ok := input.(string)
	if !ok || !canonicalIntegerString(text) {
		return nil, newError(InvalidInput, TypeMismatch, nil)
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || rule.IntegerRange == nil || value < rule.IntegerRange.Minimum || value > rule.IntegerRange.Maximum {
		return nil, newError(InvalidInput, ConversionOverflow, err)
	}
	return json.Number(strconv.FormatInt(value, 10)), nil
}

func convertString(input any) (any, error) {
	switch value := input.(type) {
	case json.Number:
		if !canonicalRuntimeInteger(value.String()) {
			return nil, newError(InvalidInput, TypeMismatch, nil)
		}
		return value.String(), nil
	case bool:
		return strconv.FormatBool(value), nil
	default:
		return nil, newError(InvalidInput, TypeMismatch, nil)
	}
}

func runtimeType(value any, expected ValueType) bool {
	switch expected {
	case String, TimestampText:
		_, ok := value.(string)
		return ok
	case Integer:
		number, ok := value.(json.Number)
		return ok && canonicalRuntimeInteger(number.String())
	case Boolean:
		_, ok := value.(bool)
		return ok
	case Null:
		return value == nil
	default:
		return false
	}
}

func canonicalIntegerString(value string) bool {
	if value == "" || value == "-0" || strings.HasPrefix(value, "+") {
		return false
	}
	unsigned := strings.TrimPrefix(value, "-")
	if unsigned == "" || len(unsigned) > 1 && unsigned[0] == '0' {
		return false
	}
	for _, character := range unsigned {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func canonicalRuntimeInteger(value string) bool {
	if !canonicalIntegerString(value) {
		return false
	}
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}

func decodeScalar(raw json.RawMessage) (any, error) {
	return domaincontract.DecodeUnique(raw)
}

func scalarKey(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", err
	}
	return string(canonical), nil
}
