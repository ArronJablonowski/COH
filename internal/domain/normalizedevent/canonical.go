package normalizedevent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

// canonicalize implements COH-NJ-1. It retains COH-CJ-1's duplicate-key,
// depth, ordering, string, and integer rules while adding exact fixed-decimal
// numbers. Exponents, negative zero, insignificant leading zeroes, and
// insignificant trailing fractional zeroes are denied so each accepted number
// has one byte representation.
func canonicalize(input []byte) ([]byte, error) {
	value, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return nil, err
	}
	var output bytes.Buffer
	if err := writeCanonical(&output, value); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func writeCanonical(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		output.WriteString(strconv.FormatBool(typed))
	case string:
		if err := writeCanonicalString(output, typed); err != nil {
			return err
		}
	case json.Number:
		if !canonicalNumber(typed.String()) {
			return fmt.Errorf("non-canonical normalization number")
		}
		output.WriteString(typed.String())
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonical(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonicalString(output, key); err != nil {
				return err
			}
			output.WriteByte(':')
			if err := writeCanonical(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return fmt.Errorf("unsupported normalization JSON value")
	}
	return nil
}

func writeCanonicalString(output *bytes.Buffer, value string) error {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	output.Write(bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'}))
	return nil
}

func canonicalNumber(value string) bool {
	negative := strings.HasPrefix(value, "-")
	unsigned := strings.TrimPrefix(value, "-")
	if unsigned == "" || strings.ContainsAny(unsigned, "eE+") {
		return false
	}
	parts := strings.Split(unsigned, ".")
	if len(parts) > 2 || !canonicalIntegerMagnitude(parts[0]) {
		return false
	}
	if len(parts) == 2 && (parts[1] == "" || parts[1][len(parts[1])-1] == '0' || !digits(parts[1])) {
		return false
	}
	if negative && parts[0] == "0" && (len(parts) == 1 || allZero(parts[1])) {
		return false
	}
	return true
}

func canonicalIntegerMagnitude(value string) bool {
	return value == "0" || value != "" && value[0] != '0' && digits(value)
}

func digits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func allZero(value string) bool {
	for _, character := range value {
		if character != '0' {
			return false
		}
	}
	return true
}
