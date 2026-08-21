// Package domaincontract validates and canonicalizes versioned domain objects.
package domaincontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const MaxInputBytes = 1 << 20

var ErrDenied = errors.New("domain contract denied")

// DecodeUnique parses one bounded JSON value and rejects duplicate object keys
// before ordinary Go decoding can silently keep the final value.
func DecodeUnique(input []byte) (any, error) {
	if len(input) == 0 || len(input) > MaxInputBytes {
		return nil, fmt.Errorf("%w: input size", ErrDenied)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("%w: trailing token %v", ErrDenied, token)
		}
		return nil, fmt.Errorf("%w: trailing data", ErrDenied)
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("%w: nesting depth", ErrDenied)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: malformed JSON", ErrDenied)
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delim {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, keyOK := keyToken.(string)
			if keyErr != nil || !keyOK {
				return nil, fmt.Errorf("%w: object key", ErrDenied)
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("%w: duplicate key %q", ErrDenied, key)
			}
			value, valueErr := decodeValue(decoder, depth+1)
			if valueErr != nil {
				return nil, valueErr
			}
			object[key] = value
		}
		if end, endErr := decoder.Token(); endErr != nil || end != json.Delim('}') {
			return nil, fmt.Errorf("%w: object close", ErrDenied)
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, valueErr := decodeValue(decoder, depth+1)
			if valueErr != nil {
				return nil, valueErr
			}
			array = append(array, value)
		}
		if end, endErr := decoder.Token(); endErr != nil || end != json.Delim(']') {
			return nil, fmt.Errorf("%w: array close", ErrDenied)
		}
		return array, nil
	default:
		return nil, fmt.Errorf("%w: unexpected delimiter", ErrDenied)
	}
}
