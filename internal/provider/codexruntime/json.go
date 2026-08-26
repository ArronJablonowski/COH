package codexruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	providercontract "github.com/ArronJablonowski/COH/internal/domain/providercontract"
)

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > maximumResponseBytes {
		return newError(providercontract.InvalidInput, "vendor_document_size", false)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(providercontract.InvalidInput, "vendor_document_malformed", false)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(providercontract.InvalidInput, "vendor_document_trailing", false)
	}
	return nil
}

func canonicalJSON(input []byte) ([]byte, error) {
	value, err := decodeUniqueJSON(input, maximumResponseBytes)
	if err != nil {
		return nil, newError(providercontract.InvalidInput, "vendor_json_noncanonical", false)
	}
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, newError(providercontract.InvalidInput, "vendor_json_noncanonical", false)
	}
	return bytes.TrimSuffix(output.Bytes(), []byte{'\n'}), nil
}

func decodeUniqueJSON(input []byte, maximum int) (any, error) {
	if len(input) == 0 || len(input) > maximum {
		return nil, newError(providercontract.InvalidInput, "vendor_document_size", false)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, newError(providercontract.InvalidInput, "vendor_document_trailing", false)
	}
	return value, nil
}

func decodeJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, newError(providercontract.Denied, "vendor_document_depth", false)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, newError(providercontract.InvalidInput, "vendor_document_malformed", false)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, keyOK := keyToken.(string)
			if keyErr != nil || !keyOK {
				return nil, newError(providercontract.InvalidInput, "vendor_object_key", false)
			}
			if _, exists := object[key]; exists {
				return nil, newError(providercontract.Denied, "vendor_duplicate_key", false)
			}
			value, valueErr := decodeJSONValue(decoder, depth+1)
			if valueErr != nil {
				return nil, valueErr
			}
			object[key] = value
		}
		if end, endErr := decoder.Token(); endErr != nil || end != json.Delim('}') {
			return nil, newError(providercontract.InvalidInput, "vendor_object_close", false)
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for decoder.More() {
			value, valueErr := decodeJSONValue(decoder, depth+1)
			if valueErr != nil {
				return nil, valueErr
			}
			array = append(array, value)
		}
		if end, endErr := decoder.Token(); endErr != nil || end != json.Delim(']') {
			return nil, newError(providercontract.InvalidInput, "vendor_array_close", false)
		}
		return array, nil
	default:
		return nil, newError(providercontract.InvalidInput, "vendor_delimiter", false)
	}
}

func digest(domain string, input []byte) string {
	sum := sha256.Sum256(append([]byte(domain), input...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func deterministicUUID(domain, input string) string {
	sum := sha256.Sum256([]byte(domain + input))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	hexValue := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexValue[:8], hexValue[8:12], hexValue[12:16], hexValue[16:20], hexValue[20:])
}

func validText(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n")
}

func jsonObject(value []byte) bool {
	var object map[string]any
	return json.Unmarshal(value, &object) == nil && object != nil
}
