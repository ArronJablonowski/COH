package securityonion

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func decodeUniqueJSON(input []byte, output any, strict bool) error {
	if len(input) == 0 || !json.Valid(input) || scanUniqueJSON(input) != nil {
		return errors.New("invalid vendor JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if strict {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing vendor JSON")
	}
	return nil
}

func scanUniqueJSON(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := scanUniqueValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing vendor JSON")
	}
	return nil
}

func scanUniqueValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("vendor object key invalid")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate vendor object key")
			}
			seen[key] = struct{}{}
			if err := scanUniqueValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("vendor object invalid")
		}
	case '[':
		for decoder.More() {
			if err := scanUniqueValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("vendor array invalid")
		}
	default:
		return errors.New("vendor delimiter invalid")
	}
	return nil
}
