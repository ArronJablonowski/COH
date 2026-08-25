package oidcidentity

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/domain/localidentity"
)

const maximumDocumentBytes = 16 * 1024

func DecodeProviderConfig(input []byte) (ProviderConfig, error) {
	var config ProviderConfig
	if err := decodeStrict(input, &config, "provider_decoding"); err != nil {
		return ProviderConfig{}, err
	}
	if err := ValidateProviderConfig(config); err != nil {
		return ProviderConfig{}, err
	}
	return config, nil
}

func DecodeClaims(input []byte) (Claims, error) {
	var claims Claims
	if err := decodeStrict(input, &claims, "claims_decoding"); err != nil {
		return Claims{}, err
	}
	if err := ValidateClaims(claims); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

func decodeStrict(input []byte, destination any, reason string) error {
	if len(input) == 0 || len(input) > maximumDocumentBytes || rejectDuplicateKeys(input) != nil {
		return oidcError(localidentity.InvalidInput, reason, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return oidcError(localidentity.InvalidInput, reason, nil)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return oidcError(localidentity.InvalidInput, reason, nil)
	}
	return nil
}

func rejectDuplicateKeys(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	var walk func() error
	walk = func() error {
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
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, keyErr := decoder.Token()
				key, keyOK := keyToken.(string)
				if keyErr != nil || !keyOK || seen[key] {
					return oidcError(localidentity.InvalidInput, "duplicate_json_key", keyErr)
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
			return err
		default:
			return oidcError(localidentity.InvalidInput, "json_structure", nil)
		}
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return oidcError(localidentity.InvalidInput, "json_trailing", err)
	}
	return nil
}
