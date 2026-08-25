package secretref

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func DecodeReference(input []byte) (Reference, error) {
	var reference Reference
	if err := decodeStrict(input, &reference); err != nil {
		return Reference{}, secretError(InvalidInput, "malformed_reference", nil)
	}
	if err := ValidateReference(reference); err != nil {
		return Reference{}, err
	}
	return reference, nil
}

func DecodeResolutionRequest(input []byte) (ResolutionRequest, error) {
	var request ResolutionRequest
	if err := decodeStrict(input, &request); err != nil {
		return ResolutionRequest{}, secretError(InvalidInput, "malformed_resolution", nil)
	}
	if err := ValidateResolutionRequest(request); err != nil {
		return ResolutionRequest{}, err
	}
	return request, nil
}

func decodeStrict(input []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
