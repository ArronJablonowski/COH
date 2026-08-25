package localidentity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func DecodeActor(input []byte) (Actor, error) {
	var actor Actor
	if err := decodeStrict(input, &actor); err != nil {
		return Actor{}, identityError(InvalidInput, "malformed_actor", nil)
	}
	if err := ValidateActor(actor); err != nil {
		return Actor{}, err
	}
	return actor, nil
}

func DecodeRequest(input []byte) (Request, error) {
	var request Request
	if err := decodeStrict(input, &request); err != nil {
		return Request{}, identityError(InvalidInput, "malformed_request", nil)
	}
	if err := ValidateRequest(request); err != nil {
		return Request{}, err
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
