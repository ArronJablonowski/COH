package credentiallease

import (
	"bytes"
	"encoding/json"
	"io"
)

const maximumIssuanceRequestBytes = 32 * 1024

func DecodeIssuanceRequest(input []byte) (IssuanceRequest, error) {
	var request IssuanceRequest
	if len(input) == 0 || len(input) > maximumIssuanceRequestBytes {
		return request, leaseError(InvalidInput, "issuance_decoding", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return IssuanceRequest{}, leaseError(InvalidInput, "issuance_decoding", nil)
	}
	if err := requireEOF(decoder); err != nil {
		return IssuanceRequest{}, err
	}
	if err := ValidateIssuanceRequest(request); err != nil {
		return IssuanceRequest{}, err
	}
	return request, nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return leaseError(InvalidInput, "issuance_decoding", nil)
	}
	return nil
}
