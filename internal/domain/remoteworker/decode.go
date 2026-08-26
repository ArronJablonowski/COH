package remoteworker

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func DecodeEnrollmentRequest(input []byte) (EnrollmentRequest, error) {
	var request EnrollmentRequest
	if err := decodeStrict(input, &request); err != nil {
		return EnrollmentRequest{}, err
	}
	if err := ValidateEnrollmentRequest(request); err != nil {
		return EnrollmentRequest{}, err
	}
	request.SignedAttestation = append(json.RawMessage(nil), request.SignedAttestation...)
	return request, nil
}

func DecodeLeaseRequest(input []byte) (LeaseRequest, error) {
	var request LeaseRequest
	if err := decodeStrict(input, &request); err != nil {
		return LeaseRequest{}, err
	}
	if err := ValidateLeaseRequest(request); err != nil {
		return LeaseRequest{}, err
	}
	request.Scope.TargetDigests = append([]string(nil), request.Scope.TargetDigests...)
	return request, nil
}

func DecodeDispatchRequest(input []byte) (DispatchRequest, error) {
	var request DispatchRequest
	if err := decodeStrict(input, &request); err != nil {
		return DispatchRequest{}, err
	}
	if err := ValidateDispatchRequest(request); err != nil {
		return DispatchRequest{}, err
	}
	request.Scope.TargetDigests = append([]string(nil), request.Scope.TargetDigests...)
	return request, nil
}

func DecodeRevocationRequest(input []byte) (RevocationRequest, error) {
	var request RevocationRequest
	if err := decodeStrict(input, &request); err != nil {
		return RevocationRequest{}, err
	}
	if err := ValidateRevocationRequest(request); err != nil {
		return RevocationRequest{}, err
	}
	return request, nil
}

func decodeStrict(input []byte, destination any) error {
	if len(input) == 0 || len(input) > MaximumInputBytes {
		return NewError(InvalidInput, "contract_decoding")
	}
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return NewError(InvalidInput, "contract_decoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return NewError(InvalidInput, "contract_decoding")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return NewError(InvalidInput, "contract_decoding")
	}
	return nil
}
