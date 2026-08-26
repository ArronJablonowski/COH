package tamperaudit

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func CanonicalEvent(event Event) ([]byte, error) {
	if err := ValidateEvent(event); err != nil {
		return nil, err
	}
	return canonical(event)
}

func CanonicalRecord(record Record) ([]byte, error) {
	if err := ValidateRecord(record); err != nil {
		return nil, err
	}
	return canonical(record)
}

func CanonicalCheckpoint(checkpoint Checkpoint) ([]byte, error) {
	if err := ValidateCheckpoint(checkpoint); err != nil {
		return nil, err
	}
	return canonical(checkpoint)
}

func DecodeRecord(input []byte) (Record, error) {
	canonicalBytes, err := domaincontract.Canonicalize(input)
	if err != nil || subtle.ConstantTimeCompare(input, canonicalBytes) != 1 {
		return Record{}, ErrInvalidInput
	}
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(canonicalBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || ValidateRecord(record) != nil {
		return Record{}, ErrInvalidInput
	}
	return record, nil
}

func DecodeCheckpoint(input []byte) (Checkpoint, error) {
	canonicalBytes, err := domaincontract.Canonicalize(input)
	if err != nil || subtle.ConstantTimeCompare(input, canonicalBytes) != 1 {
		return Checkpoint{}, ErrInvalidInput
	}
	var checkpoint Checkpoint
	decoder := json.NewDecoder(bytes.NewReader(canonicalBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil || ValidateCheckpoint(checkpoint) != nil {
		return Checkpoint{}, ErrInvalidInput
	}
	return checkpoint, nil
}

func canonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, ErrInvalidInput
	}
	result, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, ErrInvalidInput
	}
	return result, nil
}
