package approvallifecycle

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func CanonicalRecord(record Record) ([]byte, error) {
	if err := ValidateRecord(record); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, NewError(InvalidInput, "record_encoding")
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, NewError(InvalidInput, "record_encoding")
	}
	return canonical, nil
}

func DecodeRecord(input []byte) (Record, error) {
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil || subtle.ConstantTimeCompare(input, canonical) != 1 {
		return Record{}, NewError(InvalidInput, "record_not_canonical")
	}
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return Record{}, NewError(InvalidInput, "record_encoding")
	}
	if err := ValidateRecord(record); err != nil {
		return Record{}, err
	}
	return record, nil
}

func Digest(input []byte) string {
	sum := sha256.Sum256(input)
	return "sha256:" + hex.EncodeToString(sum[:])
}
