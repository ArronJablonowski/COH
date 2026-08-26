package toolroute

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const (
	maximumRecordBytes = 1 << 20
	intentDigestDomain = "COH-AGENT-LOOP-INTENT-V1\x00"
)

func Digest(value domain.ToolIntent) (string, error) {
	if err := ValidateIntent(value); err != nil {
		return "", err
	}
	payload := struct {
		OperationID    string         `json:"operation_id"`
		Case           domain.CaseRef `json:"case"`
		Tool           string         `json:"tool"`
		Action         string         `json:"action"`
		TargetDigest   string         `json:"target_digest"`
		ArgumentDigest string         `json:"argument_digest"`
	}{value.OperationID, value.Case, value.Tool, value.Action, value.TargetDigest, value.ArgumentDigest}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", newError(Internal, "intent_encoding_failed", nil)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newError(Internal, "intent_canonicalization_failed", nil)
	}
	sum := sha256.Sum256(append([]byte(intentDigestDomain), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func CanonicalIntent(value IntentRecord) ([]byte, error) {
	if err := ValidateIntentRecord(value); err != nil {
		return nil, err
	}
	return canonical(value)
}

func CanonicalReceipt(value ReceiptRecord) ([]byte, error) {
	if err := ValidateReceiptRecord(value); err != nil {
		return nil, err
	}
	return canonical(value)
}

func CanonicalState(value StateRecord) ([]byte, error) {
	if err := ValidateStateRecord(value); err != nil {
		return nil, err
	}
	return canonical(value)
}

func DecodeIntent(input []byte) (IntentRecord, error) {
	var value IntentRecord
	if err := decodeExact(input, &value); err != nil {
		return IntentRecord{}, err
	}
	return value, ValidateIntentRecord(value)
}

func DecodeReceipt(input []byte) (ReceiptRecord, error) {
	var value ReceiptRecord
	if err := decodeExact(input, &value); err != nil {
		return ReceiptRecord{}, err
	}
	return value, ValidateReceiptRecord(value)
}

func DecodeState(input []byte) (StateRecord, error) {
	var value StateRecord
	if err := decodeExact(input, &value); err != nil {
		return StateRecord{}, err
	}
	return value, ValidateStateRecord(value)
}

func canonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(Internal, "record_encoding_failed", nil)
	}
	result, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(Denied, "record_canonicalization_failed", nil)
	}
	return result, nil
}

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > maximumRecordBytes {
		return newError(Denied, "record_size_invalid", nil)
	}
	decoded, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return newError(Denied, "record_duplicate_or_malformed", nil)
	}
	target := reflect.TypeOf(output)
	if target == nil || target.Kind() != reflect.Pointer || target.Elem().Kind() != reflect.Struct ||
		!requiredFieldsPresent(decoded, target.Elem()) {
		return newError(Denied, "record_required_field_missing", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "record_malformed", nil)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "record_trailing_data", nil)
	}
	return nil
}

func requiredFieldsPresent(value any, target reflect.Type) bool {
	object, ok := value.(map[string]any)
	if !ok {
		return false
	}
	for index := 0; index < target.NumField(); index++ {
		field := target.Field(index)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		if _, found := object[name]; !found {
			return false
		}
	}
	return true
}
