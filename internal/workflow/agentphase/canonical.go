package agentphase

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strings"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const maximumRecordBytes = 1 << 20

func digestValue(domain string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", newError(Internal, "digest", "encoding_failed", false, nil)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return "", newError(InvalidInput, "digest", "canonicalization_failed", false, nil)
	}
	sum := sha256.Sum256(append([]byte(domain), canonical...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func inputSetDigest(values []string) (string, error) {
	return digestValue("COH-AGENT-PHASE-INPUT-SET-V1\x00", values)
}

func controlDigest(runID, traceID string, policy RetryPolicy) (string, error) {
	return digestValue("COH-AGENT-PHASE-CONTROL-V1\x00", struct {
		RunID       string      `json:"run_id"`
		TraceID     string      `json:"trace_id"`
		RetryPolicy RetryPolicy `json:"retry_policy"`
	}{runID, traceID, policy})
}

func CanonicalInput(value PhaseInput) ([]byte, error) {
	if err := validatePhaseInput(value); err != nil {
		return nil, err
	}
	return canonicalRecord(value)
}

func CanonicalOutput(value PhaseOutput) ([]byte, error) {
	if err := validatePhaseOutput(value); err != nil {
		return nil, err
	}
	return canonicalRecord(value)
}

func DecodeInput(input []byte) (PhaseInput, error) {
	var value PhaseInput
	if err := decodeExact(input, &value); err != nil {
		return PhaseInput{}, err
	}
	return value, validatePhaseInput(value)
}

func DecodeOutput(input []byte) (PhaseOutput, error) {
	var value PhaseOutput
	if err := decodeExact(input, &value); err != nil {
		return PhaseOutput{}, err
	}
	return value, validatePhaseOutput(value)
}

func canonicalRecord(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(Internal, "canonical", "encoding_failed", false, nil)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(Denied, "canonical", "canonicalization_failed", false, nil)
	}
	return canonical, nil
}

func decodeExact(input []byte, output any) error {
	if len(input) == 0 || len(input) > maximumRecordBytes {
		return newError(Denied, "decode", "record_size_invalid", false, nil)
	}
	decoded, err := domaincontract.DecodeUnique(input)
	if err != nil {
		return newError(Denied, "decode", "record_duplicate_or_malformed", false, nil)
	}
	target := reflect.TypeOf(output)
	if target == nil || target.Kind() != reflect.Pointer || target.Elem().Kind() != reflect.Struct ||
		!requiredFieldsPresent(decoded, target.Elem()) {
		return newError(Denied, "decode", "record_required_field_missing", false, nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return newError(Denied, "decode", "record_malformed", false, nil)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return newError(Denied, "decode", "record_trailing_data", false, nil)
	}
	return nil
}

func requiredFieldsPresent(value any, target reflect.Type) bool {
	if target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	switch target.Kind() {
	case reflect.Struct:
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
			member, found := object[name]
			if !found || !requiredFieldsPresent(member, field.Type) {
				return false
			}
		}
	case reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range items {
			if !requiredFieldsPresent(item, target.Elem()) {
				return false
			}
		}
	}
	return true
}
