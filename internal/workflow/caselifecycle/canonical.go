package caselifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func CanonicalCommand(value Command) ([]byte, error) {
	if err := validateCommandShape(value); err != nil {
		return nil, err
	}
	return canonicalValue(commandToWire(value))
}

func CommandBindingDigest(value Command) (string, error) {
	canonical, err := CanonicalCommand(value)
	if err != nil {
		return "", err
	}
	return digest("COH-CASE-COMMAND-V1\x00", canonical), nil
}

func CanonicalAuthorization(value AuthorizationRequest) ([]byte, error) {
	if err := validateAuthorizationShape(value, true); err != nil {
		return nil, err
	}
	return canonicalValue(authorizationToWire(value))
}

func AuthorizationBindingDigest(value AuthorizationRequest) (string, error) {
	copyValue := cloneAuthorization(value)
	copyValue.AuthorizationDigest = ""
	if err := validateAuthorizationShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(authorizationToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-CASE-AUTHORIZATION-V1\x00", canonical), nil
}

func CanonicalDecision(value Decision) ([]byte, error) {
	if err := validateDecision(value); err != nil {
		return nil, err
	}
	return canonicalValue(decisionToWire(value))
}

func DecisionBindingDigest(value Decision) (string, error) {
	copyValue := value
	copyValue.DecisionDigest = ""
	if err := validateDecisionShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(decisionToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-CASE-DECISION-V1\x00", canonical), nil
}

func CanonicalRecord(value Record) ([]byte, error) {
	if err := validateRecord(value); err != nil {
		return nil, err
	}
	return canonicalValue(recordToWire(value))
}

func RecordProvenanceDigest(value Record) (string, error) {
	copyValue := cloneRecord(value)
	copyValue.ProvenanceDigest = ""
	if err := validateRecordShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(recordToWire(copyValue))
	if err != nil {
		return "", err
	}
	prior := ""
	if value.PreviousProvenanceDigest != nil {
		prior = *value.PreviousProvenanceDigest
	}
	return digest("COH-CASE-PROVENANCE-V1\x00", slices.Concat([]byte(prior), []byte{0}, canonical)), nil
}

func CanonicalReceipt(value Receipt) ([]byte, error) {
	if err := validateReceipt(value); err != nil {
		return nil, err
	}
	return canonicalValue(receiptToWire(value))
}

func ReceiptBindingDigest(value Receipt) (string, error) {
	copyValue := cloneReceipt(value)
	copyValue.ReceiptDigest = ""
	if err := validateReceiptShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(receiptToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-CASE-RECEIPT-V1\x00", canonical), nil
}

func IdempotencyBindingDigest(value string) string {
	return digest("COH-CASE-IDEMPOTENCY-V1\x00", []byte(value))
}

// RetentionPolicyBindingDigest converts the canonical retention-policy
// identifier carried by case lifecycle records into the immutable digest form
// consumed by downstream custody records.
func RetentionPolicyBindingDigest(value string) (string, error) {
	if !uuidPattern.MatchString(value) {
		return "", newError(InvalidInput, "retention_policy_id_invalid", false, nil)
	}
	return digest("COH-CASE-RETENTION-POLICY-V1\x00", []byte(value)), nil
}

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(InternalFailure, "encoding_failed", false, nil)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(InternalFailure, "canonicalization_failed", false, nil)
	}
	return canonical, nil
}

func digest(domainName string, value []byte) string {
	sum := sha256.Sum256(append([]byte(domainName), value...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(timestampLayout)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || formatTime(parsed) != value {
		return time.Time{}, newError(Denied, "timestamp_invalid", false, nil)
	}
	return parsed.UTC(), nil
}
