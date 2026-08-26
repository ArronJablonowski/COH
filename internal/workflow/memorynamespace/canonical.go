package memorynamespace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func AccessDigest(value AccessRequest) (string, error) {
	if err := validateAccessRequest(value); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(accessWire(value))
	if err != nil {
		return "", err
	}
	return digest("COH-MEMORY-ACCESS-REQUEST-V1\x00", canonical), nil
}

func DecisionBindingDigest(value Decision) (string, error) {
	copyValue := value
	copyValue.DecisionDigest = ""
	if err := validateDecisionShape(copyValue); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(decisionWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-MEMORY-ACCESS-DECISION-V1\x00", canonical), nil
}

func ReviewDigest(value ReviewRequest) (string, error) {
	if err := validateReviewRequest(value); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(reviewRequestWire(value))
	if err != nil {
		return "", err
	}
	return digest("COH-MEMORY-REVIEW-REQUEST-V1\x00", canonical), nil
}

func ReviewDecisionBindingDigest(value ReviewDecision) (string, error) {
	copyValue := value
	copyValue.DecisionDigest = ""
	if err := validateReviewDecisionShape(copyValue); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(reviewDecisionWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-MEMORY-REVIEW-DECISION-V1\x00", canonical), nil
}

func retentionDigest(value RetentionPolicy) (string, error) {
	canonical, err := canonicalValue(struct {
		Class        string `json:"class"`
		PolicyDigest string `json:"policy_digest"`
		ExpiresAt    string `json:"expires_at"`
	}{value.Class, value.PolicyDigest, formatTime(value.ExpiresAt)})
	if err != nil {
		return "", err
	}
	return digest("COH-MEMORY-RETENTION-V1\x00", canonical), nil
}

func memoryValueDigest(value artifactWire, valueType string) (string, error) {
	canonical, err := canonicalValue(struct {
		Value     artifactWire `json:"value"`
		ValueType string       `json:"value_type"`
	}{value, valueType})
	if err != nil {
		return "", err
	}
	return digest("COH-MEMORY-VALUE-V1\x00", canonical), nil
}

func intentDigest(value PutRequest) (string, error) {
	canonical, err := canonicalValue(struct {
		SchemaVersion    string        `json:"schema_version"`
		ContractVersion  string        `json:"contract_version"`
		RequestID        string        `json:"request_id"`
		ActorID          string        `json:"actor_id"`
		Namespace        Namespace     `json:"namespace"`
		Scope            Scope         `json:"scope"`
		Key              string        `json:"key"`
		Value            artifactWire  `json:"value"`
		ValueType        string        `json:"value_type"`
		Retention        retentionWire `json:"retention"`
		Review           reviewWire    `json:"review"`
		PolicyDigest     string        `json:"policy_digest"`
		ExpectedRevision uint64        `json:"expected_revision"`
		Deadline         string        `json:"deadline"`
	}{value.SchemaVersion, value.ContractVersion, value.RequestID, value.ActorID, value.Namespace, value.Scope, value.Key, artifactToWire(value.Value),
		value.ValueType, retentionToWire(value.Retention), reviewToWire(value.Review), value.PolicyDigest,
		value.ExpectedRevision, formatTime(value.Deadline)})
	if err != nil {
		return "", err
	}
	return digest("COH-MEMORY-WRITE-INTENT-V1\x00", canonical), nil
}

func provenanceDigest(value Record) (string, error) {
	copyValue := value
	copyValue.ProvenanceDigest = ""
	canonical, err := canonicalValue(recordToWire(copyValue))
	if err != nil {
		return "", err
	}
	payload := slices.Concat([]byte(value.PreviousProvenanceDigest), []byte{0}, canonical)
	return digest("COH-MEMORY-PROVENANCE-V1\x00", payload), nil
}

func idempotencyDigest(value string) string {
	return digest("COH-MEMORY-IDEMPOTENCY-V1\x00", []byte(value))
}

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(Internal, "encoding_failed", false, nil)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(Internal, "canonicalization_failed", false, nil)
	}
	return canonical, nil
}

func digest(domain string, value []byte) string {
	sum := sha256.Sum256(append([]byte(domain), value...))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(timestampLayout)
}
