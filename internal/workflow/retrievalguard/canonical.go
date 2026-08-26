package retrievalguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func ProfileBindingDigest(value InspectionProfile) (string, error) {
	copyValue := cloneProfile(value)
	copyValue.ProfileDigest = ""
	if err := validateProfileShape(copyValue); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(profileToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-RETRIEVAL-PROFILE-V1\x00", canonical), nil
}
func RequestBindingDigest(value Request) (string, error) {
	if err := validateRequestShape(value); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(requestToWire(value))
	if err != nil {
		return "", err
	}
	return digest("COH-RETRIEVAL-REQUEST-V1\x00", canonical), nil
}
func DecisionBindingDigest(value Decision) (string, error) {
	copyValue := value
	copyValue.DecisionDigest = ""
	if err := validateDecisionShape(copyValue); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(decisionToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-RETRIEVAL-DECISION-V1\x00", canonical), nil
}
func FindingsBindingDigest(values []Finding) (string, error) {
	if err := validateFindingsShape(values); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(append([]Finding{}, values...))
	if err != nil {
		return "", err
	}
	return digest("COH-RETRIEVAL-FINDINGS-V1\x00", canonical), nil
}
func provenanceDigest(value Record) (string, error) {
	copyValue := cloneRecord(value)
	copyValue.ProvenanceDigest = ""
	canonical, err := canonicalValue(recordToWire(copyValue))
	if err != nil {
		return "", err
	}
	payload := slices.Concat([]byte(value.PreviousProvenanceDigest), []byte{0}, canonical)
	return digest("COH-RETRIEVAL-PROVENANCE-V1\x00", payload), nil
}
func idempotencyDigest(value string) string {
	return digest("COH-RETRIEVAL-IDEMPOTENCY-V1\x00", []byte(value))
}

func AuditEventBindingDigest(value tamperaudit.Event) (string, error) {
	canonical, err := tamperaudit.CanonicalEvent(value)
	if err != nil {
		return "", newError(Internal, "audit_event_invalid", false, nil)
	}
	return rawDigest(canonical), nil
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
func rawDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func deterministicUUID(domainName, input string) string {
	sum := sha256.Sum256([]byte(domainName + input))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:])
}
func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(timestampLayout)
}
func cloneProfile(value InspectionProfile) InspectionProfile {
	copyValue := value
	copyValue.AllowedMediaTypes = append([]string{}, value.AllowedMediaTypes...)
	return copyValue
}
func cloneInspection(value InspectionResult) InspectionResult {
	copyValue := value
	copyValue.Findings = append([]Finding{}, value.Findings...)
	return copyValue
}
func cloneRequest(value Request) Request {
	copyValue := value
	copyValue.Profile = cloneProfile(value.Profile)
	return copyValue
}
func cloneRecord(value Record) Record {
	copyValue := value
	copyValue.Request = cloneRequest(value.Request)
	copyValue.Inspection = cloneInspection(value.Inspection)
	return copyValue
}
