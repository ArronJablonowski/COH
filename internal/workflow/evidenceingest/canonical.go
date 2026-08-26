package evidenceingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
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
	return digest("COH-EVIDENCE-INGEST-COMMAND-V1\x00", canonical), nil
}

func TransportBindingDigest(value TransportContext) (string, error) {
	if err := validateTransport(value); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(transportToWire(value))
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-TRANSPORT-V1\x00", canonical), nil
}

func CanonicalAuthorization(value AuthorizationRequest) ([]byte, error) {
	if err := validateAuthorization(value); err != nil {
		return nil, err
	}
	return canonicalValue(authorizationToWire(value))
}

func AuthorizationBindingDigest(value AuthorizationRequest) (string, error) {
	copyValue := value
	copyValue.AuthorizationDigest = ""
	if err := validateAuthorizationShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(authorizationToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-INGEST-AUTHORIZATION-V1\x00", canonical), nil
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
	return digest("COH-EVIDENCE-INGEST-DECISION-V1\x00", canonical), nil
}

func CanonicalManifest(value ArtifactManifest) ([]byte, error) {
	if err := validateManifest(value); err != nil {
		return nil, err
	}
	return canonicalValue(manifestToWire(value))
}

func ManifestProvenanceDigest(value ArtifactManifest) (string, error) {
	copyValue := value
	copyValue.ProvenanceDigest = ""
	if err := validateManifestShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(manifestToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-ARTIFACT-MANIFEST-PROVENANCE-V1\x00", canonical), nil
}

func CanonicalEncryptedObject(value EncryptedObject) ([]byte, error) {
	if err := validateEncryptedObject(value); err != nil {
		return nil, err
	}
	return canonicalValue(encryptedObjectToWire(value))
}

func EncryptedObjectBindingDigest(value EncryptedObject) (string, error) {
	canonical, err := CanonicalEncryptedObject(value)
	if err != nil {
		return "", err
	}
	return digest("COH-ENCRYPTED-OBJECT-V1\x00", canonical), nil
}

func PublishedObjectBindingDigest(value PublishedObject) (string, error) {
	if err := validatePublishedObject(value); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(publishedObjectToWire(value))
	if err != nil {
		return "", err
	}
	return digest("COH-PUBLISHED-OBJECT-V1\x00", canonical), nil
}

func CanonicalReceipt(value Receipt) ([]byte, error) {
	if err := validateReceipt(value); err != nil {
		return nil, err
	}
	return canonicalValue(receiptToWire(value))
}

func ReceiptBindingDigest(value Receipt) (string, error) {
	copyValue := value
	copyValue.ReceiptDigest = ""
	if err := validateReceiptShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(receiptToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-EVIDENCE-INGEST-RECEIPT-V1\x00", canonical), nil
}

func ArtifactBindingDigest(value domain.ArtifactRef) (string, error) {
	if !validArtifact(value) {
		return "", newError(InvalidInput, "artifact_invalid", false, nil)
	}
	canonical, err := canonicalValue(artifactToWire(value))
	if err != nil {
		return "", err
	}
	return digest("COH-ARTIFACT-REFERENCE-V1\x00", canonical), nil
}

func EncryptionContextBindingDigest(value StageRequest) (string, error) {
	if !validCase(value.Case) || !digestPattern.MatchString(value.ExpectedDigest) ||
		value.ExpectedLength <= 0 || value.ExpectedLength > maximumArtifactBytes ||
		!mediaTypePattern.MatchString(value.MediaType) || !validClassification(value.Classification) ||
		!tokenPattern.MatchString(value.KeyProfile) || !digestPattern.MatchString(value.KeyProfileDigest) ||
		!validTime(value.Deadline) {
		return "", newError(InvalidInput, "encryption_context_invalid", false, nil)
	}
	wire := struct {
		Case             caseWire `json:"case"`
		ExpectedDigest   string   `json:"expected_digest"`
		ExpectedLength   int64    `json:"expected_length"`
		MediaType        string   `json:"media_type"`
		Classification   string   `json:"classification"`
		KeyProfile       string   `json:"key_profile"`
		KeyProfileDigest string   `json:"key_profile_digest"`
	}{caseToWire(value.Case), value.ExpectedDigest, value.ExpectedLength, value.MediaType,
		value.Classification, value.KeyProfile, value.KeyProfileDigest}
	canonical, err := canonicalValue(wire)
	if err != nil {
		return "", err
	}
	return digest("COH-ENCRYPTION-CONTEXT-V1\x00", canonical), nil
}

func IdempotencyBindingDigest(value string) string {
	return digest("COH-EVIDENCE-IDEMPOTENCY-V1\x00", []byte(value))
}

func SourceIdentityDigest(value string) string {
	return digest("COH-EVIDENCE-SOURCE-IDENTITY-V1\x00", []byte(value))
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
