package custody

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	return digest("COH-CUSTODY-COMMAND-V1\x00", canonical), nil
}

func IdempotencyBindingDigest(value string) string {
	return digest("COH-CUSTODY-IDEMPOTENCY-V1\x00", []byte(value))
}

func EvidenceBindingDigest(value EvidenceReference) (string, error) {
	if !validEvidence(value) {
		return "", newError(InvalidInput, "evidence_reference_invalid", false, nil)
	}
	canonical, err := canonicalValue(evidenceToWire(value))
	if err != nil {
		return "", err
	}
	return digest("COH-CUSTODY-EVIDENCE-V1\x00", canonical), nil
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
	return digest("COH-CUSTODY-AUTHORIZATION-V1\x00", canonical), nil
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
	return digest("COH-CUSTODY-DECISION-V1\x00", canonical), nil
}

// RecordProvenanceDigest binds the semantic custody event independently of
// storage hashes and audit settlement. This is the parent for the next record.
func RecordProvenanceDigest(value Record) (string, error) {
	if err := validateRecordHashBase(value); err != nil {
		return "", err
	}
	wire := struct {
		CustodyID                string      `json:"custody_id"`
		Case                     caseWire    `json:"case"`
		Sequence                 uint64      `json:"sequence"`
		Command                  commandWire `json:"command"`
		IntentDigest             string      `json:"intent_digest"`
		AuthorizationDigest      string      `json:"authorization_digest"`
		DecisionDigest           string      `json:"decision_digest"`
		RevocationDigest         string      `json:"revocation_digest"`
		EvidenceVerifiedDigest   string      `json:"evidence_verified_digest"`
		PreviousProvenanceDigest *string     `json:"previous_provenance_digest"`
		OccurredAt               string      `json:"occurred_at"`
	}{value.CustodyID, caseToWire(value.Case), value.Sequence, commandToWire(value.Command),
		value.IntentDigest, value.AuthorizationDigest, value.DecisionDigest, value.RevocationDigest,
		value.EvidenceVerifiedDigest, clonePointer(value.PreviousProvenanceDigest), formatTime(value.OccurredAt)}
	canonical, err := canonicalValue(wire)
	if err != nil {
		return "", err
	}
	return digest("COH-CUSTODY-PROVENANCE-V1\x00", canonical), nil
}

// RecordPrecommitDigest is safe to embed in the deterministic audit event. It
// deliberately excludes AuditEventDigest, RecordDigest, and ChainHash.
func RecordPrecommitDigest(value Record) (string, error) {
	if err := validateRecordHashBase(value); err != nil {
		return "", err
	}
	if !digestPattern.MatchString(value.ProvenanceDigest) {
		return "", newError(InvalidInput, "record_provenance_required", false, nil)
	}
	wire := struct {
		Record    recordWire `json:"record"`
		PriorHead headWire   `json:"prior_head"`
	}{recordToWire(Record{SchemaVersion: value.SchemaVersion, ContractVersion: value.ContractVersion,
		CustodyID: value.CustodyID, Case: value.Case, Sequence: value.Sequence,
		PreviousChainHash: value.PreviousChainHash, Command: cloneCommand(value.Command),
		IntentDigest: value.IntentDigest, AuthorizationDigest: value.AuthorizationDigest,
		DecisionDigest: value.DecisionDigest, RevocationDigest: value.RevocationDigest,
		EvidenceVerifiedDigest:   value.EvidenceVerifiedDigest,
		PreviousProvenanceDigest: clonePointer(value.PreviousProvenanceDigest),
		ProvenanceDigest:         value.ProvenanceDigest, OccurredAt: value.OccurredAt}), headToWire(value.Command.ExpectedHead)}
	canonical, err := canonicalValue(wire)
	if err != nil {
		return "", err
	}
	return digest("COH-CUSTODY-PRECOMMIT-V1\x00", canonical), nil
}

func RecordBindingDigest(value Record) (string, error) {
	if err := validateRecordHashBase(value); err != nil || !allDigests(value.ProvenanceDigest, value.AuditEventDigest) {
		return "", newError(InvalidInput, "record_binding_invalid", false, err)
	}
	copyValue := cloneRecord(value)
	copyValue.RecordDigest = ""
	copyValue.ChainHash = ""
	canonical, err := canonicalValue(recordToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-CUSTODY-RECORD-V1\x00", canonical), nil
}

func RecordChainHash(value Record) (string, error) {
	if err := validateRecordHashBase(value); err != nil ||
		!allDigests(value.ProvenanceDigest, value.AuditEventDigest, value.RecordDigest) {
		return "", newError(InvalidInput, "record_chain_input_invalid", false, err)
	}
	copyValue := cloneRecord(value)
	copyValue.ChainHash = GenesisHash
	canonical, err := canonicalValue(recordToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-CUSTODY-CHAIN-V1\x00", canonical), nil
}

func CanonicalRecord(value Record) ([]byte, error) {
	if err := validateRecord(value); err != nil {
		return nil, err
	}
	return canonicalValue(recordToWire(value))
}

func ReceiptBindingDigest(value Receipt) (string, error) {
	if value.SchemaVersion != ReceiptSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validCase(value.Case) ||
		!allDigests(value.IdempotencyDigest, value.IntentDigest, value.DecisionDigest, value.RecordDigest,
			value.ChainHash, value.AuditEventDigest, value.ProvenanceDigest) ||
		!uuidPattern.MatchString(value.CustodyID) || value.Sequence == 0 || !validTime(value.CreatedAt) {
		return "", newError(InvalidInput, "receipt_binding_invalid", false, nil)
	}
	copyValue := value
	copyValue.ReceiptDigest = ""
	canonical, err := canonicalValue(receiptToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-CUSTODY-RECEIPT-V1\x00", canonical), nil
}

func CanonicalReceipt(value Receipt) ([]byte, error) {
	if err := validateReceipt(value); err != nil {
		return nil, err
	}
	return canonicalValue(receiptToWire(value))
}

func validateRecordHashBase(value Record) error {
	if value.SchemaVersion != RecordSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.CustodyID) || !validCase(value.Case) || value.Sequence == 0 ||
		!digestPattern.MatchString(value.PreviousChainHash) || validateCommandShape(value.Command) != nil ||
		value.Command.Case != value.Case || value.Sequence != value.Command.ExpectedHead.Sequence+1 ||
		value.PreviousChainHash != value.Command.ExpectedHead.ChainHash ||
		!allDigests(value.IntentDigest, value.AuthorizationDigest, value.DecisionDigest,
			value.RevocationDigest, value.EvidenceVerifiedDigest) ||
		!pointerDigest(value.PreviousProvenanceDigest) || !validTime(value.OccurredAt) ||
		(value.Sequence == 1) != (value.PreviousProvenanceDigest == nil) {
		return newError(InvalidInput, "record_hash_input_invalid", false, nil)
	}
	return nil
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
