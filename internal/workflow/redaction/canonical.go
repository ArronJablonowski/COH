package redaction

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

func CanonicalCommand(value Command) ([]byte, error) {
	if err := validateCommandShape(value); err != nil {
		return nil, err
	}
	return canonicalValue(commandToWire(value))
}

func CanonicalRule(value RuleSet) ([]byte, error) {
	if err := ValidateRule(value); err != nil {
		return nil, err
	}
	return canonicalValue(ruleToWire(value))
}

func CanonicalPlan(value ApprovedPlan) ([]byte, error) {
	if err := ValidatePlan(value); err != nil {
		return nil, err
	}
	return canonicalValue(planToWire(value))
}

func CanonicalAuthorization(value AuthorizationRequest) ([]byte, error) {
	if err := ValidateAuthorization(value); err != nil {
		return nil, err
	}
	return canonicalValue(authorizationToWire(value))
}

func CanonicalDecision(value Decision) ([]byte, error) {
	if err := ValidateDecision(value); err != nil {
		return nil, err
	}
	return canonicalValue(decisionToWire(value))
}

func IntentBindingDigest(value Command) (string, error) {
	canonical, err := CanonicalCommand(value)
	if err != nil {
		return "", err
	}
	return digest("COH-REDACTION-INTENT-V1\x00", canonical), nil
}

func IdempotencyBindingDigest(value string) (string, error) {
	if !validOpaque(value, 1, 256) {
		return "", newError(InvalidInput, "idempotency_key_invalid", false, nil)
	}
	return digest("COH-REDACTION-IDEMPOTENCY-V1\x00", []byte(value)), nil
}

func RuleSigningBytes(value RuleSet) ([]byte, error) {
	copyValue := cloneRule(value)
	copyValue.RuleDigest, copyValue.Signature = "", ""
	if err := validateRuleShape(copyValue, false); err != nil {
		return nil, err
	}
	return canonicalValue(ruleToWire(copyValue))
}

func RuleBindingDigest(value RuleSet) (string, error) {
	canonical, err := RuleSigningBytes(value)
	if err != nil {
		return "", err
	}
	return digest("COH-REDACTION-RULE-V1\x00", canonical), nil
}

func MappingPlanBindingDigest(value ApprovedPlan) (string, error) {
	if err := validatePlanCore(value); err != nil {
		return "", err
	}
	wire := struct {
		SchemaVersion        string       `json:"schema_version"`
		ContractVersion      string       `json:"contract_version"`
		PlanID               string       `json:"plan_id"`
		Case                 caseWire     `json:"case"`
		Source               evidenceWire `json:"source"`
		RuleID               string       `json:"rule_id"`
		RuleRevision         uint64       `json:"rule_revision"`
		RuleDigest           string       `json:"rule_digest"`
		ReasonDigest         string       `json:"reason_digest"`
		Spans                []spanWire   `json:"spans"`
		OutputMediaType      string       `json:"output_media_type"`
		OutputClassification string       `json:"output_classification"`
		MaximumOutputBytes   int64        `json:"maximum_output_bytes"`
	}{value.SchemaVersion, value.ContractVersion, value.PlanID, caseToWire(value.Case), evidenceToWire(value.Source),
		value.RuleID, value.RuleRevision, value.RuleDigest, value.ReasonDigest, spansToWire(value.Spans),
		value.OutputMediaType, value.OutputClassification, value.MaximumOutputBytes}
	canonical, err := canonicalValue(wire)
	if err != nil {
		return "", err
	}
	return digest("COH-REDACTION-MAPPING-PLAN-V1\x00", canonical), nil
}

func PlanBindingDigest(value ApprovedPlan) (string, error) {
	copyValue := clonePlan(value)
	copyValue.PlanDigest = ""
	if err := validatePlanShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(planToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-REDACTION-PLAN-V1\x00", canonical), nil
}

func ApprovalUseBindingDigest(value ApprovalUseProof) (string, error) {
	copyValue := value
	copyValue.ProofDigest = ""
	if err := validateApprovalShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(approvalToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-REDACTION-APPROVAL-USE-V1\x00", canonical), nil
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
	return digest("COH-REDACTION-AUTHORIZATION-V1\x00", canonical), nil
}

func DecisionBindingDigest(value Decision) (string, error) {
	copyValue := cloneDecision(value)
	copyValue.DecisionDigest = ""
	if err := validateDecisionShape(copyValue, false); err != nil {
		return "", err
	}
	canonical, err := canonicalValue(decisionToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-REDACTION-DECISION-V1\x00", canonical), nil
}

func MappingProvenanceDigest(value Mapping) (string, error) {
	if err := validateMappingBase(value); err != nil {
		return "", err
	}
	copyValue := cloneMapping(value)
	copyValue.ProvenanceDigest, copyValue.MappingDigest = "", ""
	canonical, err := canonicalValue(mappingToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-REDACTION-MAPPING-PROVENANCE-V1\x00", canonical), nil
}

func MappingBindingDigest(value Mapping) (string, error) {
	if err := validateMappingBase(value); err != nil || !digestPattern.MatchString(value.ProvenanceDigest) {
		return "", newError(InvalidInput, "mapping_binding_invalid", false, err)
	}
	copyValue := cloneMapping(value)
	copyValue.MappingDigest = ""
	canonical, err := canonicalValue(mappingToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-REDACTION-MAPPING-V1\x00", canonical), nil
}

func RecordProvenanceDigest(value Record) (string, error) {
	if err := validateRecordBase(value); err != nil {
		return "", err
	}
	copyValue := cloneRecord(value)
	copyValue.ProvenanceDigest, copyValue.AuditEventDigest, copyValue.RecordDigest = "", "", ""
	canonical, err := canonicalValue(recordToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-REDACTION-RECORD-PROVENANCE-V1\x00", canonical), nil
}

func RecordPrecommitDigest(value Record) (string, error) {
	if err := validateRecordBase(value); err != nil || !digestPattern.MatchString(value.ProvenanceDigest) {
		return "", newError(InvalidInput, "record_precommit_invalid", false, err)
	}
	copyValue := cloneRecord(value)
	copyValue.AuditEventDigest, copyValue.RecordDigest = "", ""
	canonical, err := canonicalValue(recordToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-REDACTION-RECORD-PRECOMMIT-V1\x00", canonical), nil
}

func RecordBindingDigest(value Record) (string, error) {
	if err := validateRecordBase(value); err != nil || !allDigests(value.ProvenanceDigest, value.AuditEventDigest) {
		return "", newError(InvalidInput, "record_binding_invalid", false, err)
	}
	copyValue := cloneRecord(value)
	copyValue.RecordDigest = ""
	canonical, err := canonicalValue(recordToWire(copyValue))
	if err != nil {
		return "", err
	}
	return digest("COH-REDACTION-RECORD-V1\x00", canonical), nil
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
	return digest("COH-REDACTION-RECEIPT-V1\x00", canonical), nil
}

func CanonicalMapping(value Mapping) ([]byte, error) {
	if err := ValidateMapping(value); err != nil {
		return nil, err
	}
	return canonicalValue(mappingToWire(value))
}
func CanonicalRecord(value Record) ([]byte, error) {
	if err := ValidateRecord(value); err != nil {
		return nil, err
	}
	return canonicalValue(recordToWire(value))
}
func CanonicalReceipt(value Receipt) ([]byte, error) {
	if err := ValidateReceipt(value); err != nil {
		return nil, err
	}
	return canonicalValue(receiptToWire(value))
}

func canonicalValue(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, newError(InternalFailure, "encoding_failed", false, err)
	}
	canonical, err := domaincontract.Canonicalize(encoded)
	if err != nil {
		return nil, newError(InternalFailure, "canonicalization_failed", false, err)
	}
	return canonical, nil
}

func digest(domainName string, value []byte) string {
	sum := sha256.Sum256(append([]byte(domainName), value...))
	return "sha256:" + hex.EncodeToString(sum[:])
}
