package agentphase

import (
	"errors"
	"slices"
)

type ValidationDisposition string

const (
	ValidationAccepted ValidationDisposition = "accepted"
	ValidationRevise   ValidationDisposition = "revise"
	ValidationRejected ValidationDisposition = "rejected"
)

type ValidationCheck struct {
	Code         string   `json:"code"`
	Mandatory    bool     `json:"mandatory"`
	Passed       bool     `json:"passed"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type ValidationDiagnostic struct {
	Code         string   `json:"code"`
	Message      string   `json:"message"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type ValidationRecordV2 struct {
	ContractVersion          string                 `json:"contract_version"`
	Attempt                  uint32                 `json:"attempt"`
	ArtifactDigest           string                 `json:"artifact_digest"`
	ValidatorID              string                 `json:"validator_id"`
	ValidatorDigest          string                 `json:"validator_digest"`
	Disposition              ValidationDisposition  `json:"disposition"`
	Checks                   []ValidationCheck      `json:"checks"`
	Diagnostics              []ValidationDiagnostic `json:"diagnostics"`
	AcceptedArtifactDigest   string                 `json:"accepted_artifact_digest,omitempty"`
	BudgetSettlementDigest   string                 `json:"budget_settlement_digest"`
	PreviousProvenanceDigest string                 `json:"previous_provenance_digest,omitempty"`
	ProvenanceDigest         string                 `json:"provenance_digest"`
}

func NewValidationRecord(attempt uint32, artifact, validatorID, validatorDigest, budget,
	previous string, checks []ValidationCheck, diagnostics []ValidationDiagnostic) (ValidationRecordV2, error) {
	value := ValidationRecordV2{ContractVersion: ValidationRecordVersion, Attempt: attempt,
		ArtifactDigest: artifact, ValidatorID: validatorID, ValidatorDigest: validatorDigest,
		Checks: append([]ValidationCheck(nil), checks...), Diagnostics: append([]ValidationDiagnostic(nil), diagnostics...),
		BudgetSettlementDigest: budget, PreviousProvenanceDigest: previous}
	mandatoryFailed := slices.ContainsFunc(value.Checks, func(check ValidationCheck) bool { return check.Mandatory && !check.Passed })
	if mandatoryFailed {
		value.Disposition = ValidationRevise
	} else {
		value.Disposition, value.AcceptedArtifactDigest = ValidationAccepted, artifact
	}
	value.ProvenanceDigest = validationRecordDigest(value)
	if err := value.Validate(); err != nil {
		return ValidationRecordV2{}, err
	}
	return value, nil
}

func (value ValidationRecordV2) Validate() error {
	if value.ContractVersion != ValidationRecordVersion || value.Attempt < 1 || value.Attempt > 3 ||
		!validDigest(value.ArtifactDigest) || !validToken(value.ValidatorID) || !validDigest(value.ValidatorDigest) ||
		!validDigest(value.BudgetSettlementDigest) || value.PreviousProvenanceDigest != "" && !validDigest(value.PreviousProvenanceDigest) ||
		!validDigest(value.ProvenanceDigest) || value.ProvenanceDigest != validationRecordDigest(value) || len(value.Checks) == 0 {
		return errors.New("validation record binding is invalid")
	}
	for _, check := range value.Checks {
		if !validToken(check.Code) || !validEvidence(check.EvidenceRefs) {
			return errors.New("validation check is invalid")
		}
	}
	for _, diagnostic := range value.Diagnostics {
		if !validToken(diagnostic.Code) || !boundedSafeText(diagnostic.Message, 1, 1024) || !validEvidence(diagnostic.EvidenceRefs) {
			return errors.New("validation diagnostic is invalid")
		}
	}
	failed := slices.ContainsFunc(value.Checks, func(check ValidationCheck) bool { return check.Mandatory && !check.Passed })
	if value.Disposition == ValidationAccepted {
		if failed || value.AcceptedArtifactDigest != value.ArtifactDigest || len(value.Diagnostics) != 0 {
			return errors.New("accepted validation record is inconsistent")
		}
	} else if value.Disposition == ValidationRevise {
		if !failed || value.AcceptedArtifactDigest != "" || len(value.Diagnostics) == 0 {
			return errors.New("revise validation record is inconsistent")
		}
	} else if value.Disposition != ValidationRejected {
		return errors.New("validation disposition is invalid")
	}
	return nil
}

func validationRecordDigest(value ValidationRecordV2) string {
	value.ProvenanceDigest = ""
	return canonicalDigest(value)
}

func validEvidence(values []string) bool {
	if !slices.IsSorted(values) || hasDuplicate(values) {
		return false
	}
	for _, value := range values {
		if !validDigest(value) {
			return false
		}
	}
	return true
}
