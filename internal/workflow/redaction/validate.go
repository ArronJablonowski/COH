package redaction

import (
	"time"
)

const genesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

func ValidateCommand(value Command, now time.Time) error {
	if err := validateCommandShape(value); err != nil {
		return err
	}
	if !validTime(now) || !value.Deadline.After(now) {
		return newError(InvalidInput, "command_deadline_invalid", false, nil)
	}
	return nil
}

func validateCommandShape(value Command) error {
	if value.SchemaVersion != CommandSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validOpaque(value.IdempotencyKey, 1, 256) ||
		!validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) || !boundedRevision(value.ActorRevision) ||
		!validEvidence(value.Source) || !allDigests(value.RuleDigest, value.PlanDigest, value.ReasonDigest,
		value.KeyProfileDigest, value.PolicyDigest) || !mediaTypePattern.MatchString(value.OutputMediaType) ||
		!validClassification(value.OutputClassification) || !tokenPattern.MatchString(value.KeyProfile) ||
		!boundedRevision(value.ExpectedCaseRevision) || !validHead(value.ExpectedCustodyHead) ||
		value.ExpectedCustodyHead.Case != value.Case || !validTime(value.Deadline) {
		return newError(InvalidInput, "command_invalid", false, nil)
	}
	return nil
}

func ValidateRule(value RuleSet) error {
	if err := validateRuleShape(value, true); err != nil {
		return err
	}
	want, err := RuleBindingDigest(value)
	if err != nil || want != value.RuleDigest {
		return newError(Denied, "rule_digest_invalid", false, err)
	}
	return nil
}

func validateRuleShape(value RuleSet, bound bool) error {
	if value.SchemaVersion != RuleSetSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RuleID) || !boundedRevision(value.Revision) ||
		(bound && !digestPattern.MatchString(value.RuleDigest)) || (!bound && value.RuleDigest != "") ||
		len(value.AllowedMediaTypes) == 0 || len(value.AllowedMediaTypes) > 64 ||
		len(value.PermittedModes) == 0 || len(value.PermittedModes) > 3 ||
		value.MaximumSpans == 0 || value.MaximumSpans > 4096 || !boundedBytes(value.MaximumSelectedBytes) ||
		!boundedBytes(value.MaximumOutputBytes) || !tokenPattern.MatchString(value.SignerKeyID) ||
		!boundedRevision(value.SignerKeyRevision) || (bound && !signaturePattern.MatchString(value.Signature)) ||
		(!bound && value.Signature != "") {
		return newError(InvalidInput, "rule_invalid", false, nil)
	}
	if !sortedUniqueStrings(value.AllowedMediaTypes, func(v string) bool { return mediaTypePattern.MatchString(v) }) ||
		!sortedUniqueModes(value.PermittedModes) {
		return newError(InvalidInput, "rule_lists_invalid", false, nil)
	}
	hasToken := false
	for _, mode := range value.PermittedModes {
		hasToken = hasToken || mode == Token
	}
	if hasToken != (value.TokenDigest != nil) || value.TokenDigest != nil && !digestPattern.MatchString(*value.TokenDigest) {
		return newError(InvalidInput, "rule_token_invalid", false, nil)
	}
	return nil
}

func ValidatePlan(value ApprovedPlan) error {
	if err := validatePlanShape(value, true); err != nil {
		return err
	}
	mappingPlan, err := MappingPlanBindingDigest(value)
	if err != nil || mappingPlan != value.MappingPlanDigest {
		return newError(Denied, "mapping_plan_digest_invalid", false, err)
	}
	want, err := PlanBindingDigest(value)
	if err != nil || want != value.PlanDigest {
		return newError(Denied, "plan_digest_invalid", false, err)
	}
	return nil
}

func validatePlanShape(value ApprovedPlan, bound bool) error {
	if err := validatePlanCore(value); err != nil {
		return err
	}
	if !digestPattern.MatchString(value.MappingPlanDigest) || !uuidPattern.MatchString(value.ApprovalID) ||
		!allDigests(value.ApprovalFingerprintDigest, value.ApprovalManifestDigest, value.PolicyDecisionDigest,
			value.PolicyDigest) || !validTime(value.ValidFrom) || !validTime(value.ValidUntil) ||
		!value.ValidUntil.After(value.ValidFrom) || (bound && !digestPattern.MatchString(value.PlanDigest)) ||
		(!bound && value.PlanDigest != "") {
		return newError(InvalidInput, "plan_invalid", false, nil)
	}
	return nil
}

func validatePlanCore(value ApprovedPlan) error {
	if value.SchemaVersion != PlanSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.PlanID) || !validCase(value.Case) || !validEvidence(value.Source) ||
		!uuidPattern.MatchString(value.RuleID) || !boundedRevision(value.RuleRevision) ||
		!allDigests(value.RuleDigest, value.ReasonDigest) || !mediaTypePattern.MatchString(value.OutputMediaType) ||
		!validClassification(value.OutputClassification) || !boundedBytes(value.MaximumOutputBytes) ||
		len(value.Spans) == 0 || len(value.Spans) > 4096 {
		return newError(InvalidInput, "plan_core_invalid", false, nil)
	}
	previousEnd, delta := int64(0), int64(0)
	for index, span := range value.Spans {
		if span.Ordinal != uint16(index+1) || span.SourceStart < previousEnd || span.SourceStart < 0 ||
			span.SourceEnd <= span.SourceStart || span.SourceEnd > value.Source.Artifact.Length ||
			!digestPattern.MatchString(span.SourceSegmentDigest) || !validReplacement(span.ReplacementMode) ||
			span.ExpectedOutputStart != span.SourceStart+delta || span.ExpectedOutputEnd < span.ExpectedOutputStart {
			return newError(InvalidInput, "plan_span_invalid", false, nil)
		}
		sourceLength, outputLength := span.SourceEnd-span.SourceStart, span.ExpectedOutputEnd-span.ExpectedOutputStart
		if span.ReplacementMode == Remove && outputLength != 0 || span.ReplacementMode == Mask && outputLength != sourceLength ||
			span.ReplacementMode == Token && outputLength == 0 {
			return newError(InvalidInput, "plan_replacement_invalid", false, nil)
		}
		delta += outputLength - sourceLength
		previousEnd = span.SourceEnd
	}
	derivedLength := value.Source.Artifact.Length + delta
	if derivedLength <= 0 || derivedLength > value.MaximumOutputBytes || derivedLength > maximumArtifactBytes {
		return newError(InvalidInput, "plan_output_invalid", false, nil)
	}
	return nil
}

func ValidateApprovalUse(value ApprovalUseProof) error {
	if err := validateApprovalShape(value, true); err != nil {
		return err
	}
	want, err := ApprovalUseBindingDigest(value)
	if err != nil || want != value.ProofDigest {
		return newError(Denied, "approval_proof_digest_invalid", false, err)
	}
	return nil
}

func validateApprovalShape(value ApprovalUseProof, bound bool) error {
	if !uuidPattern.MatchString(value.ApprovalID) || !allDigests(value.FingerprintDigest, value.ManifestDigest,
		value.PolicyDecisionDigest, value.IntentDigest, value.UseDigest) || !boundedRevision(value.Revision) ||
		!boundedRevision(value.UseCount) || !boundedRevision(value.MaximumUseCount) || value.UseCount > value.MaximumUseCount ||
		!validTime(value.ValidFrom) || !validTime(value.ValidUntil) || !validTime(value.UsedAt) ||
		!value.ValidUntil.After(value.ValidFrom) || value.UsedAt.Before(value.ValidFrom) || value.UsedAt.After(value.ValidUntil) ||
		(value.State != "granted" && value.State != "consumed") || (value.State == "consumed") != (value.UseCount == value.MaximumUseCount) ||
		(bound && !digestPattern.MatchString(value.ProofDigest)) || (!bound && value.ProofDigest != "") {
		return newError(InvalidInput, "approval_use_invalid", false, nil)
	}
	return nil
}

func ValidateAuthorization(value AuthorizationRequest) error {
	if err := validateAuthorizationShape(value, true); err != nil {
		return err
	}
	want, err := AuthorizationBindingDigest(value)
	if err != nil || want != value.AuthorizationDigest {
		return newError(Denied, "authorization_digest_invalid", false, err)
	}
	return nil
}

func validateAuthorizationShape(value AuthorizationRequest, bound bool) error {
	if value.SchemaVersion != AuthorizationSchemaVersion || value.ContractVersion != ContractVersion ||
		(bound && !digestPattern.MatchString(value.AuthorizationDigest)) || (!bound && value.AuthorizationDigest != "") ||
		!digestPattern.MatchString(value.IntentDigest) || validateCommandShape(value.Command) != nil ||
		ValidatePlan(value.Plan) != nil || !validCaseState(value.CaseState) || !validClassification(value.CaseClassification) ||
		!boundedRevision(value.CaseRevision) || !allDigests(value.CaseProvenanceDigest, value.SourceVerificationDigest) ||
		ValidateApprovalUse(value.ApprovalUse) != nil || !validHead(value.CurrentCustodyHead) {
		return newError(InvalidInput, "authorization_invalid", false, nil)
	}
	intent, err := IntentBindingDigest(value.Command)
	if err != nil || intent != value.IntentDigest || value.Plan.Case != value.Command.Case || value.Plan.Source != value.Command.Source ||
		value.Plan.PlanDigest != value.Command.PlanDigest || value.Plan.RuleDigest != value.Command.RuleDigest ||
		value.Plan.ReasonDigest != value.Command.ReasonDigest || value.Plan.OutputMediaType != value.Command.OutputMediaType ||
		value.Plan.OutputClassification != value.Command.OutputClassification || value.Plan.PolicyDigest != value.Command.PolicyDigest ||
		value.ApprovalUse.IntentDigest != value.IntentDigest || value.ApprovalUse.ApprovalID != value.Plan.ApprovalID ||
		value.ApprovalUse.FingerprintDigest != value.Plan.ApprovalFingerprintDigest ||
		value.ApprovalUse.ManifestDigest != value.Plan.ApprovalManifestDigest ||
		value.ApprovalUse.PolicyDecisionDigest != value.Plan.PolicyDecisionDigest || value.CaseRevision != value.Command.ExpectedCaseRevision ||
		value.CurrentCustodyHead.Case != value.Command.Case || !sameHead(value.CurrentCustodyHead, value.Command.ExpectedCustodyHead) {
		return newError(Denied, "authorization_binding_invalid", false, err)
	}
	return nil
}

func ValidateDecision(value Decision) error {
	if err := validateDecisionShape(value, true); err != nil {
		return err
	}
	want, err := DecisionBindingDigest(value)
	if err != nil || want != value.DecisionDigest {
		return newError(Denied, "decision_digest_invalid", false, err)
	}
	return nil
}

func validateDecisionShape(value Decision, bound bool) error {
	if value.SchemaVersion != DecisionSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.DecisionID) || (bound && !digestPattern.MatchString(value.DecisionDigest)) ||
		(!bound && value.DecisionDigest != "") || !allDigests(value.AuthorizationDigest, value.IntentDigest,
		value.SourceArtifactDigest, value.PlanDigest, value.ApprovalFingerprintDigest, value.PolicyDigest, value.RevocationDigest) ||
		!validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) || !boundedRevision(value.ActorRevision) ||
		!boundedRevision(value.ExpectedCaseRevision) || !validHead(value.ExpectedCustodyHead) ||
		value.ExpectedCustodyHead.Case != value.Case || (value.Outcome != Allow && value.Outcome != Deny) ||
		!validDecisionReason(value.ReasonCode) || (value.Outcome == Allow) != (value.ReasonCode == ReasonAuthorized) ||
		!validTime(value.IssuedAt) || !validTime(value.ExpiresAt) || !value.ExpiresAt.After(value.IssuedAt) ||
		!boundedRevision(value.Revision) {
		return newError(InvalidInput, "decision_invalid", false, nil)
	}
	return nil
}
