package evidencelifecycle

func ValidateImportVerification(value ImportVerification) error {
	if err := validateVerificationShape(value, true); err != nil {
		return err
	}
	want, err := VerificationBindingDigest(value)
	if err != nil || want != value.ReportDigest {
		return newError(Denied, "verification_digest_invalid", false, err)
	}
	return nil
}

func validateVerificationShape(value ImportVerification, bound bool) error {
	if value.SchemaVersion != ImportVerificationSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.VerificationID) || !allDigests(value.SourceDigest, value.PackageDigest,
		value.HeaderDigest, value.ManifestDigest, value.SignatureDigest, value.TrustSnapshotDigest,
		value.RevocationDigest, value.ArtifactSetDigest, value.LineageDigest, value.ComponentSetDigest,
		value.CustodyReportDigest, value.AuditCheckpointDigest) || !tokenPattern.MatchString(value.SigningKeyID) ||
		!validRevision(value.SigningKeyRevision) || !validVerificationOutcome(value.Outcome) ||
		!validVerificationReason(value.ReasonCode) || (value.Outcome == VerificationValid) != (value.ReasonCode == VerifySuccess) ||
		!validTime(value.VerifiedAt) || (bound && !digestPattern.MatchString(value.ReportDigest)) ||
		(!bound && value.ReportDigest != "") {
		return newError(InvalidInput, "verification_invalid", false, nil)
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
		!validCaseState(value.CaseState) || !validClassification(value.CaseClassification) ||
		!validRevision(value.CaseRevision) || !validTime(value.RetainUntil) ||
		!digestPattern.MatchString(value.CaseProvenanceDigest) ||
		!allPointerDigests(value.ArtifactSetDigest, value.VerificationReportDigest, value.ProgressDigest) ||
		!validHead(value.CurrentCustodyHead) || value.CurrentCustodyHead.Case != value.Command.Case ||
		value.CaseRevision != value.Command.ExpectedCaseRevision || !sameHead(value.CurrentCustodyHead, value.Command.ExpectedCustodyHead) ||
		value.ArtifactSetDigest != nil && value.Command.ArtifactSetDigest != nil &&
			*value.ArtifactSetDigest != *value.Command.ArtifactSetDigest {
		return newError(InvalidInput, "authorization_invalid", false, nil)
	}
	want, err := IntentBindingDigest(value.Command)
	if err != nil || want != value.IntentDigest {
		return newError(Denied, "authorization_intent_invalid", false, err)
	}
	if value.Command.Operation == Import {
		if value.ArtifactSetDigest == nil || value.VerificationReportDigest == nil {
			return newError(Denied, "import_verification_missing", false, nil)
		}
	} else if value.ArtifactSetDigest == nil || value.Command.ArtifactSetDigest == nil ||
		*value.ArtifactSetDigest != *value.Command.ArtifactSetDigest {
		return newError(Denied, "authorization_artifact_set_invalid", false, nil)
	}
	if value.Command.Operation == Delete && (value.LegalHold || value.HoldReleasePending) {
		return newError(Denied, "deletion_hold_invalid", false, nil)
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
		value.PolicyDigest, value.RevocationDigest) || !validOperation(value.Operation) || !validCase(value.Case) ||
		!uuidPattern.MatchString(value.ActorID) || !validRevision(value.ActorRevision) ||
		!allPointerDigests(value.ArtifactSetDigest, value.PackageDigest, value.ApprovalDigest) ||
		!validRevision(value.ExpectedCaseRevision) || !validHead(value.ExpectedCustodyHead) ||
		value.ExpectedCustodyHead.Case != value.Case || !validDecisionOutcome(value.Outcome) ||
		!validDecisionReason(value.ReasonCode) || (value.Outcome == Allow) != (value.ReasonCode == ReasonAuthorized) ||
		!validTime(value.IssuedAt) || !validTime(value.ExpiresAt) || !value.ExpiresAt.After(value.IssuedAt) ||
		!validRevision(value.Revision) {
		return newError(InvalidInput, "decision_invalid", false, nil)
	}
	return nil
}

func ValidateProgress(value Progress) error {
	if err := validateProgressShape(value, true); err != nil {
		return err
	}
	want, err := ProgressBindingDigest(value)
	if err != nil || want != value.ProgressDigest {
		return newError(Denied, "progress_digest_invalid", false, err)
	}
	return nil
}

func validateProgressShape(value Progress, bound bool) error {
	if value.SchemaVersion != ProgressSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.OperationID) || !validCase(value.Case) || !validOperation(value.Operation) ||
		!validPhase(value.Phase) || !phaseAllowed(value.Operation, value.Phase) ||
		!allDigests(value.CommandDigest, value.IntentDigest) ||
		!allPointerDigests(value.DecisionDigest, value.RevocationDigest, value.PackageDigest, value.ManifestDigest,
			value.SignatureDigest, value.VerificationReportDigest, value.LifecycleReceiptDigest,
			value.AuthorizationCustodyReceiptDigest, value.CompletionCustodyReceiptDigest,
			value.DispositionAttestationDigest) || !validArtifactProgress(value.Artifacts) || !validTime(value.UpdatedAt) ||
		!validRevision(value.Revision) || (bound && !digestPattern.MatchString(value.ProgressDigest)) ||
		(!bound && value.ProgressDigest != "") || !validProgressFields(value) {
		return newError(InvalidInput, "progress_invalid", false, nil)
	}
	return nil
}

func ValidateDispositionAttestation(value DispositionAttestation) error {
	if err := validateDispositionShape(value, true); err != nil {
		return err
	}
	want, err := DispositionBindingDigest(value)
	if err != nil || want != value.AttestationDigest {
		return newError(Denied, "disposition_digest_invalid", false, err)
	}
	return nil
}

func validateDispositionShape(value DispositionAttestation, bound bool) error {
	if value.SchemaVersion != DispositionAttestationSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.AttestationID) || !validCase(value.Case) || !uuidPattern.MatchString(value.OperationID) ||
		!allDigests(value.ArtifactSetDigest, value.AuthorizationCustodyReceiptDigest, value.LifecycleReceiptDigest) ||
		(value.Mechanism != "encrypted_object_removal" && value.Mechanism != "cryptographic_erasure_and_removal") ||
		!validDispositionObjects(value.Objects) || !validTime(value.AttemptedAt) || !validTime(value.CompletedAt) ||
		value.CompletedAt.Before(value.AttemptedAt) || (bound && !digestPattern.MatchString(value.AttestationDigest)) ||
		(!bound && value.AttestationDigest != "") {
		return newError(InvalidInput, "disposition_invalid", false, nil)
	}
	return nil
}

func validDispositionObjects(values []DispositionObject) bool {
	if len(values) == 0 || len(values) > 8192 {
		return false
	}
	previous := ""
	for index, value := range values {
		if value.Ordinal != uint16(index+1) || !allDigests(value.ArtifactDigest, value.EncryptedObjectDigest,
			value.OutcomeDigest) || !validRevision(value.KeyRevision) ||
			(value.Outcome != DispositionRemoved && value.Outcome != DispositionAlreadyAbsent) ||
			previous != "" && value.ArtifactDigest <= previous {
			return false
		}
		previous = value.ArtifactDigest
	}
	return true
}

func validArtifactProgress(values []ArtifactProgress) bool {
	if len(values) > 4096 {
		return false
	}
	previous := ""
	for index, value := range values {
		if value.Ordinal != uint16(index+1) || !digestPattern.MatchString(value.ArtifactDigest) ||
			!allPointerDigests(value.IngestionReceiptDigest, value.CustodyReceiptDigest) ||
			value.CustodyReceiptDigest != nil && value.IngestionReceiptDigest == nil ||
			previous != "" && value.ArtifactDigest <= previous {
			return false
		}
		previous = value.ArtifactDigest
	}
	return true
}
