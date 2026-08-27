package evidencelifecycle

func ValidateRecord(value Record) error {
	if err := validateRecordShape(value, true); err != nil {
		return err
	}
	wantProvenance, err := RecordProvenanceDigest(value)
	if err != nil || wantProvenance != value.ProvenanceDigest {
		return newError(Denied, "record_provenance_invalid", false, err)
	}
	want, err := RecordBindingDigest(value)
	if err != nil || want != value.RecordDigest {
		return newError(Denied, "record_digest_invalid", false, err)
	}
	return nil
}

func validateRecordShape(value Record, bound bool) error {
	if value.SchemaVersion != RecordSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.OperationID) || !validCase(value.Case) || !validOperation(value.Operation) ||
		!allDigests(value.CommandDigest, value.IntentDigest, value.DecisionDigest, value.RevocationDigest) ||
		!allPointerDigests(value.ArtifactSetDigest, value.PackageDigest, value.ManifestDigest, value.SignatureDigest,
			value.VerificationReportDigest, value.LifecycleReceiptDigest, value.AuthorizationCustodyReceiptDigest,
			value.CompletionCustodyReceiptDigest, value.DispositionAttestationDigest) ||
		(bound && !allDigests(value.AuditEventDigest, value.ProvenanceDigest, value.RecordDigest)) ||
		(!bound && value.RecordDigest != "") ||
		!validTime(value.CompletedAt) || !digestPattern.MatchString(value.PreviousProvenanceDigest) ||
		!validFinalFields(value.Operation, value.ArtifactSetDigest, value.PackageDigest, value.ManifestDigest,
			value.SignatureDigest, value.VerificationReportDigest, value.LifecycleReceiptDigest,
			value.AuthorizationCustodyReceiptDigest, value.CompletionCustodyReceiptDigest,
			value.DispositionAttestationDigest) {
		return newError(InvalidInput, "record_invalid", false, nil)
	}
	return nil
}

func ValidateReceipt(value Receipt) error {
	if err := validateReceiptShape(value, true); err != nil {
		return err
	}
	want, err := ReceiptBindingDigest(value)
	if err != nil || want != value.ReceiptDigest {
		return newError(Denied, "receipt_digest_invalid", false, err)
	}
	return nil
}

func validateReceiptShape(value Receipt, bound bool) error {
	if value.SchemaVersion != ReceiptSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !uuidPattern.MatchString(value.OperationID) || !validCase(value.Case) ||
		!validOperation(value.Operation) || !allDigests(value.IdempotencyDigest, value.IntentDigest, value.DecisionDigest,
		value.RecordDigest, value.AuditEventDigest, value.ProvenanceDigest) ||
		!allPointerDigests(value.ArtifactSetDigest, value.PackageDigest, value.ManifestDigest, value.SignatureDigest,
			value.VerificationReportDigest, value.LifecycleReceiptDigest, value.CompletionCustodyReceiptDigest,
			value.DispositionAttestationDigest) || !validTime(value.CreatedAt) ||
		(bound && !digestPattern.MatchString(value.ReceiptDigest)) || (!bound && value.ReceiptDigest != "") ||
		!validReceiptFields(value) {
		return newError(InvalidInput, "receipt_invalid", false, nil)
	}
	return nil
}

func validReceiptFields(value Receipt) bool {
	switch value.Operation {
	case Export:
		return value.ArtifactSetDigest != nil && value.PackageDigest != nil && value.ManifestDigest != nil &&
			value.SignatureDigest != nil && value.VerificationReportDigest == nil && value.LifecycleReceiptDigest != nil &&
			value.CompletionCustodyReceiptDigest != nil && value.DispositionAttestationDigest == nil
	case Import:
		return value.ArtifactSetDigest != nil && value.PackageDigest != nil && value.ManifestDigest != nil &&
			value.SignatureDigest != nil && value.VerificationReportDigest != nil && value.LifecycleReceiptDigest == nil &&
			value.CompletionCustodyReceiptDigest != nil && value.DispositionAttestationDigest == nil
	case PlaceHold, ReleaseHold:
		return value.ArtifactSetDigest != nil && allNil(value.PackageDigest, value.ManifestDigest, value.SignatureDigest,
			value.VerificationReportDigest, value.DispositionAttestationDigest) && value.LifecycleReceiptDigest != nil &&
			value.CompletionCustodyReceiptDigest != nil
	case Delete:
		return value.ArtifactSetDigest != nil && allNil(value.PackageDigest, value.ManifestDigest, value.SignatureDigest,
			value.VerificationReportDigest) && value.LifecycleReceiptDigest != nil &&
			value.CompletionCustodyReceiptDigest != nil && value.DispositionAttestationDigest != nil
	default:
		return false
	}
}

func validFinalFields(operation Operation, artifactSet, packageDigest, manifest, signature, verification,
	lifecycle, authorizationCustody, completionCustody, disposition *string) bool {
	switch operation {
	case Export:
		return artifactSet != nil && packageDigest != nil && manifest != nil && signature != nil &&
			verification == nil && lifecycle != nil && completionCustody != nil && disposition == nil
	case Import:
		return artifactSet != nil && packageDigest != nil && manifest != nil && signature != nil &&
			verification != nil && lifecycle == nil && authorizationCustody == nil && completionCustody != nil && disposition == nil
	case PlaceHold, ReleaseHold:
		return artifactSet != nil && allNil(packageDigest, manifest, signature, verification, authorizationCustody, disposition) &&
			lifecycle != nil && completionCustody != nil
	case Delete:
		return artifactSet != nil && allNil(packageDigest, manifest, signature, verification) && lifecycle != nil &&
			authorizationCustody != nil && completionCustody != nil && disposition != nil
	default:
		return false
	}
}

func validCaseState(value string) bool {
	return value == "open" || value == "closed" || value == "deleted"
}

func validDecisionOutcome(value DecisionOutcome) bool { return value == Allow || value == Deny }

func validDecisionReason(value DecisionReason) bool {
	for _, candidate := range []DecisionReason{ReasonAuthorized, ReasonInvalidInput, ReasonCaseNotFound,
		ReasonCaseStateDenied, ReasonArtifactNotFound, ReasonArtifactInvalid, ReasonLineageInvalid,
		ReasonPackageInvalid, ReasonPackageOversized, ReasonMediaTypeDenied, ReasonSignatureInvalid,
		ReasonSigningKeyInvalid, ReasonCheckpointInvalid, ReasonVerificationIncomplete, ReasonAuthorityDenied,
		ReasonApprovalRequired, ReasonApprovalInvalid, ReasonRevoked, ReasonStaleActor, ReasonStaleCase,
		ReasonStaleCustody, ReasonRetentionActive, ReasonLegalHoldActive, ReasonHoldReleaseIncomplete,
		ReasonChangedReplay, ReasonDispositionFailed} {
		if value == candidate {
			return true
		}
	}
	return false
}

func validVerificationOutcome(value VerificationOutcome) bool {
	return value == VerificationValid || value == VerificationInvalid || value == VerificationIncomplete
}

func validVerificationReason(value VerificationReason) bool {
	for _, candidate := range []VerificationReason{VerifySuccess, VerifyInvalidHeader, VerifyInvalidSchema,
		VerifyInvalidScope, VerifyInvalidBounds, VerifyInvalidMediaType, VerifyCompressedInput,
		VerifyInvalidSignature, VerifyUnknownKey, VerifyRevokedKey, VerifyExpiredManifest,
		VerifyInvalidArtifact, VerifyInvalidLineage, VerifyInvalidComponent, VerifyInvalidCustody,
		VerifyInvalidCheckpoint, VerifyTrailingData, VerifyTruncatedInput} {
		if value == candidate {
			return true
		}
	}
	return false
}

func phaseAllowed(operation Operation, phase Phase) bool {
	var values []Phase
	switch operation {
	case Export:
		values = []Phase{Planned, Authorized, Packaged, Custodied, CaseRecorded, Completed}
	case Import:
		values = []Phase{Quarantined, Verified, Authorized, Published, Custodied, Completed}
	case PlaceHold, ReleaseHold:
		values = []Phase{Planned, CaseRecorded, Custodied, Completed}
	case Delete:
		values = []Phase{Planned, Authorized, Tombstoned, Disposed, Custodied, Completed}
	}
	for _, candidate := range values {
		if phase == candidate {
			return true
		}
	}
	return false
}

func validProgressFields(value Progress) bool {
	switch value.Operation {
	case Export:
		if value.VerificationReportDigest != nil || value.DispositionAttestationDigest != nil || len(value.Artifacts) != 0 {
			return false
		}
		switch value.Phase {
		case Planned:
			return allNil(value.DecisionDigest, value.RevocationDigest, value.PackageDigest, value.ManifestDigest,
				value.SignatureDigest, value.LifecycleReceiptDigest, value.AuthorizationCustodyReceiptDigest,
				value.CompletionCustodyReceiptDigest)
		case Authorized:
			return allPresent(value.DecisionDigest, value.RevocationDigest, value.AuthorizationCustodyReceiptDigest) &&
				allNil(value.PackageDigest, value.ManifestDigest, value.SignatureDigest, value.LifecycleReceiptDigest,
					value.CompletionCustodyReceiptDigest)
		case Packaged:
			return allPresent(value.DecisionDigest, value.RevocationDigest, value.AuthorizationCustodyReceiptDigest,
				value.PackageDigest, value.ManifestDigest, value.SignatureDigest) &&
				allNil(value.LifecycleReceiptDigest, value.CompletionCustodyReceiptDigest)
		case Custodied:
			return allPresent(value.DecisionDigest, value.RevocationDigest, value.AuthorizationCustodyReceiptDigest,
				value.PackageDigest, value.ManifestDigest, value.SignatureDigest, value.CompletionCustodyReceiptDigest) &&
				value.LifecycleReceiptDigest == nil
		case CaseRecorded, Completed:
			return allPresent(value.DecisionDigest, value.RevocationDigest, value.AuthorizationCustodyReceiptDigest,
				value.PackageDigest, value.ManifestDigest, value.SignatureDigest, value.CompletionCustodyReceiptDigest,
				value.LifecycleReceiptDigest)
		}
	case Import:
		if value.LifecycleReceiptDigest != nil || value.AuthorizationCustodyReceiptDigest != nil ||
			value.DispositionAttestationDigest != nil || len(value.Artifacts) == 0 || value.PackageDigest == nil {
			return false
		}
		switch value.Phase {
		case Quarantined:
			return allNil(value.DecisionDigest, value.RevocationDigest, value.ManifestDigest, value.SignatureDigest,
				value.VerificationReportDigest, value.CompletionCustodyReceiptDigest) && progressReceipts(value.Artifacts, false, false)
		case Verified:
			return allPresent(value.ManifestDigest, value.SignatureDigest, value.VerificationReportDigest) &&
				allNil(value.DecisionDigest, value.RevocationDigest, value.CompletionCustodyReceiptDigest) &&
				progressReceipts(value.Artifacts, false, false)
		case Authorized:
			return allPresent(value.ManifestDigest, value.SignatureDigest, value.VerificationReportDigest,
				value.DecisionDigest, value.RevocationDigest) && value.CompletionCustodyReceiptDigest == nil &&
				progressReceipts(value.Artifacts, false, false)
		case Published:
			return allPresent(value.ManifestDigest, value.SignatureDigest, value.VerificationReportDigest,
				value.DecisionDigest, value.RevocationDigest) && value.CompletionCustodyReceiptDigest == nil &&
				progressReceipts(value.Artifacts, true, false)
		case Custodied, Completed:
			return allPresent(value.ManifestDigest, value.SignatureDigest, value.VerificationReportDigest,
				value.DecisionDigest, value.RevocationDigest, value.CompletionCustodyReceiptDigest) &&
				progressReceipts(value.Artifacts, true, true)
		}
	case PlaceHold, ReleaseHold:
		if !allNil(value.PackageDigest, value.ManifestDigest, value.SignatureDigest, value.VerificationReportDigest,
			value.AuthorizationCustodyReceiptDigest, value.DispositionAttestationDigest) || len(value.Artifacts) != 0 {
			return false
		}
		switch value.Phase {
		case Planned:
			return allNil(value.DecisionDigest, value.RevocationDigest, value.LifecycleReceiptDigest,
				value.CompletionCustodyReceiptDigest)
		case CaseRecorded:
			return allPresent(value.DecisionDigest, value.RevocationDigest, value.LifecycleReceiptDigest) &&
				value.CompletionCustodyReceiptDigest == nil
		case Custodied, Completed:
			return allPresent(value.DecisionDigest, value.RevocationDigest, value.LifecycleReceiptDigest,
				value.CompletionCustodyReceiptDigest)
		}
	case Delete:
		if !allNil(value.PackageDigest, value.ManifestDigest, value.SignatureDigest, value.VerificationReportDigest) ||
			len(value.Artifacts) != 0 {
			return false
		}
		switch value.Phase {
		case Planned:
			return allNil(value.DecisionDigest, value.RevocationDigest, value.LifecycleReceiptDigest,
				value.AuthorizationCustodyReceiptDigest, value.CompletionCustodyReceiptDigest,
				value.DispositionAttestationDigest)
		case Authorized:
			return allPresent(value.DecisionDigest, value.RevocationDigest, value.AuthorizationCustodyReceiptDigest) &&
				allNil(value.LifecycleReceiptDigest, value.CompletionCustodyReceiptDigest,
					value.DispositionAttestationDigest)
		case Tombstoned:
			return allPresent(value.DecisionDigest, value.RevocationDigest, value.AuthorizationCustodyReceiptDigest,
				value.LifecycleReceiptDigest) && allNil(value.CompletionCustodyReceiptDigest,
				value.DispositionAttestationDigest)
		case Disposed:
			return allPresent(value.DecisionDigest, value.RevocationDigest, value.AuthorizationCustodyReceiptDigest,
				value.LifecycleReceiptDigest, value.DispositionAttestationDigest) &&
				value.CompletionCustodyReceiptDigest == nil
		case Custodied, Completed:
			return allPresent(value.DecisionDigest, value.RevocationDigest, value.AuthorizationCustodyReceiptDigest,
				value.LifecycleReceiptDigest, value.DispositionAttestationDigest,
				value.CompletionCustodyReceiptDigest)
		}
	}
	return false
}

func allPresent(values ...*string) bool {
	for _, value := range values {
		if value == nil {
			return false
		}
	}
	return true
}

func progressReceipts(values []ArtifactProgress, ingestion, custody bool) bool {
	for _, value := range values {
		if (value.IngestionReceiptDigest != nil) != ingestion || (value.CustodyReceiptDigest != nil) != custody {
			return false
		}
	}
	return true
}
