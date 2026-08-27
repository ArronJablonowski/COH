package evidencelifecycle

import "time"

func validVerifiedImport(value VerifiedImport, command Command, reference string) bool {
	if command.PackageDigest == nil || command.SourceDigest == nil ||
		ValidateExportManifest(value.Manifest) != nil || ValidateDetachedSignature(value.Signature) != nil ||
		ValidatePackageHeader(value.Package.Header) != nil || ValidateImportVerification(value.Verification) != nil ||
		value.Package.Reference != reference || value.Package.PackageDigest != *command.PackageDigest ||
		value.Package.HeaderDigest != value.Package.Header.HeaderDigest ||
		value.Package.PackageLength != value.Package.Header.PackageLength ||
		value.Package.ManifestDigest != value.Manifest.ManifestDigest ||
		value.Package.Header.ArtifactCount != uint16(len(value.Manifest.Artifacts)) ||
		value.Signature.ManifestDigest != value.Manifest.ManifestDigest ||
		value.Signature.KeyID != value.Manifest.SigningKeyID ||
		value.Signature.KeyRevision != value.Manifest.SigningKeyRevision ||
		value.Verification.Outcome != VerificationValid || value.Verification.ReasonCode != VerifySuccess ||
		value.Verification.SourceDigest != *command.SourceDigest ||
		value.Verification.PackageDigest != value.Package.PackageDigest ||
		value.Verification.HeaderDigest != value.Package.HeaderDigest ||
		value.Verification.ManifestDigest != value.Manifest.ManifestDigest ||
		value.Verification.SigningKeyID != value.Manifest.SigningKeyID ||
		value.Verification.SigningKeyRevision != value.Manifest.SigningKeyRevision ||
		value.Verification.ArtifactSetDigest != value.Manifest.ArtifactSetDigest ||
		value.Verification.CustodyReportDigest != value.Manifest.CustodyReportDigest ||
		value.Verification.AuditCheckpointDigest != value.Manifest.AuditCheckpointDigest ||
		value.Package.PackageLength > command.Limits.MaximumPackageBytes ||
		value.Package.Header.ManifestLength > command.Limits.MaximumManifestBytes ||
		value.Package.Header.SignatureLength > command.Limits.MaximumSignatureBytes ||
		len(value.Manifest.Artifacts) > int(command.Limits.MaximumArtifacts) ||
		!verifiedWithinValidity(value.Verification.VerifiedAt, value.Manifest, command.Deadline) {
		return false
	}
	signatureDigest, err := SignatureBindingDigest(value.Signature)
	if err != nil || signatureDigest != value.Package.SignatureDigest ||
		signatureDigest != value.Verification.SignatureDigest {
		return false
	}
	lineage, err := LineageBindingDigest(value.Manifest.Artifacts)
	if err != nil || lineage != value.Verification.LineageDigest {
		return false
	}
	components, err := ComponentSetBindingDigest(value.Manifest.Components)
	if err != nil || components != value.Verification.ComponentSetDigest ||
		len(value.Staged) != len(value.Manifest.Artifacts) {
		return false
	}
	seenReferences := make(map[string]struct{}, len(value.Staged))
	for index, staged := range value.Staged {
		artifact := value.Manifest.Artifacts[index]
		if staged.Ordinal != uint16(index+1) || staged.Ordinal != artifact.Ordinal ||
			staged.ArtifactDigest != artifact.Reference.Artifact.Digest ||
			!validOpaque(staged.Reference, 1, 256) || !digestPattern.MatchString(staged.VerificationDigest) ||
			artifact.Reference.Artifact.Length > command.Limits.MaximumArtifactBytes {
			return false
		}
		if _, duplicate := seenReferences[staged.Reference]; duplicate {
			return false
		}
		seenReferences[staged.Reference] = struct{}{}
	}
	return true
}

func verifiedWithinValidity(at time.Time, manifest ExportManifest, deadline time.Time) bool {
	return validTime(at) && !at.Before(manifest.CreatedAt) && at.Before(manifest.ValidUntil) &&
		!at.After(deadline)
}

func validImportDecision(value Decision, authorization AuthorizationRequest, now time.Time) bool {
	command := authorization.Command
	return ValidateDecision(value) == nil && value.Outcome == Allow && value.ReasonCode == ReasonAuthorized &&
		value.AuthorizationDigest == authorization.AuthorizationDigest && value.IntentDigest == authorization.IntentDigest &&
		value.Operation == Import && value.Case == command.Case && value.ActorID == command.ActorID &&
		value.ActorRevision == command.ActorRevision && value.ArtifactSetDigest != nil &&
		authorization.ArtifactSetDigest != nil && *value.ArtifactSetDigest == *authorization.ArtifactSetDigest &&
		value.PackageDigest != nil && command.PackageDigest != nil && *value.PackageDigest == *command.PackageDigest &&
		value.PolicyDigest == command.PolicyDigest && value.ApprovalDigest == nil &&
		value.ExpectedCaseRevision == authorization.CaseRevision &&
		sameHead(value.ExpectedCustodyHead, authorization.CurrentCustodyHead) && validTime(now) &&
		!now.Before(value.IssuedAt) && now.Before(value.ExpiresAt) && !value.ExpiresAt.After(command.Deadline)
}

func validPublishedImport(value PublishedImport, verified VerifiedImport) bool {
	if len(value.Artifacts) == 0 || len(value.Artifacts) != len(verified.Manifest.Artifacts) ||
		len(value.Progress) != len(value.Artifacts) {
		return false
	}
	seenArtifacts, seenManifests := make(map[string]struct{}, len(value.Artifacts)),
		make(map[string]struct{}, len(value.Artifacts))
	for index, reference := range value.Artifacts {
		manifestArtifact, progress := verified.Manifest.Artifacts[index], value.Progress[index]
		if !validEvidence(reference) || reference.Artifact != manifestArtifact.Reference.Artifact ||
			progress.Ordinal != uint16(index+1) || progress.Ordinal != manifestArtifact.Ordinal ||
			progress.ArtifactDigest != reference.Artifact.Digest || progress.IngestionReceiptDigest == nil ||
			*progress.IngestionReceiptDigest != reference.IngestionReceiptDigest || progress.CustodyReceiptDigest != nil {
			return false
		}
		if _, duplicate := seenArtifacts[reference.Artifact.Digest]; duplicate {
			return false
		}
		if _, duplicate := seenManifests[reference.Manifest.Digest]; duplicate {
			return false
		}
		seenArtifacts[reference.Artifact.Digest] = struct{}{}
		seenManifests[reference.Manifest.Digest] = struct{}{}
	}
	return true
}
