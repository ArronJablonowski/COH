package evidencelifecycle

import (
	"context"
	"time"
)

func (service *ExportService) loadExportProgress(ctx context.Context, command Command, intent,
	idempotency string) (Progress, bool, error) {
	progress, found, err := service.store.LoadProgress(ctx, command.Case, idempotency)
	if err != nil {
		return Progress{}, false, mapExportDependency(ctx, "export_progress_recovery_unavailable", err)
	}
	if found && !validRecoveredExportProgress(progress, command, intent) {
		return Progress{}, false, newError(Conflict, string(ReasonChangedReplay), false, nil)
	}
	return progress, found, nil
}

func validRecoveredExportProgress(value Progress, command Command, intent string) bool {
	commandDigest, err := CommandBindingDigest(command)
	if err != nil || ValidateProgress(value) != nil || value.Operation != Export || value.Case != command.Case ||
		value.CommandDigest != commandDigest || value.IntentDigest != intent || value.OperationID !=
		deterministicUUID("COH-EVIDENCE-EXPORT-OPERATION-ID-V1\x00", command.RequestID+"\x00"+intent) ||
		len(value.Artifacts) != 0 {
		return false
	}
	return value.Phase == Planned || value.Phase == Authorized || value.Phase == Packaged ||
		value.Phase == Custodied || value.Phase == CaseRecorded
}

func (service *ExportService) authorizeCustodyOrRecoverExport(ctx context.Context, state exportState,
	progress Progress) (CustodyProofSet, Progress, error) {
	if progress.Phase == Planned {
		proof, verified, stored, err := service.authorizeCustody(ctx, state, progress)
		_ = verified
		return proof, stored, err
	}
	if progress.AuthorizationCustodyReceiptDigest == nil || progress.DecisionDigest == nil ||
		progress.RevocationDigest == nil {
		return CustodyProofSet{}, Progress{}, newError(Conflict,
			"export_authorization_recovery_phase_invalid", false, nil)
	}
	proof, found, err := service.custody.RecoverLifecycle(ctx, state.Command.Case,
		*progress.AuthorizationCustodyReceiptDigest)
	if err != nil {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx,
			"export_authorization_custody_recovery_unavailable", err)
	}
	if !found || proof.ReceiptSetDigest != *progress.AuthorizationCustodyReceiptDigest ||
		!validCustodyProofSet(proof, state.Command.Case, state.Command.ExpectedCustodyHead,
			len(state.Evidence.Artifacts)) {
		return CustodyProofSet{}, Progress{}, newError(Denied,
			"export_authorization_custody_recovery_invalid", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, state.Command.Case, 1, proof.Head.Sequence)
	if err != nil {
		return CustodyProofSet{}, Progress{}, mapExportDependency(ctx,
			"export_authorization_custody_recovery_verification_unavailable", err)
	}
	if !validCustodyVerification(verified, proof.Head) {
		return CustodyProofSet{}, Progress{}, newError(Denied,
			"export_authorization_custody_recovery_verification_invalid", false, nil)
	}
	return proof, progress, nil
}

func (service *ExportService) packageOrRecoverExport(ctx context.Context, state exportState,
	authorization CustodyProofSet, progress Progress) (ExportManifest, DetachedSignature,
	QuarantinedPackage, Progress, exportState, error) {
	if (state.RecoveredPhase == Authorized || state.RecoveredPhase == Packaged) &&
		!sameHead(state.Decision.ExpectedCustodyHead, authorization.Head) {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{}, exportState{},
			newError(Conflict, string(ReasonStaleCustody), false, nil)
	}
	if progress.Phase == Authorized {
		manifest, signature, packaged, stored, err := service.packageExport(ctx, state, authorization, progress)
		return manifest, signature, packaged, stored, state, err
	}
	if progress.PackageDigest == nil || progress.ManifestDigest == nil || progress.SignatureDigest == nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{}, exportState{},
			newError(Conflict, "export_package_recovery_phase_invalid", false, nil)
	}
	packaged, found, err := service.packages.RecoverPackage(ctx, state.Command.Case, *progress.PackageDigest)
	if err != nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{}, exportState{},
			mapExportDependency(ctx, "export_package_recovery_unavailable", err)
	}
	if !found || packaged.PackageDigest != *progress.PackageDigest ||
		packaged.ManifestDigest != *progress.ManifestDigest || packaged.SignatureDigest != *progress.SignatureDigest {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{}, exportState{},
			newError(Denied, "export_package_recovery_invalid", false, nil)
	}
	if err = service.packages.VerifyPackage(ctx, packaged, state.Command.Limits); err != nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{}, exportState{},
			mapExportDependency(ctx, "export_package_recovery_verification_unavailable", err)
	}
	manifest, signature, err := service.packages.RecoverPackageProof(ctx, packaged, state.Command.Limits)
	if err != nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{}, exportState{},
			mapExportDependency(ctx, "export_package_proof_recovery_unavailable", err)
	}
	if !validRecoveredExportPackage(manifest, signature, packaged, state, progress, service.signing,
		service.clock.Now()) {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{}, exportState{},
			newError(Denied, "export_package_proof_recovery_invalid", false, nil)
	}
	canonical, err := CanonicalManifest(manifest)
	if err != nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{}, exportState{}, err
	}
	if err = service.verifier.VerifyDetachedSignature(ctx, VerifySignatureRequest{ManifestDigest: manifest.ManifestDigest,
		CanonicalBytes: canonical, Signature: signature, TrustSnapshotDigest: service.signing.TrustSnapshotDigest,
		RevocationDigest: service.signing.KeyRevocationDigest, At: service.clock.Now()}); err != nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{}, exportState{},
			mapExportDependency(ctx, "export_recovered_signature_verification_unavailable", err)
	}
	state.Case.Revision, state.Case.Classification = manifest.CaseRevision, manifest.Classification
	state.Case.ProvenanceDigest = manifest.PreviousProvenanceDigest
	return manifest, signature, packaged, progress, state, nil
}

func validRecoveredExportPackage(manifest ExportManifest, signature DetachedSignature,
	packaged QuarantinedPackage, state exportState, progress Progress, signing SigningProfile, now time.Time) bool {
	idempotency, err := IdempotencyBindingDigest(state.Command.IdempotencyKey)
	signatureDigest, signatureErr := SignatureBindingDigest(signature)
	return err == nil && signatureErr == nil && ValidateExportManifest(manifest) == nil &&
		ValidateDetachedSignature(signature) == nil && validQuarantinedPackage(packaged, manifest, signatureDigest) &&
		manifest.ManifestDigest == *progress.ManifestDigest && signatureDigest == *progress.SignatureDigest &&
		manifest.Case == state.Command.Case && manifest.CaseRevision == state.Command.ExpectedCaseRevision &&
		manifest.ActorID == state.Command.ActorID && manifest.ActorRevision == state.Command.ActorRevision &&
		manifest.PurposeDigest == *state.Command.PurposeDigest &&
		manifest.DestinationDigest == *state.Command.DestinationDigest &&
		manifest.ArtifactSetDigest == state.Evidence.ArtifactSetDigest &&
		manifest.PolicyDigest == state.Command.PolicyDigest && manifest.DecisionDigest == state.FinalDecisionDigest &&
		manifest.ApprovalDigest == *state.Command.ApprovalDigest &&
		manifest.RevocationDigest == state.FinalRevocationDigest &&
		manifest.CustodyFromSequence == state.Custody.FromSequence &&
		manifest.CustodyToSequence == state.Custody.ToSequence &&
		manifest.CustodyReportDigest == state.Custody.ReportDigest &&
		manifest.AuditCheckpointDigest == state.Custody.CheckpointDigest &&
		manifest.SigningKeyID == signing.KeyID && manifest.SigningKeyRevision == signing.KeyRevision &&
		manifest.SigningTrustSnapshotDigest == signing.TrustSnapshotDigest &&
		manifest.SigningKeyRevocationDigest == signing.KeyRevocationDigest &&
		manifest.IdempotencyDigest == idempotency && signature.ManifestDigest == manifest.ManifestDigest &&
		signature.KeyID == signing.KeyID && signature.KeyRevision == signing.KeyRevision && validTime(now) &&
		!now.Before(manifest.CreatedAt) && now.Before(manifest.ValidUntil)
}
