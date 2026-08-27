package evidencelifecycle

import "context"

func (service *ExportService) plan(ctx context.Context, state exportState, idempotency string) (Progress, error) {
	commandDigest, err := CommandBindingDigest(state.Command)
	if err != nil {
		return Progress{}, err
	}
	progress := Progress{SchemaVersion: ProgressSchemaVersion, ContractVersion: ContractVersion,
		OperationID: deterministicUUID("COH-EVIDENCE-EXPORT-OPERATION-ID-V1\x00", state.Command.RequestID+"\x00"+state.IntentDigest),
		Case:        state.Command.Case, Operation: Export, Phase: Planned, CommandDigest: commandDigest,
		IntentDigest: state.IntentDigest, UpdatedAt: state.AuthorizedAt, Revision: 1}
	progress.ProgressDigest, err = ProgressBindingDigest(progress)
	if err != nil {
		return Progress{}, err
	}
	stored, replayed, err := service.store.Advance(ctx, state.Command.IdempotencyKey, state.IntentDigest, progress)
	if err != nil {
		return Progress{}, mapExportDependency(ctx, "export_plan_unavailable", err)
	}
	if replayed || ValidateProgress(stored) != nil || stored.ProgressDigest != progress.ProgressDigest {
		return Progress{}, newError(Conflict, "export_progress_conflict", true, nil)
	}
	_ = idempotency
	return stored, nil
}

func (service *ExportService) authorizeCustody(ctx context.Context, state exportState,
	progress Progress) (CustodyProof, CustodyVerification, Progress, error) {
	request := CustodyRequest{Operation: Export, Phase: Authorized, Case: state.Command.Case,
		ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision,
		ArtifactSetDigest: state.Evidence.ArtifactSetDigest, PurposeDigest: state.Command.PurposeDigest,
		DestinationDigest: state.Command.DestinationDigest, PolicyDigest: state.Command.PolicyDigest,
		ExpectedCaseRevision: state.Case.Revision, ExpectedHead: state.Command.ExpectedCustodyHead,
		Deadline: state.Command.Deadline}
	proof, err := service.custody.RecordLifecycle(ctx, request)
	if err != nil {
		return CustodyProof{}, CustodyVerification{}, Progress{}, mapExportDependency(ctx, "export_custody_authorization_unavailable", err)
	}
	if !validCustodyProof(proof, state.Command.Case, state.Command.ExpectedCustodyHead) {
		return CustodyProof{}, CustodyVerification{}, Progress{}, newError(Denied, "export_custody_authorization_invalid", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, state.Command.Case, 1, proof.Head.Sequence)
	if err != nil {
		return CustodyProof{}, CustodyVerification{}, Progress{},
			mapExportDependency(ctx, "export_custody_authorization_verification_unavailable", err)
	}
	if !validCustodyVerification(verified, proof.Head) {
		return CustodyProof{}, CustodyVerification{}, Progress{},
			newError(Denied, "export_custody_authorization_verification_invalid", false, nil)
	}
	progress.Phase, progress.DecisionDigest, progress.RevocationDigest = Authorized,
		&state.Decision.DecisionDigest, &state.Decision.RevocationDigest
	progress.AuthorizationCustodyReceiptDigest = &proof.ReceiptDigest
	stored, err := service.advanceProgress(ctx, state, progress)
	return proof, verified, stored, err
}

func (service *ExportService) packageExport(ctx context.Context, state exportState, authorization CustodyProof,
	progress Progress) (ExportManifest, DetachedSignature, QuarantinedPackage, Progress, error) {
	now := service.clock.Now()
	if !validTime(now) || !now.Before(state.Command.Deadline) || !now.Before(state.Decision.ExpiresAt) {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{},
			newError(Timeout, "export_authorization_expired", false, nil)
	}
	validUntil := now.Add(service.signing.Validity)
	if state.Command.Deadline.Before(validUntil) {
		validUntil = state.Command.Deadline
	}
	if state.Decision.ExpiresAt.Before(validUntil) {
		validUntil = state.Decision.ExpiresAt
	}
	manifest := ExportManifest{SchemaVersion: ExportManifestSchemaVersion, ContractVersion: ContractVersion,
		ManifestID:     deterministicUUID("COH-EVIDENCE-EXPORT-MANIFEST-ID-V1\x00", progress.OperationID),
		PackageVersion: PackageVersion, Case: state.Command.Case, CaseRevision: state.Case.Revision,
		Classification: state.Case.Classification, ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision,
		PurposeDigest: *state.Command.PurposeDigest, DestinationDigest: *state.Command.DestinationDigest,
		Artifacts: state.Evidence.Artifacts, ArtifactSetDigest: state.Evidence.ArtifactSetDigest,
		Components: state.Evidence.Components, PolicyDigest: state.Command.PolicyDigest,
		DecisionDigest: state.Decision.DecisionDigest, ApprovalDigest: *state.Command.ApprovalDigest,
		RevocationDigest: state.Decision.RevocationDigest, CustodyFromSequence: state.Custody.FromSequence,
		CustodyToSequence: state.Custody.ToSequence, CustodyReportDigest: state.Custody.ReportDigest,
		AuditCheckpointID: state.Custody.CheckpointID, AuditCheckpointDigest: state.Custody.CheckpointDigest,
		AuditCheckpointSequence: state.Custody.CheckpointSequence,
		AuditSigningKeyRevision: state.Custody.CheckpointSigningKeyRevision,
		AuditProofDigest:        state.Custody.CheckpointProofDigest, SigningAlgorithm: SigningAlgorithm,
		SigningKeyID: service.signing.KeyID, SigningKeyRevision: service.signing.KeyRevision,
		SigningTrustSnapshotDigest: service.signing.TrustSnapshotDigest,
		SigningKeyRevocationDigest: service.signing.KeyRevocationDigest,
		Compression:                NoCompression, Limits: state.Command.Limits, CreatedAt: now, ValidUntil: validUntil,
		PreviousProvenanceDigest: state.Case.ProvenanceDigest}
	manifest.IdempotencyDigest, _ = IdempotencyBindingDigest(state.Command.IdempotencyKey)
	manifest.ManifestDigest, _ = ManifestBindingDigest(manifest)
	if ValidateExportManifest(manifest) != nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{},
			newError(Denied, "export_manifest_build_invalid", false, nil)
	}
	canonical, err := CanonicalManifest(manifest)
	if err != nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{}, err
	}
	signature, err := service.signer.SignManifest(ctx, SignRequest{ManifestDigest: manifest.ManifestDigest,
		CanonicalBytes: canonical, KeyID: service.signing.KeyID, KeyRevision: service.signing.KeyRevision,
		DecisionDigest: state.Decision.DecisionDigest})
	if err != nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{},
			mapExportDependency(ctx, "export_signing_unavailable", err)
	}
	if ValidateDetachedSignature(signature) != nil || signature.ManifestDigest != manifest.ManifestDigest ||
		signature.KeyID != service.signing.KeyID || signature.KeyRevision != service.signing.KeyRevision {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{},
			newError(Denied, "export_signature_invalid", false, nil)
	}
	if err = service.verifier.VerifyDetachedSignature(ctx, VerifySignatureRequest{ManifestDigest: manifest.ManifestDigest,
		CanonicalBytes: canonical, Signature: signature, TrustSnapshotDigest: service.signing.TrustSnapshotDigest,
		RevocationDigest: service.signing.KeyRevocationDigest, At: now}); err != nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{},
			mapExportDependency(ctx, "export_signature_verification_unavailable", err)
	}
	packaged, err := service.packages.BuildPackage(ctx, PackageBuildRequest{Manifest: manifest,
		Signature: signature, Evidence: state.Evidence, Deadline: state.Command.Deadline})
	if err != nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{},
			mapExportDependency(ctx, "export_package_build_unavailable", err)
	}
	signatureDigest, _ := SignatureBindingDigest(signature)
	if !validQuarantinedPackage(packaged, manifest, signatureDigest) {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{},
			newError(Denied, "export_package_invalid", false, nil)
	}
	if err = service.packages.VerifyPackage(ctx, packaged, state.Command.Limits); err != nil {
		return ExportManifest{}, DetachedSignature{}, QuarantinedPackage{}, Progress{},
			mapExportDependency(ctx, "export_package_verification_unavailable", err)
	}
	progress.Phase, progress.PackageDigest, progress.ManifestDigest, progress.SignatureDigest =
		Packaged, &packaged.PackageDigest, &manifest.ManifestDigest, &signatureDigest
	stored, err := service.advanceProgress(ctx, state, progress)
	return manifest, signature, packaged, stored, err
}

func (service *ExportService) completeCustody(ctx context.Context, state exportState, authorization CustodyProof,
	manifest ExportManifest, signature DetachedSignature, packaged QuarantinedPackage,
	progress Progress) (CustodyProof, Progress, error) {
	signatureDigest, _ := SignatureBindingDigest(signature)
	request := CustodyRequest{Operation: Export, Phase: Completed, Case: state.Command.Case,
		ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision,
		ArtifactSetDigest: state.Evidence.ArtifactSetDigest, ManifestDigest: &manifest.ManifestDigest,
		PackageDigest: &packaged.PackageDigest, PurposeDigest: state.Command.PurposeDigest,
		DestinationDigest: state.Command.DestinationDigest, SignatureDigest: &signatureDigest,
		PriorAuthorizationDigest: &authorization.ReceiptDigest, PolicyDigest: state.Command.PolicyDigest,
		ExpectedCaseRevision: state.Case.Revision, ExpectedHead: authorization.Head, Deadline: state.Command.Deadline}
	proof, err := service.custody.RecordLifecycle(ctx, request)
	if err != nil {
		return CustodyProof{}, Progress{}, mapExportDependency(ctx, "export_custody_completion_unavailable", err)
	}
	if !validCustodyProof(proof, state.Command.Case, authorization.Head) {
		return CustodyProof{}, Progress{}, newError(Denied, "export_custody_completion_invalid", false, nil)
	}
	verified, err := service.custody.VerifyLifecycle(ctx, state.Command.Case, 1, proof.Head.Sequence)
	if err != nil {
		return CustodyProof{}, Progress{}, mapExportDependency(ctx, "export_custody_completion_verification_unavailable", err)
	}
	if !validCustodyVerification(verified, proof.Head) {
		return CustodyProof{}, Progress{}, newError(Denied, "export_custody_completion_verification_invalid", false, nil)
	}
	progress.Phase, progress.CompletionCustodyReceiptDigest = Custodied, &proof.ReceiptDigest
	stored, err := service.advanceProgress(ctx, state, progress)
	return proof, stored, err
}

func (service *ExportService) recordCaseExport(ctx context.Context, state exportState, manifest ExportManifest,
	progress Progress) (LifecycleProof, Progress, error) {
	proof, err := service.lifecycle.ApplyCaseOperation(ctx, LifecycleRequest{Operation: Export, Case: state.Command.Case,
		ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision,
		ExpectedCaseRevision: state.Case.Revision, ManifestDigest: &manifest.ManifestDigest,
		PolicyDigest: state.Command.PolicyDigest, IdempotencyDigest: progress.IntentDigest,
		Deadline: state.Command.Deadline})
	if err != nil {
		return LifecycleProof{}, Progress{}, mapExportDependency(ctx, "case_export_unavailable", err)
	}
	if !validLifecycleProof(proof, state.Command.Case, Export) {
		return LifecycleProof{}, Progress{}, newError(Denied, "case_export_proof_invalid", false, nil)
	}
	resolved, found, err := service.cases.ResolveLifecycleReceipt(ctx, state.Command.Case, proof.ReceiptDigest)
	if err != nil {
		return LifecycleProof{}, Progress{}, mapExportDependency(ctx, "case_export_verification_unavailable", err)
	}
	if !found || resolved != proof {
		return LifecycleProof{}, Progress{}, newError(Denied, "case_export_verification_invalid", false, nil)
	}
	progress.Phase, progress.LifecycleReceiptDigest = CaseRecorded, &proof.ReceiptDigest
	stored, err := service.advanceProgress(ctx, state, progress)
	return proof, stored, err
}

func (service *ExportService) advanceProgress(ctx context.Context, state exportState, progress Progress) (Progress, error) {
	progress.Revision++
	progress.UpdatedAt = service.clock.Now()
	progress.ProgressDigest = ""
	progress.ProgressDigest, _ = ProgressBindingDigest(progress)
	if ValidateProgress(progress) != nil {
		return Progress{}, newError(Unavailable, "export_progress_build_invalid", false, nil)
	}
	stored, replayed, err := service.store.Advance(ctx, state.Command.IdempotencyKey, state.IntentDigest, progress)
	if err != nil {
		return Progress{}, mapExportDependency(ctx, "export_progress_unavailable", err)
	}
	if replayed || ValidateProgress(stored) != nil || stored.ProgressDigest != progress.ProgressDigest {
		return Progress{}, newError(Conflict, "export_progress_conflict", true, nil)
	}
	return stored, nil
}
