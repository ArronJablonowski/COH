package evidencelifecycle

import "time"

func validCompletedExportPackage(manifest ExportManifest, signature DetachedSignature,
	packaged QuarantinedPackage, receipt Receipt, command Command, evidence VerifiedEvidenceSet,
	signing SigningProfile, now time.Time) bool {
	if receipt.PackageDigest == nil || receipt.ManifestDigest == nil || receipt.SignatureDigest == nil ||
		receipt.AuthorizationCustodyReceiptDigest == nil || receipt.CompletionCustodyReceiptDigest == nil ||
		receipt.LifecycleReceiptDigest == nil || command.PurposeDigest == nil || command.DestinationDigest == nil ||
		command.ApprovalDigest == nil {
		return false
	}
	idempotency, err := IdempotencyBindingDigest(command.IdempotencyKey)
	signatureDigest, signatureErr := SignatureBindingDigest(signature)
	return err == nil && signatureErr == nil && ValidateExportManifest(manifest) == nil &&
		ValidateDetachedSignature(signature) == nil && validQuarantinedPackage(packaged, manifest, signatureDigest) &&
		packaged.PackageDigest == *receipt.PackageDigest && manifest.ManifestDigest == *receipt.ManifestDigest &&
		signatureDigest == *receipt.SignatureDigest && manifest.Case == command.Case &&
		manifest.CaseRevision == command.ExpectedCaseRevision && manifest.ActorID == command.ActorID &&
		manifest.ActorRevision == command.ActorRevision && manifest.PurposeDigest == *command.PurposeDigest &&
		manifest.DestinationDigest == *command.DestinationDigest &&
		manifest.ArtifactSetDigest == evidence.ArtifactSetDigest && manifest.PolicyDigest == command.PolicyDigest &&
		manifest.DecisionDigest == receipt.DecisionDigest && manifest.ApprovalDigest == *command.ApprovalDigest &&
		manifest.SigningKeyID == signing.KeyID && manifest.SigningKeyRevision == signing.KeyRevision &&
		manifest.SigningTrustSnapshotDigest == signing.TrustSnapshotDigest &&
		manifest.SigningKeyRevocationDigest == signing.KeyRevocationDigest && manifest.IdempotencyDigest == idempotency &&
		signature.ManifestDigest == manifest.ManifestDigest && signature.KeyID == signing.KeyID &&
		signature.KeyRevision == signing.KeyRevision && validTime(now) && !now.Before(manifest.CreatedAt) &&
		now.Before(manifest.ValidUntil)
}
