package evidencelifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func validCaseSnapshot(value CaseSnapshot) bool {
	return validCase(value.Case) && (value.State == "open" || value.State == "closed" || value.State == "deleted") &&
		validClassification(value.Classification) && validRevision(value.Revision) && validTime(value.RetainUntil) &&
		digestPattern.MatchString(value.ProvenanceDigest)
}

func validVerifiedEvidenceSet(value VerifiedEvidenceSet, command Command, classification string) bool {
	if value.Case != command.Case || value.ArtifactSetDigest != *command.ArtifactSetDigest ||
		!digestPattern.MatchString(value.LineageDigest) || !digestPattern.MatchString(value.ComponentSetDigest) ||
		!validManifestArtifacts(value.Artifacts, classification, command.Limits.MaximumArtifacts) ||
		!validComponents(value.Components) {
		return false
	}
	artifactSet, err := ArtifactSetBindingDigest(value.Artifacts)
	if err != nil || artifactSet != value.ArtifactSetDigest {
		return false
	}
	components, err := ComponentSetBindingDigest(value.Components)
	return err == nil && components == value.ComponentSetDigest
}

func validRedactionProofs(evidence VerifiedEvidenceSet, proofs []RedactionProof) bool {
	wanted := make(map[string]ManifestArtifact)
	for _, artifact := range evidence.Artifacts {
		if artifact.Role == DerivedArtifact {
			wanted[artifact.Reference.Artifact.Digest] = artifact
		}
	}
	if len(proofs) != len(wanted) {
		return false
	}
	seen := make(map[string]struct{}, len(proofs))
	for _, proof := range proofs {
		artifact, found := wanted[proof.ArtifactDigest]
		if !found || !allDigests(proof.ArtifactDigest, proof.ReceiptDigest, proof.MappingDigest,
			proof.ProvenanceDigest) || artifact.RedactionReceiptDigest == nil || artifact.MappingDigest == nil ||
			*artifact.RedactionReceiptDigest != proof.ReceiptDigest || *artifact.MappingDigest != proof.MappingDigest {
			return false
		}
		if _, duplicate := seen[proof.ArtifactDigest]; duplicate {
			return false
		}
		seen[proof.ArtifactDigest] = struct{}{}
	}
	return true
}

func validCustodyVerification(value CustodyVerification, head CustodyHead) bool {
	return value.FromSequence == 1 && value.ToSequence == head.Sequence && sameHead(value.Head, head) &&
		uuidPattern.MatchString(value.CheckpointID) && allDigests(value.CheckpointDigest,
		value.CheckpointProofDigest, value.ReportDigest) && validRevision(value.CheckpointSequence) &&
		value.CheckpointSequence >= value.ToSequence && validRevision(value.CheckpointSigningKeyRevision)
}

func validExportDecision(value Decision, authorization AuthorizationRequest, now time.Time) bool {
	if ValidateDecision(value) != nil || value.Outcome != Allow || value.ReasonCode != ReasonAuthorized ||
		value.AuthorizationDigest != authorization.AuthorizationDigest || value.IntentDigest != authorization.IntentDigest ||
		value.Operation != Export || value.Case != authorization.Command.Case ||
		value.ActorID != authorization.Command.ActorID || value.ActorRevision != authorization.Command.ActorRevision ||
		value.ArtifactSetDigest == nil || authorization.ArtifactSetDigest == nil ||
		*value.ArtifactSetDigest != *authorization.ArtifactSetDigest || value.PackageDigest != nil ||
		value.PolicyDigest != authorization.Command.PolicyDigest || value.ApprovalDigest == nil ||
		authorization.Command.ApprovalDigest == nil || *value.ApprovalDigest != *authorization.Command.ApprovalDigest ||
		value.ExpectedCaseRevision != authorization.CaseRevision || !sameHead(value.ExpectedCustodyHead,
		authorization.CurrentCustodyHead) || !validTime(now) || now.Before(value.IssuedAt) || !now.Before(value.ExpiresAt) ||
		value.ExpiresAt.After(authorization.Command.Deadline) {
		return false
	}
	return true
}

func validCustodyProof(value CustodyProof, scope domain.CaseRef, prior CustodyHead) bool {
	return allDigests(value.ReceiptDigest, value.RecordDigest, value.AuditDigest) && validHead(value.Head) &&
		value.Head.Case == scope && value.Head.Sequence == prior.Sequence+1 && value.Head.ChainHash != prior.ChainHash
}

func validLifecycleProof(value LifecycleProof, scope domain.CaseRef, operation Operation) bool {
	return value.Operation == operation && value.Case == scope && validRevision(value.Revision) &&
		allDigests(value.ReceiptDigest, value.ProvenanceDigest)
}

func validQuarantinedPackage(value QuarantinedPackage, manifest ExportManifest, signatureDigest string) bool {
	return validOpaque(value.Reference, 1, 256) && ValidatePackageHeader(value.Header) == nil &&
		value.HeaderDigest == value.Header.HeaderDigest && digestPattern.MatchString(value.PackageDigest) &&
		value.PackageLength == value.Header.PackageLength && value.ManifestDigest == manifest.ManifestDigest &&
		value.SignatureDigest == signatureDigest && value.Header.ArtifactCount == uint16(len(manifest.Artifacts)) &&
		value.PackageLength <= manifest.Limits.MaximumPackageBytes
}

func mapExportDependency(ctx context.Context, reason string, err error) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return newError(Canceled, "request_canceled", false, context.Canceled)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", false, context.DeadlineExceeded)
	}
	switch CodeOf(err) {
	case Denied, NotFound, Conflict:
		return newError(CodeOf(err), Reason(err), Retryable(err), err)
	default:
		return newError(Unavailable, reason, true, err)
	}
}
