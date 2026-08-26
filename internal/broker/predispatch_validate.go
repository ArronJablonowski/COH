package broker

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/policy"
)

func validatePreDispatchDecision(decision policy.Decision, request policy.Request, signer policy.BundleAuthority,
	startedAt, finishedAt time.Time) error {
	manifest := request.Manifest.Manifest()
	if finishedAt.IsZero() || finishedAt.Before(startedAt) {
		return lifecycle.NewError(lifecycle.Unavailable, "predispatch_clock")
	}
	if _, err := policy.VerifyDecisionDigest(decision); err != nil {
		return lifecycle.NewError(lifecycle.Denied, "policy_decision_digest")
	}
	if !signer.Active || signer.Algorithm != "ed25519" || signer.KeyRevision == 0 ||
		!tokenPattern.MatchString(signer.KeyID) || len(signer.PublicKey) != 32 ||
		decision.EvaluationID != request.EvaluationID || decision.Phase != policy.PreDispatch ||
		decision.Outcome != "allowed" || !decision.ApprovalRequired ||
		decision.ManifestDigest != request.Manifest.ManifestDigest || decision.ActorID != request.Actor.ActorID ||
		decision.ActorRevision != request.Actor.Revision || decision.PolicyDigest != manifest.PolicyDigest ||
		decision.PolicyRevision != manifest.PolicyRevision || decision.SignerKeyID != signer.KeyID ||
		decision.SignerKeyRevision != signer.KeyRevision || decision.AuditOrganizationID != manifest.OrganizationID ||
		decision.AuditTenantID != manifest.TenantID || decision.AuditCaseID != manifest.CaseID {
		return lifecycle.NewError(lifecycle.Denied, "policy_decision_binding")
	}
	evaluatedAt, err := time.Parse(timestampLayout, decision.EvaluatedAt)
	if err != nil || evaluatedAt.Before(startedAt) || evaluatedAt.After(finishedAt) {
		return lifecycle.NewError(lifecycle.Denied, "policy_decision_stale")
	}
	return nil
}

func validatePolicyActor(actor policy.ActorAuthority, manifest actionmanifest.Manifest) error {
	if actor.ActorID != manifest.RequestorActorID {
		return lifecycle.NewError(lifecycle.Denied, "actor_scope_mismatch")
	}
	if err := validateActor(actor, manifest.OrganizationID, manifest.TenantID, manifest.CaseID, "action.request"); err != nil {
		return err
	}
	return nil
}

func validateApprovalInputs(command preDispatchCommand, verified actionmanifest.VerifiedEnvelope) error {
	manifest := verified.Manifest()
	fingerprint := command.Fingerprint
	if _, err := policy.VerifyDecisionDigest(command.IntentDecision); err != nil ||
		command.IntentDecision.Phase != policy.IntentCreated || command.IntentDecision.Outcome != "allowed" ||
		!command.IntentDecision.ApprovalRequired || command.IntentDecision.ManifestDigest != verified.ManifestDigest ||
		command.IntentDecision.PolicyDigest != manifest.PolicyDigest ||
		command.IntentDecision.PolicyRevision != manifest.PolicyRevision ||
		command.IntentDecision.ActorID != manifest.RequestorActorID {
		return lifecycle.NewError(lifecycle.Denied, "approval_binding")
	}
	if command.PolicyActor.Revision < command.IntentDecision.ActorRevision {
		return lifecycle.NewError(lifecycle.Denied, "identity_state_stale")
	}
	if fingerprint.ManifestDigest != verified.ManifestDigest || fingerprint.OrganizationID != manifest.OrganizationID ||
		fingerprint.TenantID != manifest.TenantID || fingerprint.CaseID != manifest.CaseID ||
		fingerprint.RequestorActorID != manifest.RequestorActorID ||
		fingerprint.ActionOwnerActorID != manifest.ActionOwnerActorID || fingerprint.PolicyDigest != manifest.PolicyDigest ||
		fingerprint.PolicyRevision != manifest.PolicyRevision || !sameOptionalDigest(fingerprint.ROEDigest, manifest.ROEDigest) ||
		fingerprint.ValidFrom != manifest.ValidFrom || fingerprint.ValidUntil != manifest.ValidUntil ||
		fingerprint.MaximumUseCount != manifest.MaximumUseCount ||
		fingerprint.PolicyDecisionDigest != command.IntentDecision.DecisionDigest {
		return lifecycle.NewError(lifecycle.Denied, "approval_binding")
	}
	return nil
}

func sameOptionalDigest(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func (gate *preDispatchGate) verifyROE(ctx context.Context, manifest actionmanifest.Manifest,
	verifyAt time.Time) (*verifiedROEProof, error) {
	if manifest.ROEDigest == nil {
		if manifest.ActionTier == "T4" {
			return nil, lifecycle.NewError(lifecycle.Denied, "roe_required")
		}
		return nil, nil
	}
	expected := signedROEExpectation{Digest: *manifest.ROEDigest, OrganizationID: manifest.OrganizationID,
		TenantID: manifest.TenantID, CaseID: manifest.CaseID, VerifyAt: formatTime(verifyAt)}
	proof, err := gate.roe.verifySignedROE(ctx, expected)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return nil, contextErr
		}
		return nil, lifecycle.NewError(lifecycle.Denied, "roe_authority")
	}
	validFrom, fromErr := time.Parse(timestampLayout, proof.ValidFrom)
	validUntil, untilErr := time.Parse(timestampLayout, proof.ValidUntil)
	if proof.Digest != expected.Digest || proof.OrganizationID != expected.OrganizationID ||
		proof.TenantID != expected.TenantID || proof.CaseID != expected.CaseID || proof.Revision == 0 ||
		proof.VerifiedAt != expected.VerifyAt || !proof.SignerActive || proof.SignerKeyRevision == 0 ||
		!tokenPattern.MatchString(proof.SignerKeyID) || proof.SignatureAlgorithm != "ed25519" ||
		fromErr != nil || untilErr != nil || validUntil.Before(validFrom) || validUntil.Equal(validFrom) ||
		verifyAt.Before(validFrom) || !verifyAt.Before(validUntil) {
		return nil, lifecycle.NewError(lifecycle.Denied, "roe_authority")
	}
	return &proof, nil
}

func validateConsumedApproval(record lifecycle.Record, command preDispatchCommand,
	manifest actionmanifest.Manifest) error {
	if err := lifecycle.ValidateRecord(record); err != nil ||
		record.ApprovalID != command.Approval.ApprovalID || record.OrganizationID != manifest.OrganizationID ||
		record.TenantID != manifest.TenantID || record.CaseID != manifest.CaseID ||
		record.ManifestDigest != command.Fingerprint.ManifestDigest ||
		record.FingerprintDigest != command.Fingerprint.FingerprintDigest ||
		record.PolicyDecisionDigest != command.IntentDecision.DecisionDigest ||
		record.RequestorActorID != manifest.RequestorActorID || record.ActionOwnerActorID != manifest.ActionOwnerActorID ||
		record.ActionTier != manifest.ActionTier || record.UseCount == 0 || record.UseCount > record.MaximumUseCount ||
		record.MaximumUseCount != command.Fingerprint.MaximumUseCount {
		return lifecycle.NewError(lifecycle.Denied, "approval_authority")
	}
	if record.Revision != command.Approval.ExpectedRevision+1 || record.LastActorID != manifest.ActionOwnerActorID ||
		record.LastActorRevision != command.Approval.Actor.Revision {
		return lifecycle.NewError(lifecycle.Denied, "approval_authority")
	}
	return nil
}

func mapManifestError(err error) error {
	switch actionmanifest.Code(err) {
	case actionmanifest.InvalidInput:
		return lifecycle.NewError(lifecycle.InvalidInput, "manifest_authority")
	case actionmanifest.Canceled:
		return lifecycle.NewError(lifecycle.Canceled, "request_canceled")
	case actionmanifest.Timeout:
		return lifecycle.NewError(lifecycle.Timeout, "request_timeout")
	default:
		return lifecycle.NewError(lifecycle.Denied, "manifest_authority")
	}
}

func mapPolicyError(err error) error {
	switch policy.Code(err) {
	case policy.InvalidInput:
		return lifecycle.NewError(lifecycle.InvalidInput, policy.Reason(err))
	case policy.Denied:
		return lifecycle.NewError(lifecycle.Denied, policy.Reason(err))
	case policy.Canceled:
		return lifecycle.NewError(lifecycle.Canceled, policy.Reason(err))
	case policy.Timeout:
		return lifecycle.NewError(lifecycle.Timeout, policy.Reason(err))
	default:
		return lifecycle.NewError(lifecycle.Unavailable, policy.Reason(err))
	}
}

func lifecycleOutcome(err error) string {
	switch lifecycle.Code(err) {
	case lifecycle.InvalidInput:
		return "invalid"
	case lifecycle.Denied:
		return "denied"
	case lifecycle.Canceled:
		return "canceled"
	case lifecycle.Timeout:
		return "timeout"
	default:
		return "unavailable"
	}
}
