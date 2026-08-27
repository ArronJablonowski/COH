package redaction

import (
	"context"
	"time"
)

func (service *preflight) authorizeApproval(ctx context.Context, command Command, plan ApprovedPlan,
	intent string, now time.Time) (ApprovalUseProof, error) {
	request := ApprovalUseRequest{Case: command.Case, ApprovalID: plan.ApprovalID,
		FingerprintDigest: plan.ApprovalFingerprintDigest, ManifestDigest: plan.ApprovalManifestDigest,
		PolicyDecisionDigest: plan.PolicyDecisionDigest, IntentDigest: intent, ActorID: command.ActorID,
		ActorRevision: command.ActorRevision, IdempotencyKey: command.IdempotencyKey, Deadline: command.Deadline}
	proof, _, err := service.approvals.AuthorizeUse(ctx, request)
	if err != nil {
		return ApprovalUseProof{}, mapDependency(ctx, "approval_use_unavailable", err)
	}
	if err = service.verifyApproval(ctx, proof, command, plan, intent, now); err != nil {
		return ApprovalUseProof{}, err
	}
	return proof, nil
}

func (service *preflight) verifyApproval(ctx context.Context, proof ApprovalUseProof, command Command,
	plan ApprovedPlan, intent string, now time.Time) error {
	if ValidateApprovalUse(proof) != nil || proof.ApprovalID != plan.ApprovalID ||
		proof.FingerprintDigest != plan.ApprovalFingerprintDigest || proof.ManifestDigest != plan.ApprovalManifestDigest ||
		proof.PolicyDecisionDigest != plan.PolicyDecisionDigest || proof.IntentDigest != intent ||
		now.Before(proof.ValidFrom) || !now.Before(proof.ValidUntil) {
		return newError(Denied, string(ReasonApprovalInvalid), false, nil)
	}
	if err := service.approvals.VerifyUse(ctx, proof); err != nil {
		return mapDependency(ctx, "approval_verification_unavailable", err)
	}
	return nil
}

func planMatchesCommand(plan ApprovedPlan, command Command) bool {
	return plan.Case == command.Case && plan.Source == command.Source && plan.PlanDigest == command.PlanDigest &&
		plan.RuleDigest == command.RuleDigest && plan.ReasonDigest == command.ReasonDigest &&
		plan.OutputMediaType == command.OutputMediaType && plan.OutputClassification == command.OutputClassification &&
		plan.PolicyDigest == command.PolicyDigest
}

func ruleMatchesPlan(rule RuleSet, plan ApprovedPlan) bool {
	if rule.RuleID != plan.RuleID || rule.Revision != plan.RuleRevision || rule.RuleDigest != plan.RuleDigest ||
		plan.MaximumOutputBytes > rule.MaximumOutputBytes || len(plan.Spans) > int(rule.MaximumSpans) ||
		!containsString(rule.AllowedMediaTypes, plan.Source.Artifact.MediaType) ||
		!containsString(rule.AllowedMediaTypes, plan.OutputMediaType) {
		return false
	}
	var selected int64
	for _, span := range plan.Spans {
		selected += span.SourceEnd - span.SourceStart
		if !containsMode(rule.PermittedModes, span.ReplacementMode) {
			return false
		}
	}
	return selected <= rule.MaximumSelectedBytes
}

func validateBoundDecision(value Decision, request AuthorizationRequest, now time.Time) error {
	command := request.Command
	if ValidateDecision(value) != nil || value.AuthorizationDigest != request.AuthorizationDigest ||
		value.IntentDigest != request.IntentDigest || value.Case != command.Case || value.ActorID != command.ActorID ||
		value.ActorRevision != command.ActorRevision || value.SourceArtifactDigest != command.Source.Artifact.Digest ||
		value.PlanDigest != command.PlanDigest || value.ApprovalFingerprintDigest != request.ApprovalUse.FingerprintDigest ||
		value.PolicyDigest != command.PolicyDigest || value.ExpectedCaseRevision != request.CaseRevision ||
		!sameHead(value.ExpectedCustodyHead, request.CurrentCustodyHead) || value.IssuedAt.After(now) ||
		!value.ExpiresAt.After(now) || value.ExpiresAt.After(command.Deadline) ||
		value.ExpiresAt.After(request.Plan.ValidUntil) || value.ExpiresAt.After(request.ApprovalUse.ValidUntil) {
		return newError(Denied, "decision_binding_invalid", false, nil)
	}
	return nil
}

func validCaseSnapshot(value CaseSnapshot) bool {
	return validCase(value.Case) && validCaseState(value.State) && validClassification(value.Classification) &&
		boundedRevision(value.Revision) && digestPattern.MatchString(value.ProvenanceDigest)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsMode(values []ReplacementMode, target ReplacementMode) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
