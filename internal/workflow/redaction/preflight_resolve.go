package redaction

import (
	"context"
	"time"
)

func (service *preflight) resolveCurrent(ctx context.Context, command Command, now time.Time) (
	CaseSnapshot, RuleSet, ApprovedPlan, VerifiedSource, CustodyHead, error) {
	current, err := service.loadCase(ctx, command)
	if err != nil {
		return CaseSnapshot{}, RuleSet{}, ApprovedPlan{}, VerifiedSource{}, CustodyHead{}, err
	}
	plan, rule, err := service.loadPlanAndRule(ctx, command, now)
	if err != nil {
		return CaseSnapshot{}, RuleSet{}, ApprovedPlan{}, VerifiedSource{}, CustodyHead{}, err
	}
	source, err := service.resolveSource(ctx, command)
	if err != nil {
		return CaseSnapshot{}, RuleSet{}, ApprovedPlan{}, VerifiedSource{}, CustodyHead{}, err
	}
	head, err := service.custody.LoadCustodyHead(ctx, command.Case)
	if err != nil {
		return CaseSnapshot{}, RuleSet{}, ApprovedPlan{}, VerifiedSource{}, CustodyHead{}, mapDependency(ctx, "custody_head_unavailable", err)
	}
	if !validHead(head) || !sameHead(head, command.ExpectedCustodyHead) {
		return CaseSnapshot{}, RuleSet{}, ApprovedPlan{}, VerifiedSource{}, CustodyHead{}, newError(Conflict, "stale_custody", true, nil)
	}
	return current, rule, plan, source, head, nil
}

func (service *preflight) loadCase(ctx context.Context, command Command) (CaseSnapshot, error) {
	current, found, err := service.cases.LoadCase(ctx, command.Case)
	if err != nil {
		return CaseSnapshot{}, mapDependency(ctx, "case_load_unavailable", err)
	}
	if !found {
		return CaseSnapshot{}, newError(NotFound, string(ReasonCaseNotFound), false, nil)
	}
	if !validCaseSnapshot(current) || current.Case != command.Case {
		return CaseSnapshot{}, newError(Denied, "case_snapshot_invalid", false, nil)
	}
	if current.State != "open" {
		return CaseSnapshot{}, newError(Denied, string(ReasonCaseStateDenied), false, nil)
	}
	if current.Revision != command.ExpectedCaseRevision {
		return CaseSnapshot{}, newError(Conflict, string(ReasonStaleCase), true, nil)
	}
	return current, nil
}

func (service *preflight) loadPlanAndRule(ctx context.Context, command Command, now time.Time) (ApprovedPlan, RuleSet, error) {
	plan, found, err := service.plans.ResolvePlan(ctx, command.Case, command.PlanDigest)
	if err != nil {
		return ApprovedPlan{}, RuleSet{}, mapDependency(ctx, "plan_load_unavailable", err)
	}
	if !found {
		return ApprovedPlan{}, RuleSet{}, newError(NotFound, "plan_not_found", false, nil)
	}
	if ValidatePlan(plan) != nil || !planMatchesCommand(plan, command) || now.Before(plan.ValidFrom) || !now.Before(plan.ValidUntil) {
		return ApprovedPlan{}, RuleSet{}, newError(Denied, string(ReasonPlanInvalid), false, nil)
	}
	rule, found, err := service.plans.ResolveRule(ctx, plan.RuleDigest)
	if err != nil {
		return ApprovedPlan{}, RuleSet{}, mapDependency(ctx, "rule_load_unavailable", err)
	}
	if !found {
		return ApprovedPlan{}, RuleSet{}, newError(NotFound, "rule_not_found", false, nil)
	}
	if ValidateRule(rule) != nil || !ruleMatchesPlan(rule, plan) {
		return ApprovedPlan{}, RuleSet{}, newError(Denied, string(ReasonRuleInvalid), false, nil)
	}
	return plan, rule, nil
}

func (service *preflight) resolveSource(ctx context.Context, command Command) (VerifiedSource, error) {
	verified, err := service.sources.ResolveSource(ctx, command.Case, cloneEvidence(command.Source))
	if err != nil {
		return VerifiedSource{}, mapDependency(ctx, "source_resolution_unavailable", err)
	}
	if !validEvidence(verified.Reference) || verified.Reference != command.Source ||
		!allDigests(verified.SourceIdentityDigest, verified.VerificationDigest) {
		return VerifiedSource{}, newError(Denied, string(ReasonSourceInvalid), false, nil)
	}
	return verified, nil
}
