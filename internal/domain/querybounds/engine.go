package querybounds

import (
	"context"
	"errors"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/queryconnector"
)

type Engine struct {
	audit  AuditSink
	clock  Clock
	replay ReplayGuard
}

func New(audit AuditSink, clock Clock, replay ReplayGuard) (*Engine, error) {
	if audit == nil || clock == nil || replay == nil {
		return nil, newError(InvalidInput, "dependencies_required", nil)
	}
	return &Engine{audit: audit, clock: clock, replay: replay}, nil
}

func (engine *Engine) Admit(ctx context.Context, query queryconnector.ValidatedQuery, authority AuthoritySnapshot) (Admission, error) {
	if engine == nil || engine.audit == nil || engine.clock == nil || engine.replay == nil {
		return Admission{}, newError(Unavailable, "engine_unavailable", nil)
	}
	if query.Digest() == "" {
		return Admission{}, newError(InvalidInput, "validated_query_required", nil)
	}
	now := engine.clock.Now().UTC()
	decision, err := baseDecision(query, authority, now)
	if err != nil {
		return Admission{}, err
	}
	if contextErr := checkContext(ctx); contextErr != nil {
		return engine.finish(ctx, query, decision, contextErr)
	}
	if err := engine.evaluate(ctx, query, authority, now, &decision); err != nil {
		return engine.finish(ctx, query, decision, err)
	}
	decision.Outcome, decision.ReasonCode = "allowed", "bounds_satisfied"
	return engine.finish(ctx, query, decision, nil)
}

func (engine *Engine) evaluate(ctx context.Context, validated queryconnector.ValidatedQuery, authority AuthoritySnapshot,
	now time.Time, decision *Decision) error {
	if err := validateAuthority(authority, now); err != nil {
		return err
	}
	query := validated.Value()
	if query.Scope.OrganizationID != authority.OrganizationID || query.Scope.TenantID != authority.TenantID ||
		query.Scope.CaseID != authority.CaseID || query.Scope.SourceID != authority.SourceID ||
		!sameStrings(query.Scope.ResourceIDs, authority.ResourceIDs) || query.Authority.ActorID != authority.ActorID {
		return newError(Denied, "scope_denied", nil)
	}
	if query.CapabilityDigest != authority.CapabilityDigest {
		return newError(Denied, "capability_mismatch", nil)
	}
	if query.Authority.AuthorizationDigest != authority.AuthorizationDecisionDigest ||
		query.Authority.PolicyDecisionDigest != authority.PolicyDecisionDigest ||
		query.Authority.AuditReservationDigest != authority.AuditReservationDigest {
		return newError(Denied, "authority_binding_mismatch", nil)
	}
	if !authority.ActorActive {
		return newError(Denied, "actor_revoked", nil)
	}
	if !authority.SourceActive {
		return newError(Denied, "source_revoked", nil)
	}
	if !authority.AllowlistActive {
		return newError(Denied, "allowlist_revoked", nil)
	}
	if !authority.CapabilityActive {
		return newError(Denied, "capability_revoked", nil)
	}
	if authority.EmergencyStopActive {
		return newError(Denied, "emergency_stop", nil)
	}
	if !authority.AuthorizationAllowed {
		return newError(Denied, "authorization_denied", nil)
	}
	if !authority.PolicyAllowed {
		return newError(Denied, "policy_denied", nil)
	}
	if authority.ApprovalRequired && (!authority.ApprovalAllowed || !authority.ApprovalExpiresAt.UTC().After(now) ||
		authority.ApprovalQueryDigest != validated.Digest() || authority.ApprovalPolicyDecisionDigest != authority.PolicyDecisionDigest) {
		return newError(Denied, "approval_denied", nil)
	}
	start, startErr := time.Parse("2006-01-02T15:04:05.000000000Z", query.TimeRange.Start)
	end, endErr := time.Parse("2006-01-02T15:04:05.000000000Z", query.TimeRange.End)
	requested, requestErr := time.Parse("2006-01-02T15:04:05.000000000Z", query.RequestedAt)
	deadline, deadlineErr := time.Parse("2006-01-02T15:04:05.000000000Z", query.Deadline)
	if startErr != nil || endErr != nil || requestErr != nil || deadlineErr != nil || !start.Before(end) {
		return newError(InvalidInput, "utc_interval_invalid", nil)
	}
	if end.Sub(start) > authority.MaximumInterval {
		return newError(Denied, "interval_excessive", nil)
	}
	if end.After(now.Add(authority.MaximumFutureSkew)) || requested.After(now.Add(authority.MaximumFutureSkew)) {
		return newError(Denied, "future_unsafe", nil)
	}
	if !deadline.After(now) {
		return newError(Denied, "query_deadline_elapsed", nil)
	}
	if !withinLimits(query.Limits, authority.MaximumLimits) {
		return newError(Denied, "limits_excessive", nil)
	}
	if err := checkContext(ctx); err != nil {
		return err
	}
	replayed, err := engine.replay.Observe(ctx, query.QueryID, validated.Digest())
	if err != nil {
		if errors.Is(err, ErrChangedReplay) {
			return newError(Conflict, "changed_replay", err)
		}
		if contextErr := checkContext(ctx); contextErr != nil {
			return contextErr
		}
		return newError(Unavailable, "replay_guard_unavailable", err)
	}
	decision.Replayed = replayed
	return checkContext(ctx)
}

func (engine *Engine) finish(ctx context.Context, query queryconnector.ValidatedQuery, decision Decision,
	resultErr error) (Admission, error) {
	if resultErr != nil {
		code, reason := nonSecretReason(resultErr)
		decision.Outcome, decision.ReasonCode, decision.Replayed = outcomeFor(code), reason, false
	}
	finalized, err := FinalizeDecision(decision)
	if err != nil {
		return Admission{}, err
	}
	auditParent := context.Background()
	if ctx != nil {
		auditParent = context.WithoutCancel(ctx)
	}
	auditCtx, cancel := context.WithTimeout(auditParent, auditTimeout)
	defer cancel()
	if err := engine.audit.AppendQueryBoundDecision(auditCtx, finalized); err != nil {
		finalized.Outcome, finalized.ReasonCode, finalized.Replayed = "unavailable", "audit_unavailable", false
		updated, finalizeErr := FinalizeDecision(finalized)
		if finalizeErr != nil {
			return Admission{}, finalizeErr
		}
		finalized = updated
		return Admission{Decision: finalized}, newError(Unavailable, "audit_unavailable", err)
	}
	if resultErr != nil {
		return Admission{Decision: finalized}, resultErr
	}
	return Admission{Query: query, Decision: finalized}, nil
}

func baseDecision(validated queryconnector.ValidatedQuery, authority AuthoritySnapshot, now time.Time) (Decision, error) {
	query := validated.Value()
	authorityValueDigest, err := authorityDigest(authority)
	if err != nil {
		return Decision{}, newError(InvalidInput, "authority_encoding", err)
	}
	resources, err := resourceDigest(query.Scope)
	if err != nil {
		return Decision{}, newError(InvalidInput, "resource_encoding", err)
	}
	limits, err := limitsDigest(query.Limits)
	if err != nil {
		return Decision{}, newError(InvalidInput, "limits_encoding", err)
	}
	approvalDigest := ""
	if validDigest(authority.ApprovalDecisionDigest) {
		approvalDigest = authority.ApprovalDecisionDigest
	}
	return Decision{SchemaVersion: DecisionSchemaVersion, ContractVersion: ContractVersion,
		QueryID: query.QueryID, QueryDigest: validated.Digest(), Outcome: "invalid", ReasonCode: "evaluation_pending",
		OrganizationID: query.Scope.OrganizationID, TenantID: query.Scope.TenantID, CaseID: query.Scope.CaseID,
		ActorID: query.Authority.ActorID, ActorRevision: authority.ActorRevision,
		SourceID: query.Scope.SourceID, SourceRevision: authority.SourceRevision, AllowlistRevision: authority.AllowlistRevision,
		CapabilityDigest: query.CapabilityDigest, CapabilityRevision: authority.CapabilityRevision,
		AuthorityDigest: authorityValueDigest, ResourceScopeDigest: resources,
		AuthorizationDecisionDigest: query.Authority.AuthorizationDigest, PolicyDecisionDigest: query.Authority.PolicyDecisionDigest,
		PolicyRevision: authority.PolicyRevision, ApprovalDecisionDigest: approvalDigest, ApprovalRequired: authority.ApprovalRequired,
		AuditReservationDigest: query.Authority.AuditReservationDigest, RevocationRevision: authority.RevocationRevision,
		IntervalStart: query.TimeRange.Start, IntervalEnd: query.TimeRange.End, LimitsDigest: limits, EvaluatedAt: formatTime(now)}, nil
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return newError(InvalidInput, "context_required", nil)
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return newError(Timeout, "request_timeout", err)
		}
		return newError(Canceled, "request_canceled", err)
	}
	return nil
}

func outcomeFor(code ErrorCode) string {
	switch code {
	case InvalidInput:
		return "invalid"
	case Unavailable:
		return "unavailable"
	default:
		return "denied"
	}
}
