package opaengine

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
	"github.com/ArronJablonowski/COH/internal/policy"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/topdown"
)

type evaluationInput struct {
	SchemaVersion  string                  `json:"schema_version"`
	EvaluationID   string                  `json:"evaluation_id"`
	Phase          policy.Phase            `json:"phase"`
	EvaluatedAt    string                  `json:"evaluated_at"`
	Actor          evaluationActor         `json:"actor"`
	ManifestDigest string                  `json:"manifest_digest"`
	Manifest       actionmanifest.Manifest `json:"manifest"`
	Runtime        evaluationRuntime       `json:"runtime"`
	Policy         evaluationPolicy        `json:"policy"`
}

type evaluationActor struct {
	ActorID        string   `json:"actor_id"`
	OrganizationID string   `json:"organization_id"`
	TenantID       string   `json:"tenant_id"`
	CaseID         string   `json:"case_id"`
	Revision       uint64   `json:"revision"`
	Roles          []string `json:"roles"`
	Permissions    []string `json:"permissions"`
}

type evaluationRuntime struct {
	DataRoute             string `json:"data_route"`
	ValidatorState        string `json:"validator_state"`
	ToolRegistered        bool   `json:"tool_registered"`
	TargetsAuthorized     bool   `json:"targets_authorized"`
	TenantAuthorized      bool   `json:"tenant_authorized"`
	DataRouteAuthorized   bool   `json:"data_route_authorized"`
	CapabilityFieldsKnown bool   `json:"capability_fields_known"`
	EmergencyStopActive   bool   `json:"emergency_stop_active"`
}

type evaluationPolicy struct {
	BundleID       string `json:"bundle_id"`
	PolicyDigest   string `json:"policy_digest"`
	PolicyRevision uint64 `json:"policy_revision"`
}

func (engine *Engine) Evaluate(ctx context.Context, request policy.Request, authority policy.BundleAuthority) (policy.Decision, error) {
	now := time.Time{}
	if engine != nil && engine.clock != nil {
		now = engine.clock.Now().UTC()
	}
	current := (*snapshot)(nil)
	if engine != nil {
		current = engine.active.Load()
	}
	decision := baseDecision(request, current, now)
	if engine == nil || engine.audit == nil || engine.clock == nil {
		return decisionWithError(decision, policy.NewError(policy.Unavailable, "engine_unavailable")), policy.NewError(policy.Unavailable, "engine_unavailable")
	}
	if now.IsZero() {
		return engine.record(ctx, decision, policy.NewError(policy.Unavailable, "clock_unavailable"))
	}
	if err := contextError(ctx); err != nil {
		return engine.record(ctx, decision, err)
	}
	if current == nil {
		return engine.record(ctx, decision, policy.NewError(policy.Denied, "policy_unavailable"))
	}
	if err := validateAuthority(authority); err != nil {
		return engine.record(ctx, decision, err)
	}
	if !sameAuthority(authority, current.metadata) {
		return engine.record(ctx, decision, policy.NewError(policy.Denied, "policy_signer_revoked"))
	}
	if now.Before(current.validFrom) || !now.Before(current.validUntil) {
		return engine.record(ctx, decision, policy.NewError(policy.Denied, "policy_expired"))
	}
	if err := validateRequest(request); err != nil {
		return engine.record(ctx, decision, err)
	}
	manifest := request.Manifest.Manifest()
	if manifest.PolicyDigest != current.digest || manifest.PolicyRevision != current.metadata.PolicyRevision {
		return engine.record(ctx, decision, policy.NewError(policy.Denied, "policy_state_stale"))
	}
	if manifest.OrganizationID != current.metadata.OrganizationID || manifest.TenantID != current.metadata.TenantID {
		return engine.record(ctx, decision, policy.NewError(policy.Denied, "policy_scope_mismatch"))
	}
	manifestFrom, _ := time.Parse(timestampLayout, manifest.ValidFrom)
	manifestUntil, _ := time.Parse(timestampLayout, manifest.ValidUntil)
	if now.Before(manifestFrom) || !now.Before(manifestUntil) {
		return engine.record(ctx, decision, policy.NewError(policy.Denied, "manifest_not_current"))
	}
	input := newEvaluationInput(request, current, now)
	encoded, err := json.Marshal(input)
	if err != nil {
		return engine.record(ctx, decision, policy.NewError(policy.InvalidInput, "evaluation_input"))
	}
	decision.InputDigest = digestBytes(encoded)
	inputValue, err := domaincontract.DecodeUnique(encoded)
	if err != nil {
		return engine.record(ctx, decision, policy.NewError(policy.InvalidInput, "evaluation_input"))
	}
	opaInput, err := ast.InterfaceToValue(inputValue)
	if err != nil {
		return engine.record(ctx, decision, policy.NewError(policy.InvalidInput, "evaluation_input"))
	}
	txn, err := current.store.NewTransaction(ctx)
	if err != nil {
		return engine.record(ctx, decision, policy.NewError(policy.Unavailable, "policy_evaluation_failed"))
	}
	defer current.store.Abort(ctx, txn)
	results, err := topdown.NewQuery(current.query).
		WithCompiler(current.compiler).
		WithStore(current.store).
		WithTransaction(txn).
		WithInput(ast.NewTerm(opaInput)).
		WithTime(now).
		WithStrictBuiltinErrors(true).
		Run(ctx)
	if err != nil {
		if contextErr := contextError(ctx); contextErr != nil {
			return engine.record(ctx, decision, contextErr)
		}
		return engine.record(ctx, decision, policy.NewError(policy.Unavailable, "policy_evaluation_failed"))
	}
	output, err := decodeOutput(results)
	if err != nil {
		return engine.record(ctx, decision, err)
	}
	decision.ApprovalRequired = output.ApprovalRequired
	decision.ReasonCode = output.ReasonCode
	if !output.Allow {
		return engine.record(ctx, decision, policy.NewError(policy.Denied, output.ReasonCode))
	}
	decision.Outcome = "allowed"
	return engine.record(ctx, decision, nil)
}

func newEvaluationInput(request policy.Request, current *snapshot, now time.Time) evaluationInput {
	return evaluationInput{
		SchemaVersion: "coh.policy-input/v1", EvaluationID: request.EvaluationID, Phase: request.Phase,
		EvaluatedAt: now.Format(timestampLayout), ManifestDigest: request.Manifest.ManifestDigest,
		Manifest: request.Manifest.Manifest(),
		Actor: evaluationActor{ActorID: request.Actor.ActorID, OrganizationID: request.Actor.OrganizationID,
			TenantID: request.Actor.TenantID, CaseID: request.Actor.CaseID, Revision: request.Actor.Revision,
			Roles: slices.Clone(request.Actor.Roles), Permissions: slices.Clone(request.Actor.Permissions)},
		Runtime: evaluationRuntime{DataRoute: request.Runtime.DataRoute, ValidatorState: request.Runtime.ValidatorState,
			ToolRegistered: request.Runtime.ToolRegistered, TargetsAuthorized: request.Runtime.TargetsAuthorized,
			TenantAuthorized: request.Runtime.TenantAuthorized, DataRouteAuthorized: request.Runtime.DataRouteAuthorized,
			CapabilityFieldsKnown: request.Runtime.CapabilityFieldsKnown, EmergencyStopActive: request.Runtime.EmergencyStopActive},
		Policy: evaluationPolicy{BundleID: current.metadata.BundleID, PolicyDigest: current.digest,
			PolicyRevision: current.metadata.PolicyRevision},
	}
}

func decodeOutput(results topdown.QueryResultSet) (policyOutput, error) {
	if len(results) != 1 || results[0][ast.Var("result")] == nil {
		return policyOutput{}, policy.NewError(policy.Denied, "policy_undefined")
	}
	value, err := ast.JSON(results[0][ast.Var("result")].Value)
	if err != nil {
		return policyOutput{}, policy.NewError(policy.Denied, "policy_output_invalid")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return policyOutput{}, policy.NewError(policy.Denied, "policy_output_invalid")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) != 3 || fields["allow"] == nil ||
		fields["reason_code"] == nil || fields["approval_required"] == nil {
		return policyOutput{}, policy.NewError(policy.Denied, "policy_output_invalid")
	}
	var output policyOutput
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		return policyOutput{}, policy.NewError(policy.Denied, "policy_output_invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || !tokenPattern.MatchString(output.ReasonCode) {
		return policyOutput{}, policy.NewError(policy.Denied, "policy_output_invalid")
	}
	return output, nil
}

func baseDecision(request policy.Request, current *snapshot, now time.Time) policy.Decision {
	decision := policy.Decision{SchemaVersion: policy.SchemaVersion, ContractVersion: policy.ContractVersion,
		EvaluationID: request.EvaluationID, Phase: request.Phase, ManifestDigest: request.Manifest.ManifestDigest,
		ActorID: request.Actor.ActorID, ActorRevision: request.Actor.Revision, EvaluatedAt: now.Format(timestampLayout)}
	if current != nil {
		decision.PolicyDigest, decision.PolicyRevision, decision.BundleID = current.digest, current.metadata.PolicyRevision, current.metadata.BundleID
		decision.SignerKeyID, decision.SignerKeyRevision = current.metadata.SignerKeyID, current.metadata.SignerKeyRevision
	}
	return decision
}

func (engine *Engine) record(ctx context.Context, decision policy.Decision, resultErr error) (policy.Decision, error) {
	decision = decisionWithError(decision, resultErr)
	auditCtx, cancel := auditContext(ctx)
	defer cancel()
	if err := engine.audit.AppendPolicyEvent(auditCtx, policy.AuditEvent{Kind: "policy_evaluation", Decision: &decision}); err != nil {
		auditErr := policy.NewError(policy.Unavailable, "audit_unavailable")
		return decisionWithError(decision, auditErr), auditErr
	}
	return decision, resultErr
}

func decisionWithError(decision policy.Decision, err error) policy.Decision {
	if err != nil {
		decision.Outcome, decision.ReasonCode, decision.ApprovalRequired = outcome(err), policy.Reason(err), false
	} else if decision.Outcome == "" {
		decision.Outcome, decision.ReasonCode = "allowed", "policy_allowed"
	}
	decision.DecisionDigest = ""
	encoded, marshalErr := json.Marshal(decision)
	if marshalErr != nil {
		panic("policy decisions contain only JSON-safe fields")
	}
	decision.DecisionDigest = digestBytes(encoded)
	return decision
}

func outcome(err error) string {
	switch policy.Code(err) {
	case policy.InvalidInput:
		return "invalid"
	case policy.Denied:
		return "denied"
	case policy.Canceled:
		return "canceled"
	case policy.Timeout:
		return "timeout"
	default:
		return "unavailable"
	}
}
