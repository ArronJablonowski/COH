package deploymentprofile

import (
	"context"
	"encoding/json"

	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

// Validator is the fail-closed startup gate. A profile cannot authorize
// composition unless its redacted decision is accepted by the audit sink.
type Validator struct {
	Audit AuditSink
}

func (validator Validator) Validate(ctx context.Context, input []byte, authority AuthoritySnapshot) (Decision, error) {
	decision, profileErr := evaluate(ctx, input)
	if validator.Audit == nil {
		return auditUnavailable(decision), validationError(Unavailable, "audit_unavailable", nil)
	}
	if profileErr != nil {
		return validator.record(ctx, bindAuthority(decision, authority), profileErr)
	}
	config, err := decodedConfig(input)
	if err != nil {
		return validator.record(ctx, bindAuthority(decision, authority), validationError(InvalidInput, "schema_shape", nil))
	}
	decision, err = authorizeChange(decision, config.Change, authority)
	return validator.record(ctx, decision, err)
}

func authorizeChange(decision Decision, change ChangeControl, authority AuthoritySnapshot) (Decision, error) {
	if !uuidV7Pattern.MatchString(authority.OrganizationID) || !uuidV7Pattern.MatchString(authority.ActorID) ||
		(authority.CurrentRevision == 0 && authority.CurrentConfigDigest != "") ||
		(authority.CurrentRevision > 0 && !digestPattern.MatchString(authority.CurrentConfigDigest)) {
		return changeDecision(decision, "invalid", "authority_snapshot_invalid"), validationError(InvalidInput, "authority_snapshot_invalid", nil)
	}
	if change.OrganizationID != authority.OrganizationID || change.ActorID != authority.ActorID {
		return changeDecision(decision, "denied", "authority_scope_mismatch"), validationError(Denied, "authority_scope_mismatch", nil)
	}
	if !authority.Active {
		return changeDecision(decision, "denied", "actor_revoked"), validationError(Denied, "actor_revoked", nil)
	}
	if change.Revision == authority.CurrentRevision && decision.ConfigDigest == authority.CurrentConfigDigest {
		decision.Replayed = true
		decision.DecisionDigest = decisionDigest(decision)
		return decision, nil
	}
	if change.Revision != authority.CurrentRevision+1 {
		return changeDecision(decision, "denied", "stale_revision"), validationError(Denied, "stale_revision", nil)
	}
	if change.PreviousConfigDigest != authority.CurrentConfigDigest {
		return changeDecision(decision, "denied", "lineage_mismatch"), validationError(Denied, "lineage_mismatch", nil)
	}
	return decision, nil
}

func (validator Validator) record(ctx context.Context, decision Decision, resultErr error) (Decision, error) {
	decision.DecisionDigest = decisionDigest(decision)
	if err := validator.Audit.AppendProfileDecision(ctx, decision); err != nil {
		return auditUnavailable(decision), validationError(Unavailable, "audit_unavailable", nil)
	}
	return decision, resultErr
}

func decodedConfig(input []byte) (Config, error) {
	canonical, err := domaincontract.Canonicalize(input)
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(canonical, &config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func bindAuthority(decision Decision, authority AuthoritySnapshot) Decision {
	if decision.OrganizationID == "" {
		decision.OrganizationID = authority.OrganizationID
	}
	if decision.ActorID == "" {
		decision.ActorID = authority.ActorID
	}
	decision.DecisionDigest = decisionDigest(decision)
	return decision
}

func changeDecision(decision Decision, outcome, reason string) Decision {
	decision.Outcome = outcome
	decision.ReasonCode = reason
	decision.Replayed = false
	decision.DecisionDigest = decisionDigest(decision)
	return decision
}

func auditUnavailable(decision Decision) Decision {
	return changeDecision(decision, "unavailable", "audit_unavailable")
}
