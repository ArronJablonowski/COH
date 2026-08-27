package entityresolution

import "context"

type commitResponseError struct{ err error }

func (value *commitResponseError) Error() string { return value.err.Error() }
func (value *commitResponseError) Unwrap() error { return value.err }

func (service *Service) persist(ctx context.Context, command Command, outcome Outcome, observation *Observation,
	candidate *Candidate, plan *TransitionPlan) (Receipt, error) {
	_, outcomeDigest, err := CanonicalOutcome(ctx, outcome)
	if err != nil {
		return Receipt{}, err
	}
	audit, err := service.dependencies.Audit.BuildAudit(ctx, command.OperationID, outcome.CommandDigest, outcome.Status, outcome.ReasonCode)
	if err != nil {
		return Receipt{}, dependencyError(ctx, err)
	}
	if audit.OperationID != command.OperationID || audit.CommandDigest != outcome.CommandDigest || audit.Status != outcome.Status ||
		audit.Reason != outcome.ReasonCode || !digestPattern.MatchString(audit.Digest) {
		return Receipt{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	provenance, err := service.dependencies.Provenance.BuildProvenance(ctx, command.OperationID, outcome.CommandDigest, outcomeDigest)
	if err != nil {
		return Receipt{}, dependencyError(ctx, err)
	}
	if provenance.OperationID != command.OperationID || provenance.CommandDigest != outcome.CommandDigest ||
		provenance.OutcomeDigest != outcomeDigest || !digestPattern.MatchString(provenance.Digest) ||
		provenance.PreviousDigest != "" && !digestPattern.MatchString(provenance.PreviousDigest) {
		return Receipt{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	entities, decision, history, err := materializeTransition(ctx, plan, audit.Digest, provenance.Digest)
	if err != nil {
		return Receipt{}, err
	}
	if observation != nil {
		if _, _, err := CanonicalObservation(ctx, *observation); err != nil {
			return Receipt{}, err
		}
	}
	if candidate != nil {
		if _, _, err := CanonicalCandidate(ctx, *candidate); err != nil {
			return Receipt{}, err
		}
	}
	updatedAt := formatEntityTime(service.dependencies.Clock.Now())
	if updatedAt < outcome.CreatedAt {
		updatedAt = outcome.CreatedAt
	}
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		OperationID: command.OperationID, IdempotencyKey: command.IdempotencyKey, CommandDigest: outcome.CommandDigest,
		OutcomeDigest: outcomeDigest, Status: outcome.Status, ReasonCode: outcome.ReasonCode, AuditDigest: audit.Digest,
		ProvenanceDigest: provenance.Digest, CreatedAt: outcome.CreatedAt, UpdatedAt: updatedAt}
	if provenance.PreviousDigest != "" {
		receipt.PreviousProvenanceDigest = &provenance.PreviousDigest
	}
	if _, _, err := CanonicalReceipt(ctx, receipt); err != nil {
		return Receipt{}, err
	}
	commit := Commit{Command: command, Observation: observation, Candidate: candidate, Decision: decision, History: history,
		Entities: entities, Outcome: outcome, Receipt: receipt, Audit: audit, Provenance: provenance}
	if err := service.dependencies.Durable.Commit(ctx, commit); err != nil {
		return Receipt{}, &commitResponseError{err: dependencyError(ctx, err)}
	}
	return receipt, nil
}

func materializeTransition(ctx context.Context, plan *TransitionPlan, auditDigest, provenanceDigest string) ([]Entity, *Decision, *History, error) {
	if plan == nil {
		return []Entity{}, nil, nil, nil
	}
	decisionCanonical, decisionDigest, err := CanonicalDecision(ctx, plan.Decision)
	if err != nil || decisionDigest != plan.DecisionDigest || !sameBytes(decisionCanonical, plan.DecisionCanonical) {
		return nil, nil, nil, newError(InvalidInputError, TransitionInvalid, err)
	}
	historyCanonical, historyDigest, err := CanonicalHistory(ctx, plan.History)
	if err != nil || historyDigest != plan.HistoryDigest || !sameBytes(historyCanonical, plan.HistoryCanonical) ||
		plan.History.DecisionDigest != plan.DecisionDigest {
		return nil, nil, nil, newError(InvalidInputError, TransitionInvalid, err)
	}
	drafts := append(append([]EntityRevisionDraft(nil), plan.Outputs...), plan.Superseded...)
	entities := make([]Entity, 0, len(drafts))
	for _, draft := range drafts {
		entity := draft.Entity
		entity.AuditDigest = auditDigest
		entity.ProvenanceDigest = provenanceDigest
		if err := ValidateEntityRevision(ctx, entity, draft.Reference); err != nil {
			return nil, nil, nil, err
		}
		entities = append(entities, entity)
	}
	decision, history := plan.Decision, plan.History
	return entities, &decision, &history, nil
}

func sameBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
