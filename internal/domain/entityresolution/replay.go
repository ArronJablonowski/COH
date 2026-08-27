package entityresolution

import (
	"context"
	"slices"
)

func (service *Service) validateReplay(ctx context.Context, commit Commit, commandDigest, idempotencyKey string) error {
	fail := func(cause error) error { return newError(ConflictError, IdempotencyConflict, cause) }
	_, storedCommandDigest, err := CanonicalCommand(ctx, commit.Command)
	if err != nil || storedCommandDigest != commandDigest || commit.Command.IdempotencyKey != idempotencyKey {
		return fail(err)
	}
	receipt, outcome := commit.Receipt, commit.Outcome
	if _, _, err = CanonicalReceipt(ctx, receipt); err != nil || receipt.CommandDigest != commandDigest ||
		receipt.IdempotencyKey != idempotencyKey || receipt.OperationID != commit.Command.OperationID {
		return fail(err)
	}
	_, outcomeDigest, err := CanonicalOutcome(ctx, outcome)
	if err != nil || outcomeDigest != receipt.OutcomeDigest || outcome.CommandDigest != commandDigest ||
		outcome.OperationID != receipt.OperationID || outcome.Status != receipt.Status || outcome.ReasonCode != receipt.ReasonCode {
		return fail(err)
	}
	if !validReplayBindings(commit, outcomeDigest) {
		return fail(nil)
	}
	if !validReplayRelationships(commit) {
		return fail(nil)
	}
	if err := service.validateReplayCandidate(ctx, commit); err != nil {
		return fail(err)
	}
	if err := validateReplayPayload(ctx, commit); err != nil {
		return fail(err)
	}
	return nil
}

func validReplayRelationships(commit Commit) bool {
	command, outcome := commit.Command, commit.Outcome
	success := map[Operation]Status{Observe: Observed, Resolve: Resolved, Merge: Merged, Split: SplitStatus,
		Reject: Rejected, Reindex: Reindexed}
	if outcome.Status == success[command.Operation] {
		if command.Operation == Observe {
			return commit.Observation != nil && commit.Candidate != nil && commit.Decision == nil && commit.History == nil &&
				command.Observation != nil && sameCanonicalValue(*commit.Observation, *command.Observation) &&
				command.CandidateID != nil && commit.Candidate.CandidateID == *command.CandidateID &&
				commit.Candidate.OperationID == command.OperationID
		}
		if commit.Decision == nil || commit.History == nil || commit.Observation != nil {
			return false
		}
		decision, history := *commit.Decision, *commit.History
		if decision.OperationID != command.OperationID || decision.Operation != command.Operation || decision.Scope != command.Scope ||
			decision.ActorID != command.ActorID || decision.ActorRevision != command.ActorRevision || decision.CreatedAt != command.RequestedAt ||
			!sameCanonicalValue(decision.InputEntities, command.InputEntities) || !sameCanonicalValue(decision.Partitions, command.Partitions) ||
			!sameCanonicalValue(decision.SupportingEvidence, command.SupportingEvidence) ||
			!sameCanonicalValue(decision.Counterevidence, command.Counterevidence) || command.Confidence == nil ||
			!sameCanonicalValue(decision.Confidence, *command.Confidence) || history.Operation != command.Operation || history.Scope != command.Scope ||
			history.CreatedAt != command.RequestedAt || history.DecisionDigest != *outcome.DecisionDigest ||
			!sameCanonicalValue(history.InputEntities, decision.InputEntities) ||
			!sameCanonicalValue(history.OutputEntities, decision.OutputEntities) {
			return false
		}
		for _, output := range decision.OutputEntities {
			if !slices.Contains(outcome.Entities, output) {
				return false
			}
		}
		return command.Operation != Resolve || commit.Candidate == nil
	}
	return slices.Contains([]Status{Denied, Canceled, Timeout, DependencyUnavailable}, outcome.Status) &&
		commit.Observation == nil && commit.Candidate == nil && commit.Decision == nil && commit.History == nil && len(commit.Entities) == 0
}

func validReplayBindings(commit Commit, outcomeDigest string) bool {
	receipt, audit, provenance := commit.Receipt, commit.Audit, commit.Provenance
	if audit.OperationID != commit.Command.OperationID || audit.CommandDigest != receipt.CommandDigest ||
		audit.Status != receipt.Status || audit.Reason != receipt.ReasonCode || audit.Digest != receipt.AuditDigest ||
		!digestPattern.MatchString(audit.Digest) || provenance.OperationID != commit.Command.OperationID ||
		provenance.CommandDigest != receipt.CommandDigest || provenance.OutcomeDigest != outcomeDigest ||
		provenance.Digest != receipt.ProvenanceDigest || !digestPattern.MatchString(provenance.Digest) ||
		provenance.PreviousDigest != "" && !digestPattern.MatchString(provenance.PreviousDigest) {
		return false
	}
	if provenance.PreviousDigest == "" {
		return receipt.PreviousProvenanceDigest == nil
	}
	return receipt.PreviousProvenanceDigest != nil && *receipt.PreviousProvenanceDigest == provenance.PreviousDigest
}

func validateReplayPayload(ctx context.Context, commit Commit) error {
	outcome := commit.Outcome
	if commit.Entities == nil {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	if err := replayObservation(ctx, commit.Observation, outcome.ObservationDigest); err != nil {
		return err
	}
	if err := replayDecision(ctx, commit.Decision, outcome.DecisionDigest); err != nil {
		return err
	}
	if err := replayHistory(ctx, commit.History, outcome.HistoryDigest); err != nil {
		return err
	}
	if (commit.Decision == nil) != (commit.History == nil) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	references := make([]EntityRef, 0, len(commit.Entities))
	for _, entity := range commit.Entities {
		_, digest, err := EntityRecordDigest(ctx, entity)
		if err != nil {
			return err
		}
		reference := EntityRef{EntityID: entity.EntityID, Revision: entity.Revision, RecordDigest: digest}
		if entity.AuditDigest != commit.Audit.Digest || entity.ProvenanceDigest != commit.Provenance.Digest ||
			ValidateEntityRevision(ctx, entity, reference) != nil {
			return newError(InvalidInputError, TransitionInvalid, nil)
		}
		references = append(references, reference)
	}
	slices.SortFunc(references, compareEntityRef)
	if !slices.Equal(references, outcome.Entities) {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	return nil
}

func replayObservation(ctx context.Context, value *Observation, expected *string) error {
	if value == nil || expected == nil {
		if value == nil && expected == nil {
			return nil
		}
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	_, digest, err := CanonicalObservation(ctx, *value)
	if err != nil || digest != *expected {
		return newError(InvalidInputError, TransitionInvalid, err)
	}
	return nil
}

func replayCandidate(ctx context.Context, value *Candidate, expected *string) error {
	if value == nil || expected == nil {
		if value == nil && expected == nil {
			return nil
		}
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	_, digest, err := CanonicalCandidate(ctx, *value)
	if err != nil || digest != *expected {
		return newError(InvalidInputError, TransitionInvalid, err)
	}
	return nil
}

func (service *Service) validateReplayCandidate(ctx context.Context, commit Commit) error {
	if commit.Candidate != nil || commit.Outcome.CandidateDigest == nil {
		return replayCandidate(ctx, commit.Candidate, commit.Outcome.CandidateDigest)
	}
	if commit.Outcome.Status != Resolved {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	candidate, found, err := service.dependencies.Candidates.LoadCandidate(ctx, commit.Command.Scope, *commit.Outcome.CandidateDigest)
	if err = dependencyError(ctx, err); err != nil {
		return err
	}
	if !found {
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	return replayCandidate(ctx, &candidate, commit.Outcome.CandidateDigest)
}

func replayDecision(ctx context.Context, value *Decision, expected *string) error {
	if value == nil || expected == nil {
		if value == nil && expected == nil {
			return nil
		}
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	_, digest, err := CanonicalDecision(ctx, *value)
	if err != nil || digest != *expected {
		return newError(InvalidInputError, TransitionInvalid, err)
	}
	return nil
}

func replayHistory(ctx context.Context, value *History, expected *string) error {
	if value == nil || expected == nil {
		if value == nil && expected == nil {
			return nil
		}
		return newError(InvalidInputError, TransitionInvalid, nil)
	}
	_, digest, err := CanonicalHistory(ctx, *value)
	if err != nil || digest != *expected {
		return newError(InvalidInputError, TransitionInvalid, err)
	}
	return nil
}
