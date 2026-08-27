package entityresolution

import (
	"context"
	"errors"
	"slices"
	"time"
)

type Service struct{ dependencies Dependencies }

func NewService(dependencies Dependencies) (*Service, error) {
	if nilDependency(dependencies.Evidence) || nilDependency(dependencies.Matches) || nilDependency(dependencies.Authorization) ||
		nilDependency(dependencies.Observations) || nilDependency(dependencies.Entities) || nilDependency(dependencies.Candidates) ||
		nilDependency(dependencies.Durable) || nilDependency(dependencies.Audit) || nilDependency(dependencies.Provenance) ||
		nilDependency(dependencies.Clock) {
		return nil, newError(InvalidInputError, DependencyUnavailableReason, nil)
	}
	return &Service{dependencies: dependencies}, nil
}

func (service *Service) Execute(ctx context.Context, command Command) (Receipt, error) {
	if service == nil {
		return Receipt{}, newError(InvalidInputError, DependencyUnavailableReason, nil)
	}
	_, commandDigest, err := CanonicalCommand(ctx, command)
	if err != nil {
		return Receipt{}, err
	}
	existingDigest, begun, err := service.dependencies.Durable.LoadCommandDigest(ctx, command.IdempotencyKey)
	if err != nil {
		return Receipt{}, dependencyError(ctx, err)
	}
	if begun && existingDigest != commandDigest {
		conflict := newError(ConflictError, IdempotencyConflict, nil)
		receipt, persistErr := service.persistTerminal(ctx, command, commandDigest, conflict)
		if persistErr != nil {
			return Receipt{}, persistErr
		}
		return receipt, conflict
	}
	if begun {
		if commit, exists, loadErr := service.dependencies.Durable.LoadCommit(ctx, command.IdempotencyKey); loadErr != nil {
			return Receipt{}, dependencyError(ctx, loadErr)
		} else if exists {
			if err := service.validateReplay(ctx, commit, commandDigest, command.IdempotencyKey); err != nil {
				return Receipt{}, err
			}
			return commit.Receipt, nil
		}
	}
	acquired, err := service.dependencies.Durable.Begin(ctx, command, commandDigest)
	if err != nil {
		return Receipt{}, dependencyError(ctx, err)
	}
	if !acquired {
		if commit, exists, loadErr := service.dependencies.Durable.LoadCommit(ctx, command.IdempotencyKey); loadErr != nil {
			return Receipt{}, dependencyError(ctx, loadErr)
		} else if exists && service.validateReplay(ctx, commit, commandDigest, command.IdempotencyKey) == nil {
			return commit.Receipt, nil
		}
		return Receipt{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	deadline, _ := time.Parse(timestampLayout, command.Deadline)
	workContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	receipt, err := service.executeBegun(workContext, command, commandDigest)
	if err != nil {
		var commitErr *commitResponseError
		if errors.As(err, &commitErr) {
			return Receipt{}, commitErr.err
		}
		return service.finishFailure(ctx, command, commandDigest, err)
	}
	return receipt, nil
}

func (service *Service) executeBegun(ctx context.Context, command Command, commandDigest string) (Receipt, error) {
	switch command.Operation {
	case Observe:
		return service.executeObserve(ctx, command, commandDigest)
	case Resolve:
		return service.executeResolve(ctx, command, commandDigest)
	case Merge:
		return service.executeMerge(ctx, command, commandDigest)
	case Split:
		return service.executeSplit(ctx, command, commandDigest)
	default:
		return Receipt{}, newError(InvalidInputError, InvalidInput, nil)
	}
}

func (service *Service) executeObserve(ctx context.Context, command Command, commandDigest string) (Receipt, error) {
	_, observationDigest, err := CanonicalObservation(ctx, *command.Observation)
	if err != nil {
		return Receipt{}, err
	}
	lookup, err := LookupCandidate(ctx, service.dependencies,
		CandidateLookupRequest{Observation: *command.Observation, ObservationDigest: observationDigest})
	if err != nil {
		return Receipt{}, err
	}
	confidence, err := composeDeclaredConfidence(ctx, service.dependencies, command.Scope, command.Observation,
		command.ConfidenceAssessments, command.Counterevidence, uint32(len(lookup.MatchingEntities)), *command.Confidence)
	if err != nil {
		return Receipt{}, err
	}
	candidate, _, candidateDigest, err := BuildCandidate(ctx, *command.CandidateID, command.OperationID, lookup, confidence, command.RequestedAt)
	if err != nil {
		return Receipt{}, err
	}
	outcome := Outcome{SchemaVersion: OutcomeSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		OperationID: command.OperationID, CommandDigest: commandDigest, Status: Observed, ReasonCode: ObservedReason,
		ObservationDigest: &observationDigest, CandidateDigest: &candidateDigest, Entities: []EntityRef{}, CreatedAt: command.RequestedAt}
	return service.persist(ctx, command, outcome, command.Observation, &candidate, nil)
}

func (service *Service) executeResolve(ctx context.Context, command Command, commandDigest string) (Receipt, error) {
	candidate, found, err := service.dependencies.Candidates.LoadCandidate(ctx, command.Scope, *command.CandidateDigest)
	if err != nil {
		return Receipt{}, dependencyError(ctx, err)
	}
	if !found || candidate.Scope != command.Scope {
		return Receipt{}, newError(DeniedError, EvidenceBindingMismatch, nil)
	}
	_, candidateDigest, err := CanonicalCandidate(ctx, candidate)
	if err != nil || candidateDigest != *command.CandidateDigest {
		return Receipt{}, newError(DeniedError, EvidenceBindingMismatch, err)
	}
	confidence, err := composeDeclaredConfidence(ctx, service.dependencies, command.Scope, nil, command.ConfidenceAssessments,
		command.Counterevidence, uint32(len(candidate.MatchingEntities)), *command.Confidence)
	if err != nil || !sameCanonicalValue(confidence, candidate.Confidence) {
		return Receipt{}, newError(InvalidInputError, ConfidenceInvalid, err)
	}
	plan, err := planResolve(ctx, service.dependencies, command, candidate)
	if err != nil {
		return Receipt{}, err
	}
	entities := transitionReferences(plan)
	decisionDigest, historyDigest := plan.DecisionDigest, plan.HistoryDigest
	outcome := Outcome{SchemaVersion: OutcomeSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		OperationID: command.OperationID, CommandDigest: commandDigest, Status: Resolved, ReasonCode: ResolvedReason,
		CandidateDigest: command.CandidateDigest, DecisionDigest: &decisionDigest, HistoryDigest: &historyDigest,
		Entities: entities, CreatedAt: command.RequestedAt}
	return service.persist(ctx, command, outcome, nil, nil, &plan)
}

func (service *Service) executeMerge(ctx context.Context, command Command, commandDigest string) (Receipt, error) {
	if _, err := composeDeclaredConfidence(ctx, service.dependencies, command.Scope, nil, command.ConfidenceAssessments,
		command.Counterevidence, 0, *command.Confidence); err != nil {
		return Receipt{}, err
	}
	metadata := transitionMetadataFromCommand(command, commandDigest)
	plan, err := PlanMerge(ctx, service.dependencies, MergeRequest{Metadata: metadata,
		InputEntities: command.InputEntities, OutputEntityID: *command.OutputEntityID})
	if err != nil {
		return Receipt{}, err
	}
	decisionDigest, historyDigest := plan.DecisionDigest, plan.HistoryDigest
	outcome := Outcome{SchemaVersion: OutcomeSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		OperationID: command.OperationID, CommandDigest: commandDigest, Status: Merged, ReasonCode: MergedReason,
		DecisionDigest: &decisionDigest, HistoryDigest: &historyDigest, Entities: transitionReferences(plan), CreatedAt: command.RequestedAt}
	return service.persist(ctx, command, outcome, nil, nil, &plan)
}

func (service *Service) executeSplit(ctx context.Context, command Command, commandDigest string) (Receipt, error) {
	if _, err := composeDeclaredConfidence(ctx, service.dependencies, command.Scope, nil, command.ConfidenceAssessments,
		command.Counterevidence, 0, *command.Confidence); err != nil {
		return Receipt{}, err
	}
	partitions := make([]SplitPartitionRequest, 0, len(command.Partitions))
	for _, partition := range command.Partitions {
		if _, err := composeDeclaredConfidence(ctx, service.dependencies, command.Scope, nil, partition.ConfidenceAssessments,
			partition.Confidence.Counterevidence, 0, partition.Confidence); err != nil {
			return Receipt{}, err
		}
		partitions = append(partitions, SplitPartitionRequest{PartitionID: partition.PartitionID,
			OutputEntityID: partition.OutputEntityID, MemberObservations: cloneSlice(partition.MemberObservations),
			AliasProofDigests: cloneSlice(partition.AliasProofDigests), Confidence: partition.Confidence,
			ConfidenceAssessments: cloneSlice(partition.ConfidenceAssessments)})
	}
	metadata := transitionMetadataFromCommand(command, commandDigest)
	plan, err := PlanSplit(ctx, service.dependencies, SplitRequest{Metadata: metadata, InputEntity: command.InputEntities[0], Partitions: partitions})
	if err != nil {
		return Receipt{}, err
	}
	decisionDigest, historyDigest := plan.DecisionDigest, plan.HistoryDigest
	outcome := Outcome{SchemaVersion: OutcomeSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		OperationID: command.OperationID, CommandDigest: commandDigest, Status: SplitStatus, ReasonCode: SplitReason,
		DecisionDigest: &decisionDigest, HistoryDigest: &historyDigest, Entities: transitionReferences(plan), CreatedAt: command.RequestedAt}
	return service.persist(ctx, command, outcome, nil, nil, &plan)
}

func transitionReferences(plan TransitionPlan) []EntityRef {
	result := make([]EntityRef, 0, len(plan.Outputs)+len(plan.Superseded))
	for _, draft := range append(append([]EntityRevisionDraft(nil), plan.Outputs...), plan.Superseded...) {
		result = append(result, draft.Reference)
	}
	slices.SortFunc(result, compareEntityRef)
	return result
}

func (service *Service) finishFailure(parent context.Context, command Command, commandDigest string, cause error) (Receipt, error) {
	receipt, persistErr := service.persistTerminal(parent, command, commandDigest, cause)
	if persistErr != nil {
		return Receipt{}, persistErr
	}
	return receipt, normalizeServiceError(cause)
}

func (service *Service) persistTerminal(parent context.Context, command Command, commandDigest string, cause error) (Receipt, error) {
	writeContext, cancel := context.WithTimeout(context.WithoutCancel(parent), time.Second)
	defer cancel()
	status, reason := terminalStatus(cause)
	outcome := Outcome{SchemaVersion: OutcomeSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		OperationID: command.OperationID, CommandDigest: commandDigest, Status: status, ReasonCode: reason,
		Entities: []EntityRef{}, CreatedAt: formatEntityTime(service.dependencies.Clock.Now())}
	return service.persist(writeContext, command, outcome, nil, nil, nil)
}

func terminalStatus(err error) (Status, Reason) {
	if errors.Is(err, context.Canceled) || Code(err) == CanceledError {
		return Canceled, ContextCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) || Code(err) == TimeoutError {
		return Timeout, ContextDeadline
	}
	if Code(err) == UnavailableError {
		return DependencyUnavailable, DependencyUnavailableReason
	}
	reason := ErrorReason(err)
	if validStatusReason(Denied, reason) {
		return Denied, reason
	}
	return DependencyUnavailable, DependencyUnavailableReason
}

func normalizeServiceError(err error) error {
	if Code(err) != "" {
		return err
	}
	if errors.Is(err, context.Canceled) {
		return newError(CanceledError, ContextCanceled, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newError(TimeoutError, ContextDeadline, err)
	}
	return newError(UnavailableError, DependencyUnavailableReason, err)
}

func formatEntityTime(value time.Time) string { return value.UTC().Format(timestampLayout) }
