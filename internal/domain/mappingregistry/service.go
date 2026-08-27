package mappingregistry

import (
	"context"
	"errors"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/normalizedevent"
)

type Service struct{ dependencies Dependencies }

func NewService(dependencies Dependencies) (*Service, error) {
	if dependencies.Evidence == nil || dependencies.Signatures == nil || dependencies.SourceSchemas == nil ||
		dependencies.Store == nil || dependencies.Audit == nil || dependencies.Provenance == nil || dependencies.Clock == nil {
		return nil, newError(InvalidInput, DependencyUnavailableReason, nil)
	}
	return &Service{dependencies: dependencies}, nil
}

func (service *Service) Execute(ctx context.Context, command Command, input *normalizedevent.ValidatedEnvelope) (Receipt, error) {
	if service == nil {
		return Receipt{}, newError(InvalidInput, DependencyUnavailableReason, nil)
	}
	_, commandDigest, err := CanonicalCommand(ctx, command)
	if err != nil {
		return Receipt{}, err
	}
	if (command.Operation == Apply && input == nil) || (command.Operation != Apply && input != nil) {
		return Receipt{}, newError(InvalidInput, ManifestInvalid, nil)
	}
	existingDigest, begun, err := service.dependencies.Store.LoadCommandDigest(ctx, command.IdempotencyKey)
	if err != nil {
		return Receipt{}, dependencyError(err)
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
		if receipt, exists, loadErr := service.dependencies.Store.LoadReceipt(ctx, command.IdempotencyKey); loadErr != nil {
			return Receipt{}, dependencyError(loadErr)
		} else if exists {
			if err := service.validateReplay(ctx, receipt, commandDigest, command.IdempotencyKey); err != nil {
				return Receipt{}, err
			}
			return receipt, nil
		}
	}
	acquired, err := service.dependencies.Store.Begin(ctx, command, commandDigest)
	if err != nil {
		return Receipt{}, dependencyError(err)
	}
	if !acquired {
		if receipt, exists, loadErr := service.dependencies.Store.LoadReceipt(ctx, command.IdempotencyKey); loadErr != nil {
			return Receipt{}, dependencyError(loadErr)
		} else if exists {
			if err := service.validateReplay(ctx, receipt, commandDigest, command.IdempotencyKey); err == nil {
				return receipt, nil
			}
		}
		return Receipt{}, newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	deadline, _ := time.Parse(timestampLayout, command.Deadline)
	workContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := service.dependencies.Evidence.VerifyBinding(workContext, command.Case, command.SourceBinding); err != nil {
		return service.finishFailure(ctx, command, commandDigest, err)
	}
	if command.Operation == Apply {
		selected, err := resolveVerifiedMapping(workContext, service.dependencies, command)
		if err != nil {
			return service.finishFailure(ctx, command, commandDigest, err)
		}
		application, err := applyVerifiedMapping(workContext, command, selected, *input)
		if err != nil {
			return service.finishFailure(ctx, command, commandDigest, err)
		}
		outcome := appliedOutcome(command, commandDigest, selected.RegistryRevision, application, service.dependencies.Clock.Now())
		return service.persist(workContext, command, outcome, nil, nil, &application.Envelope)
	}
	mutation, err := executeRegistryMutation(workContext, service.dependencies, command)
	if err != nil {
		return service.finishFailure(ctx, command, commandDigest, err)
	}
	outcome := mutationOutcome(command, commandDigest, mutation, service.dependencies.Clock.Now())
	return service.persist(workContext, command, outcome, mutation.SignedMapping, mutation.Snapshot, nil)
}

func (service *Service) validateReplay(ctx context.Context, receipt Receipt, commandDigest, idempotencyKey string) error {
	if receipt.CommandDigest != commandDigest || receipt.IdempotencyKey != idempotencyKey {
		return newError(ConflictError, IdempotencyConflict, nil)
	}
	if _, _, err := CanonicalReceipt(ctx, receipt); err != nil {
		return newError(ConflictError, IdempotencyConflict, err)
	}
	outcome, exists, err := service.dependencies.Store.LoadOutcome(ctx, receipt.OutcomeDigest)
	if err != nil {
		return dependencyError(err)
	}
	if !exists || outcome.CommandDigest != commandDigest || outcome.OperationID != receipt.OperationID ||
		outcome.Status != receipt.Status || outcome.ReasonCode != receipt.ReasonCode {
		return newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	_, digest, err := CanonicalOutcome(ctx, outcome)
	if err != nil || digest != receipt.OutcomeDigest {
		return newError(ConflictError, IdempotencyConflict, err)
	}
	return nil
}

func (service *Service) finishFailure(parent context.Context, command Command, commandDigest string, cause error) (Receipt, error) {
	receipt, persistErr := service.persistTerminal(parent, command, commandDigest, cause)
	if persistErr != nil {
		return Receipt{}, persistErr
	}
	return receipt, normalizeDependencyError(cause)
}

func (service *Service) persistTerminal(parent context.Context, command Command, commandDigest string, cause error) (Receipt, error) {
	writeContext, cancel := context.WithTimeout(context.WithoutCancel(parent), time.Second)
	defer cancel()
	status, reason := terminalStatus(cause)
	outcome := Outcome{SchemaVersion: OutcomeSchemaVersion, ContractVersion: ContractVersion,
		OperationID: command.OperationID, CommandDigest: commandDigest, MappingDigest: command.MappingDigest,
		Status: status, ReasonCode: reason, Coverage: "none", AppliedRules: []string{}, UnmappedPaths: []string{},
		LossyPaths: []string{}, EntityHints: []EmittedEntityHint{}, ReverseResults: []ReverseResult{},
		CreatedAt: formatMappingTime(service.dependencies.Clock.Now())}
	return service.persist(writeContext, command, outcome, nil, nil, nil)
}

func (service *Service) persist(ctx context.Context, command Command, outcome Outcome, signed *SignedMapping,
	snapshot *RegistrySnapshot, envelope *normalizedevent.ValidatedEnvelope) (Receipt, error) {
	_, outcomeDigest, err := CanonicalOutcome(ctx, outcome)
	if err != nil {
		return Receipt{}, err
	}
	audit, err := service.dependencies.Audit.BuildAudit(ctx, command.OperationID, outcome.CommandDigest, outcome.Status, outcome.ReasonCode)
	if err != nil || audit.OperationID != command.OperationID || audit.CommandDigest != outcome.CommandDigest ||
		audit.Status != outcome.Status || audit.Reason != outcome.ReasonCode || !digestPattern.MatchString(audit.Digest) {
		return Receipt{}, dependencyError(err)
	}
	provenance, err := service.dependencies.Provenance.BuildProvenance(ctx, command.OperationID, outcome.CommandDigest, outcomeDigest)
	if err != nil || provenance.OperationID != command.OperationID || provenance.CommandDigest != outcome.CommandDigest ||
		provenance.OutcomeDigest != outcomeDigest || !digestPattern.MatchString(provenance.Digest) ||
		provenance.PreviousDigest != "" && !digestPattern.MatchString(provenance.PreviousDigest) {
		return Receipt{}, dependencyError(err)
	}
	now := formatMappingTime(service.dependencies.Clock.Now())
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		OperationID: command.OperationID, IdempotencyKey: command.IdempotencyKey, CommandDigest: outcome.CommandDigest,
		OutcomeDigest: outcomeDigest, Status: outcome.Status, ReasonCode: outcome.ReasonCode, AuditDigest: audit.Digest,
		ProvenanceDigest: provenance.Digest, CreatedAt: outcome.CreatedAt, UpdatedAt: now}
	if provenance.PreviousDigest != "" {
		receipt.PreviousProvenanceDigest = &provenance.PreviousDigest
	}
	if _, _, err := CanonicalReceipt(ctx, receipt); err != nil {
		return Receipt{}, err
	}
	commit := Commit{Command: command, SignedMapping: signed, Snapshot: snapshot, NormalizedEnvelope: envelope,
		Outcome: outcome, Receipt: receipt, Audit: audit, Provenance: provenance}
	if err := service.dependencies.Store.Commit(ctx, commit); err != nil {
		return Receipt{}, dependencyError(err)
	}
	return receipt, nil
}

func appliedOutcome(command Command, commandDigest string, revision uint64, application applicationResult, now time.Time) Outcome {
	digest := application.Envelope.Digest()
	return Outcome{SchemaVersion: OutcomeSchemaVersion, ContractVersion: ContractVersion,
		OperationID: command.OperationID, CommandDigest: commandDigest, MappingDigest: command.MappingDigest,
		RegistryRevision: revision, Status: Applied, ReasonCode: AppliedReason, NormalizedEnvelopeDigest: &digest,
		Coverage: application.Coverage, AppliedRules: append([]string{}, application.AppliedRules...),
		UnmappedPaths: append([]string{}, application.UnmappedPaths...), LossyPaths: append([]string{}, application.LossyPaths...),
		EntityHints: append([]EmittedEntityHint{}, application.EntityHints...), ReverseResults: append([]ReverseResult{}, application.ReverseResults...),
		CreatedAt: formatMappingTime(now)}
}

func mutationOutcome(command Command, commandDigest string, mutation registryMutation, now time.Time) Outcome {
	return Outcome{SchemaVersion: OutcomeSchemaVersion, ContractVersion: ContractVersion,
		OperationID: command.OperationID, CommandDigest: commandDigest, MappingDigest: command.MappingDigest,
		RegistryRevision: mutation.Revision, Status: mutation.Status, ReasonCode: mutation.Reason, Coverage: "none",
		AppliedRules: []string{}, UnmappedPaths: []string{}, LossyPaths: []string{}, EntityHints: []EmittedEntityHint{}, ReverseResults: []ReverseResult{},
		CreatedAt: formatMappingTime(now)}
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

func dependencyError(err error) error {
	if err == nil {
		return newError(UnavailableError, DependencyUnavailableReason, nil)
	}
	return normalizeDependencyError(err)
}
