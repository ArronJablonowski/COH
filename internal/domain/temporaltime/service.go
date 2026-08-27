package temporaltime

import (
	"context"
	"errors"
	"time"
)

type Service struct{ dependencies Dependencies }

func NewService(dependencies Dependencies) (*Service, error) {
	if dependencies.Evidence == nil || dependencies.Parsers == nil || dependencies.Timezones == nil || dependencies.Calibrations == nil ||
		dependencies.Store == nil || dependencies.Audit == nil || dependencies.Provenance == nil || dependencies.Clock == nil {
		return nil, newError(InvalidInput, DependencyUnavailableReason, nil)
	}
	return &Service{dependencies: dependencies}, nil
}

// Normalize executes one durable idempotent normalization. Exact replay
// returns the original receipt. A changed command under the same key is
// durably denied without replacing the original receipt.
func (service *Service) Normalize(ctx context.Context, command Command) (Receipt, error) {
	if service == nil {
		return Receipt{}, newError(InvalidInput, DependencyUnavailableReason, nil)
	}
	_, commandDigest, err := CanonicalCommand(ctx, command)
	if err != nil {
		return Receipt{}, err
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
			if !validReplayReceipt(ctx, receipt, commandDigest, command.IdempotencyKey) {
				return Receipt{}, newError(ConflictError, IdempotencyConflict, nil)
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
		} else if exists && validReplayReceipt(ctx, receipt, commandDigest, command.IdempotencyKey) {
			return receipt, nil
		}
		return Receipt{}, newError(Unavailable, DependencyUnavailableReason, nil)
	}
	deadline, _ := time.Parse(timestampLayout, command.Deadline)
	workContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	if err := service.dependencies.Evidence.VerifyBinding(workContext, command.Case, command.SourceBinding); err != nil {
		return service.finishFailure(ctx, command, commandDigest, err)
	}
	parser, err := service.dependencies.Parsers.ResolveParser(workContext, command.Parser)
	if err != nil {
		return service.finishFailure(ctx, command, commandDigest, err)
	}
	civil, err := parser.Parse(workContext, command.OriginalTime.Text, command.OriginalTime.Format, command.OriginalTime.Precision)
	if err != nil {
		return service.finishFailure(ctx, command, commandDigest, err)
	}
	resolution, err := service.dependencies.Timezones.ResolveCivil(workContext, civil, command.Timezone)
	if err != nil {
		return service.finishFailure(ctx, command, commandDigest, err)
	}
	calibration, err := service.dependencies.Calibrations.ResolveCalibration(workContext, command.Case, command.Calibration)
	if err != nil {
		return service.finishFailure(ctx, command, commandDigest, err)
	}
	record, err := BuildRecord(workContext, command, civil, resolution, calibration, service.dependencies.Clock.Now())
	if err != nil {
		return service.finishFailure(ctx, command, commandDigest, err)
	}
	receipt, err := service.persist(workContext, command, commandDigest, record)
	if err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func validReplayReceipt(ctx context.Context, receipt Receipt, commandDigest, idempotencyKey string) bool {
	if receipt.CommandDigest != commandDigest || receipt.IdempotencyKey != idempotencyKey {
		return false
	}
	_, _, err := CanonicalReceipt(ctx, receipt)
	return err == nil
}

func (service *Service) CompareAndPersist(ctx context.Context, comparisonID string, left, right Record) (Comparison, error) {
	if service == nil {
		return Comparison{}, newError(InvalidInput, DependencyUnavailableReason, nil)
	}
	comparison, err := CompareRecords(ctx, comparisonID, left, right, service.dependencies.Clock.Now())
	if err != nil {
		return Comparison{}, err
	}
	_, digest, err := CanonicalComparison(ctx, comparison)
	if err != nil {
		return Comparison{}, err
	}
	auditDigest, err := service.dependencies.Audit.BuildComparisonAudit(ctx, comparison)
	if err != nil || !digestPattern.MatchString(auditDigest) {
		return Comparison{}, dependencyError(err)
	}
	previous, provenance, err := service.dependencies.Provenance.BuildComparisonProvenance(ctx, comparison, digest)
	if err != nil || previous != "" && !digestPattern.MatchString(previous) || !digestPattern.MatchString(provenance) {
		return Comparison{}, dependencyError(err)
	}
	commit := ComparisonCommit{Comparison: comparison, ComparisonDigest: digest, AuditDigest: auditDigest, PreviousProvenanceDigest: previous, ProvenanceDigest: provenance}
	if err := service.dependencies.Store.CommitComparison(ctx, commit); err != nil {
		return Comparison{}, dependencyError(err)
	}
	return comparison, nil
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
	outcome, reason := terminalOutcome(cause)
	record := baseRecord(command, commandDigest, command.Calibration, service.dependencies.Clock.Now())
	record.Outcome, record.ReasonCode = outcome, reason
	return service.persist(writeContext, command, commandDigest, record)
}

func (service *Service) persist(ctx context.Context, command Command, commandDigest string, record Record) (Receipt, error) {
	_, recordDigest, err := CanonicalRecord(ctx, record)
	if err != nil {
		return Receipt{}, err
	}
	audit, err := service.dependencies.Audit.BuildAudit(ctx, command.OperationID, commandDigest, record.Outcome, record.ReasonCode)
	if err != nil || audit.OperationID != command.OperationID || audit.CommandDigest != commandDigest || audit.Outcome != record.Outcome ||
		audit.ReasonCode != record.ReasonCode || !digestPattern.MatchString(audit.Digest) {
		return Receipt{}, dependencyError(err)
	}
	provenance, err := service.dependencies.Provenance.BuildProvenance(ctx, command.OperationID, commandDigest, recordDigest)
	if err != nil || provenance.OperationID != command.OperationID || provenance.CommandDigest != commandDigest || provenance.RecordDigest != recordDigest ||
		!digestPattern.MatchString(provenance.Digest) || provenance.PreviousDigest != "" && !digestPattern.MatchString(provenance.PreviousDigest) {
		return Receipt{}, dependencyError(err)
	}
	now := formatTime(service.dependencies.Clock.Now())
	reference := RecordRef{RecordID: record.RecordID, RecordDigest: recordDigest, DeduplicationDigest: record.SourceBinding.DeduplicationDigest}
	receipt := Receipt{
		SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion, OperationID: command.OperationID,
		IdempotencyKey: command.IdempotencyKey, CommandDigest: commandDigest, Record: &reference,
		Outcome: record.Outcome, ReasonCode: record.ReasonCode, AuditDigest: audit.Digest,
		ProvenanceDigest: provenance.Digest, CreatedAt: record.CreatedAt, UpdatedAt: now,
	}
	if provenance.PreviousDigest != "" {
		receipt.PreviousProvenanceDigest = &provenance.PreviousDigest
	}
	if _, _, err := CanonicalReceipt(ctx, receipt); err != nil {
		return Receipt{}, err
	}
	if err := service.dependencies.Store.Commit(ctx, Commit{Command: command, Record: record, Receipt: receipt, Audit: audit, Provenance: provenance}); err != nil {
		return Receipt{}, dependencyError(err)
	}
	return receipt, nil
}

func terminalOutcome(err error) (Outcome, Reason) {
	if errors.Is(err, context.Canceled) {
		return CanceledOutcome, ContextCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return TimeoutOutcome, ContextDeadline
	}
	reason := ErrorReason(err)
	switch Code(err) {
	case Canceled:
		return CanceledOutcome, ContextCanceled
	case Timeout:
		return TimeoutOutcome, ContextDeadline
	case Unavailable:
		return DependencyUnavailable, DependencyUnavailableReason
	}
	if reason == TimezoneUnresolved || reason == TimezoneMismatch || reason == DSTGap || reason == PrecisionUnknown || reason == CalibrationUnresolved {
		return Unresolved, reason
	}
	if validOutcomeReason(Denied, reason) {
		return Denied, reason
	}
	return DependencyUnavailable, DependencyUnavailableReason
}

func normalizeDependencyError(err error) error {
	if Code(err) != "" {
		return err
	}
	if errors.Is(err, context.Canceled) {
		return newError(Canceled, ContextCanceled, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newError(Timeout, ContextDeadline, err)
	}
	return newError(Unavailable, DependencyUnavailableReason, err)
}

func dependencyError(err error) error {
	if err == nil {
		return newError(Unavailable, DependencyUnavailableReason, nil)
	}
	return normalizeDependencyError(err)
}
