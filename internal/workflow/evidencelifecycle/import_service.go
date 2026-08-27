package evidencelifecycle

import (
	"context"
	"time"
)

type ImportService struct {
	authority Authority
	cases     CaseStore
	custody   Custody
	reader    PackageReader
	publisher Publisher
	store     Store
	auditor   Auditor
	clock     Clock
}

func NewImportService(authority Authority, cases CaseStore, custody Custody, reader PackageReader,
	publisher Publisher, store Store, auditor Auditor, clock Clock) (*ImportService, error) {
	if authority == nil || cases == nil || custody == nil || reader == nil || publisher == nil || store == nil ||
		auditor == nil || clock == nil {
		return nil, newError(InvalidInput, "import_dependencies_invalid", false, nil)
	}
	return &ImportService{authority, cases, custody, reader, publisher, store, auditor, clock}, nil
}

func (service *ImportService) Execute(ctx context.Context, command Command, inputReference string) (Result, error) {
	result, err := service.execute(ctx, command, inputReference)
	if err == nil {
		return result, nil
	}
	if auditErr := service.auditImportDenial(ctx, command, err); auditErr != nil {
		return Result{}, auditErr
	}
	return Result{}, err
}

func (service *ImportService) execute(ctx context.Context, command Command, inputReference string) (Result, error) {
	if ctx == nil || !validOpaque(inputReference, 1, 256) {
		return Result{}, newError(InvalidInput, "import_input_invalid", false, nil)
	}
	now := service.clock.Now()
	if command.Operation != Import || ValidateCommand(command, now) != nil {
		return Result{}, newError(InvalidInput, "import_command_invalid", false, nil)
	}
	opCtx, cancel := operationContext(ctx, command.Deadline)
	defer cancel()
	if err := operationContextError(opCtx); err != nil {
		return Result{}, err
	}
	intent, err := IntentBindingDigest(command)
	if err != nil {
		return Result{}, err
	}
	idempotency, err := IdempotencyBindingDigest(command.IdempotencyKey)
	if err != nil {
		return Result{}, err
	}
	if receipt, found, recoverErr := service.store.Recover(opCtx, command.Case, idempotency); recoverErr != nil {
		return Result{}, mapExportDependency(opCtx, "import_recovery_unavailable", recoverErr)
	} else if found {
		return service.recoverCompletedImport(opCtx, command, inputReference, intent, idempotency, receipt)
	}
	verified, err := service.reader.VerifyImport(opCtx, ImportRequest{Reference: inputReference,
		SourceDigest: *command.SourceDigest, PackageDigest: *command.PackageDigest,
		Limits: command.Limits, Deadline: command.Deadline})
	if err != nil {
		return Result{}, mapExportDependency(opCtx, "import_verification_unavailable", err)
	}
	if !validVerifiedImport(verified, command, inputReference) {
		return Result{}, newError(Denied, "import_verification_invalid", false, nil)
	}
	progress, err := service.restoreOrPlanImport(opCtx, command, intent, idempotency, verified)
	if err != nil {
		return Result{}, err
	}
	state, err := service.authorizeImport(opCtx, command, intent, verified, progress.Phase != Verified)
	if err != nil {
		return Result{}, err
	}
	progress, state, err = service.authorizeOrResumeImport(opCtx, state, progress)
	if err != nil {
		return Result{}, err
	}
	published, progress, err := service.publishOrRecoverImport(opCtx, state, progress)
	if err != nil {
		return Result{}, err
	}
	custody, progress, err := service.custodyOrRecoverImport(opCtx, state, published, progress)
	if err != nil {
		return Result{}, err
	}
	return service.commitImport(ctx, opCtx, state, idempotency, published, custody, progress)
}

type importState struct {
	Command               Command
	IntentDigest          string
	Case                  CaseSnapshot
	Verified              VerifiedImport
	Decision              Decision
	FinalDecisionDigest   string
	FinalRevocationDigest string
	AuthorizedAt          time.Time
}
