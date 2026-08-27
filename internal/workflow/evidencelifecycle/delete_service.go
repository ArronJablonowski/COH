package evidencelifecycle

import (
	"context"
	"time"
)

type DeleteService struct {
	authority Authority
	cases     CaseStore
	lifecycle CaseLifecycle
	evidence  EvidenceResolver
	custody   Custody
	disposer  Disposer
	store     Store
	auditor   Auditor
	clock     Clock
}

func NewDeleteService(authority Authority, cases CaseStore, lifecycle CaseLifecycle, evidence EvidenceResolver,
	custody Custody, disposer Disposer, store Store, auditor Auditor, clock Clock) (*DeleteService, error) {
	if authority == nil || cases == nil || lifecycle == nil || evidence == nil || custody == nil ||
		disposer == nil || store == nil || auditor == nil || clock == nil {
		return nil, newError(InvalidInput, "delete_dependencies_invalid", false, nil)
	}
	return &DeleteService{authority, cases, lifecycle, evidence, custody, disposer, store, auditor, clock}, nil
}

func (service *DeleteService) Execute(ctx context.Context, command Command) (Result, error) {
	result, err := service.execute(ctx, command)
	if err == nil {
		return result, nil
	}
	if auditErr := service.auditDeleteDenial(ctx, command, err); auditErr != nil {
		return Result{}, auditErr
	}
	return Result{}, err
}

func (service *DeleteService) execute(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || command.Operation != Delete || ValidateCommand(command, service.clock.Now()) != nil {
		return Result{}, newError(InvalidInput, "delete_command_invalid", false, nil)
	}
	opCtx, cancel := operationContext(ctx, command.Deadline)
	defer cancel()
	intent, err := IntentBindingDigest(command)
	if err != nil {
		return Result{}, err
	}
	idempotency, err := IdempotencyBindingDigest(command.IdempotencyKey)
	if err != nil {
		return Result{}, err
	}
	if receipt, found, recoverErr := service.store.Recover(opCtx, command.Case, idempotency); recoverErr != nil {
		return Result{}, mapExportDependency(opCtx, "delete_recovery_unavailable", recoverErr)
	} else if found {
		return service.recoverCompletedDelete(opCtx, command, intent, idempotency, receipt)
	}
	progress, found, err := service.loadDeleteProgress(opCtx, command, intent, idempotency)
	if err != nil {
		return Result{}, err
	}
	state, err := service.authorizeDelete(opCtx, command, intent, progress, found)
	if err != nil {
		return Result{}, err
	}
	if !found {
		progress, err = service.planDelete(opCtx, state)
		if err != nil {
			return Result{}, err
		}
	}
	authorization, progress, state, err := service.authorizeCustodyOrRecoverDelete(opCtx, state, progress)
	if err != nil {
		return Result{}, err
	}
	lifecycle, progress, err := service.tombstoneOrRecoverDelete(opCtx, state, authorization, progress)
	if err != nil {
		return Result{}, err
	}
	attestation, progress, err := service.disposeOrRecoverDelete(opCtx, state, authorization, lifecycle, progress)
	if err != nil {
		return Result{}, err
	}
	completion, progress, err := service.completeCustodyOrRecoverDelete(opCtx, state, authorization,
		lifecycle, attestation, progress)
	if err != nil {
		return Result{}, err
	}
	return service.commitDelete(ctx, opCtx, state, idempotency, authorization, lifecycle,
		attestation, completion, progress)
}

type deleteState struct {
	Command               Command
	IntentDigest          string
	Case                  CaseSnapshot
	Evidence              VerifiedEvidenceSet
	Decision              Decision
	FinalDecisionDigest   string
	FinalRevocationDigest string
	InitialHead           CustodyHead
	AuthorizedAt          time.Time
}
