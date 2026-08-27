package evidencelifecycle

import (
	"context"
	"time"
)

type HoldService struct {
	authority Authority
	cases     CaseStore
	lifecycle CaseLifecycle
	evidence  EvidenceResolver
	custody   Custody
	store     Store
	auditor   Auditor
	clock     Clock
}

func NewHoldService(authority Authority, cases CaseStore, lifecycle CaseLifecycle, evidence EvidenceResolver,
	custody Custody, store Store, auditor Auditor, clock Clock) (*HoldService, error) {
	if authority == nil || cases == nil || lifecycle == nil || evidence == nil || custody == nil || store == nil ||
		auditor == nil || clock == nil {
		return nil, newError(InvalidInput, "hold_dependencies_invalid", false, nil)
	}
	return &HoldService{authority, cases, lifecycle, evidence, custody, store, auditor, clock}, nil
}

func (service *HoldService) Execute(ctx context.Context, command Command) (Result, error) {
	result, err := service.execute(ctx, command)
	if err == nil {
		return result, nil
	}
	if auditErr := service.auditHoldDenial(ctx, command, err); auditErr != nil {
		return Result{}, auditErr
	}
	return Result{}, err
}

func (service *HoldService) execute(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || (command.Operation != PlaceHold && command.Operation != ReleaseHold) ||
		ValidateCommand(command, service.clock.Now()) != nil {
		return Result{}, newError(InvalidInput, "hold_command_invalid", false, nil)
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
		return Result{}, mapExportDependency(opCtx, "hold_recovery_unavailable", recoverErr)
	} else if found {
		return service.recoverCompletedHold(opCtx, command, intent, idempotency, receipt)
	}
	progress, found, err := service.loadHoldProgress(opCtx, command, intent, idempotency)
	if err != nil {
		return Result{}, err
	}
	state, err := service.authorizeHold(opCtx, command, intent, progress, found)
	if err != nil {
		return Result{}, err
	}
	if !found {
		progress, err = service.planHold(opCtx, state)
		if err != nil {
			return Result{}, err
		}
	}
	lifecycle, progress, state, err := service.applyOrRecoverHold(opCtx, state, progress)
	if err != nil {
		return Result{}, err
	}
	custody, progress, err := service.custodyOrRecoverHold(opCtx, state, lifecycle, progress)
	if err != nil {
		return Result{}, err
	}
	return service.commitHold(ctx, opCtx, state, idempotency, lifecycle, custody, progress)
}

type holdState struct {
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
