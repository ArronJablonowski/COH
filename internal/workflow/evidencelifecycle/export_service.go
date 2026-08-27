package evidencelifecycle

import (
	"context"
	"time"
)

type SigningProfile struct {
	KeyID               string
	KeyRevision         uint64
	TrustSnapshotDigest string
	KeyRevocationDigest string
	Validity            time.Duration
}

type ExportService struct {
	authority  Authority
	cases      CaseStore
	lifecycle  CaseLifecycle
	evidence   EvidenceResolver
	redactions RedactionResolver
	custody    Custody
	signer     Signer
	verifier   SignatureVerifier
	packages   PackageWriter
	store      Store
	auditor    Auditor
	clock      Clock
	signing    SigningProfile
}

func NewExportService(authority Authority, cases CaseStore, lifecycle CaseLifecycle, evidence EvidenceResolver,
	redactions RedactionResolver, custody Custody, signer Signer, verifier SignatureVerifier,
	packages PackageWriter, store Store, auditor Auditor, clock Clock, signing SigningProfile) (*ExportService, error) {
	if authority == nil || cases == nil || lifecycle == nil || evidence == nil || redactions == nil || custody == nil ||
		signer == nil || verifier == nil || packages == nil || store == nil || auditor == nil || clock == nil ||
		!tokenPattern.MatchString(signing.KeyID) || !validRevision(signing.KeyRevision) ||
		!allDigests(signing.TrustSnapshotDigest, signing.KeyRevocationDigest) ||
		signing.Validity <= 0 || signing.Validity > 24*time.Hour {
		return nil, newError(InvalidInput, "export_dependencies_invalid", false, nil)
	}
	return &ExportService{authority, cases, lifecycle, evidence, redactions, custody, signer, verifier,
		packages, store, auditor, clock, signing}, nil
}

func (service *ExportService) Execute(ctx context.Context, command Command) (Result, error) {
	result, err := service.execute(ctx, command)
	if err == nil {
		return result, nil
	}
	if auditErr := service.auditDenial(ctx, command, err); auditErr != nil {
		return Result{}, auditErr
	}
	return Result{}, err
}

func (service *ExportService) execute(ctx context.Context, command Command) (Result, error) {
	if ctx == nil {
		return Result{}, newError(InvalidInput, "context_required", false, nil)
	}
	now := service.clock.Now()
	if command.Operation != Export || ValidateCommand(command, now) != nil {
		return Result{}, newError(InvalidInput, "export_command_invalid", false, nil)
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
	if recovered, found, recoverErr := service.store.Recover(opCtx, command.Case, idempotency); recoverErr != nil {
		return Result{}, mapExportDependency(opCtx, "export_recovery_unavailable", recoverErr)
	} else if found {
		return service.recoverCompleted(opCtx, command, intent, idempotency, recovered)
	}
	state, err := service.preflight(opCtx, command, intent)
	if err != nil {
		return Result{}, err
	}
	progress, err := service.plan(opCtx, state, idempotency)
	if err != nil {
		return Result{}, err
	}
	authorizationCustody, authorizedCustody, progress, err := service.authorizeCustody(opCtx, state, progress)
	if err != nil {
		return Result{}, err
	}
	state.Custody = authorizedCustody
	manifest, signature, packaged, progress, err := service.packageExport(opCtx, state, authorizationCustody, progress)
	if err != nil {
		return Result{}, err
	}
	completionCustody, progress, err := service.completeCustody(opCtx, state, authorizationCustody,
		manifest, signature, packaged, progress)
	if err != nil {
		return Result{}, err
	}
	lifecycle, progress, err := service.recordCaseExport(opCtx, state, manifest, progress)
	if err != nil {
		return Result{}, err
	}
	record, receipt, progress, event, expectedEvent, err := buildExportResult(state, idempotency,
		authorizationCustody, completionCustody, lifecycle, manifest, signature, packaged, progress)
	if err != nil {
		return Result{}, err
	}
	if err = service.appendAndVerifyAudit(ctx, command.Case, event, expectedEvent); err != nil {
		return Result{}, err
	}
	record.AuditEventDigest = expectedEvent
	record.RecordDigest, err = RecordBindingDigest(record)
	if err != nil {
		return Result{}, newError(Unavailable, "export_record_build_failed", false, err)
	}
	receipt.RecordDigest, receipt.AuditEventDigest = record.RecordDigest, expectedEvent
	receipt.ReceiptDigest, err = ReceiptBindingDigest(receipt)
	if err != nil || ValidateRecord(record) != nil || ValidateReceipt(receipt) != nil {
		return Result{}, newError(Unavailable, "export_result_build_failed", false, err)
	}
	stored, replayed, err := service.store.Commit(opCtx, command.IdempotencyKey, intent, progress, record, receipt)
	if err != nil {
		return Result{}, mapExportDependency(opCtx, "export_commit_unavailable", err)
	}
	if ValidateReceipt(stored) != nil || stored.IntentDigest != intent || stored.IdempotencyDigest != idempotency ||
		stored.PackageDigest == nil || *stored.PackageDigest != packaged.PackageDigest {
		return Result{}, newError(Denied, "stored_export_receipt_invalid", false, nil)
	}
	reference := packaged.Reference
	return Result{Receipt: stored, ReleaseReference: &reference, Replayed: replayed}, nil
}
