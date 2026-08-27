package custody

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain/tamperaudit"
)

const custodyReadBatch = uint16(256)

type Controller struct {
	authority Authority
	cases     CaseStore
	evidence  EvidenceResolver
	ledger    Ledger
	auditor   Auditor
	clock     Clock
}

func New(authority Authority, cases CaseStore, evidence EvidenceResolver, ledger Ledger,
	auditor Auditor, clock Clock) (*Controller, error) {
	if authority == nil || cases == nil || evidence == nil || ledger == nil || auditor == nil || clock == nil {
		return nil, newError(InvalidInput, "dependencies_required", false, nil)
	}
	return &Controller{authority: authority, cases: cases, evidence: evidence,
		ledger: ledger, auditor: auditor, clock: clock}, nil
}

func (controller *Controller) Execute(ctx context.Context, command Command) (Result, error) {
	result, err := controller.execute(ctx, command)
	if err == nil || validateCommandShape(command) != nil {
		return result, err
	}
	now := controller.clock.Now()
	if !validTime(now) {
		return Result{}, err
	}
	intent, digestErr := CommandBindingDigest(command)
	if digestErr != nil {
		return Result{}, err
	}
	event := deniedAuditEvent(command, intent, err, now)
	if _, auditErr := controller.appendAudit(ctx, event); auditErr != nil {
		return Result{}, auditErr
	}
	return Result{}, err
}

func (controller *Controller) execute(ctx context.Context, command Command) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	now, err := controller.now()
	if err != nil {
		return Result{}, err
	}
	if err = validateCommand(command, now); err != nil {
		return Result{}, err
	}
	opCtx, cancel := operationContext(ctx, command.Deadline, now)
	defer cancel()
	intent, err := CommandBindingDigest(command)
	if err != nil {
		return Result{}, err
	}
	idempotency := IdempotencyBindingDigest(command.IdempotencyKey)
	recovered, found, err := controller.ledger.Recover(opCtx, command.Case, idempotency)
	if err != nil {
		return Result{}, mapDependency(opCtx, "receipt_recovery_unavailable", err)
	}
	if found {
		return controller.replay(opCtx, command, intent, idempotency, recovered, now)
	}
	current, err := controller.loadCase(opCtx, command.Case)
	if err != nil {
		return Result{}, err
	}
	if current.Revision != command.ExpectedCaseRevision {
		return Result{}, newError(Conflict, "stale_case", true, nil)
	}
	head, err := controller.loadHead(opCtx, command.Case)
	if err != nil {
		return Result{}, err
	}
	if !sameHead(head, command.ExpectedHead) {
		return Result{}, newError(Conflict, "stale_head", true, nil)
	}
	verified, err := controller.resolveEvidence(opCtx, command)
	if err != nil {
		return Result{}, err
	}
	if err = controller.verifyLifecycle(opCtx, command, current, now); err != nil {
		return Result{}, err
	}
	if err = controller.verifyPriorAuthorization(opCtx, command, head); err != nil {
		return Result{}, err
	}
	decision, authorization, err := controller.authorize(opCtx, command, intent, current, head, verified, now)
	if err != nil {
		return Result{}, err
	}
	if decision.Outcome != Allow {
		return Result{}, newError(Denied, string(decision.ReasonCode), false, nil)
	}
	record, receipt, event, err := controller.buildCommit(opCtx, command, intent, idempotency,
		authorization, decision, head, verified, now)
	if err != nil {
		return Result{}, err
	}
	stored, replayed, err := controller.ledger.Append(opCtx, command.IdempotencyKey, intent, head, record, receipt)
	if err != nil {
		return Result{}, mapLedgerError(opCtx, err)
	}
	storedRecord := record
	if replayed {
		storedRecord, err = controller.loadReceiptRecord(opCtx, stored, command, intent, idempotency)
		if err != nil {
			return Result{}, err
		}
		event, err = allowedAuditEvent(storedRecord)
		if err != nil {
			return Result{}, err
		}
	} else if err = validateReceiptRecord(stored, record, command, intent, idempotency); err != nil {
		return Result{}, err
	}
	proof, err := controller.appendAudit(ctx, event)
	if err != nil {
		return Result{}, err
	}
	if err = controller.verifyAudit(ctx, stored, proof); err != nil {
		return Result{}, err
	}
	if replayed {
		replayProof, replayErr := controller.appendAudit(ctx, replayAuditEvent(command, decision, stored, now))
		if replayErr != nil || !validAuditProof(replayProof) {
			return Result{}, newError(Unavailable, "replay_audit_unavailable", true, replayErr)
		}
	}
	return Result{Receipt: stored, Audit: proof, Replayed: replayed}, nil
}

func (controller *Controller) replay(ctx context.Context, command Command, intent, idempotency string,
	receipt Receipt, now time.Time) (Result, error) {
	record, err := controller.loadReceiptRecord(ctx, receipt, command, intent, idempotency)
	if err != nil {
		return Result{}, err
	}
	current, err := controller.loadCase(ctx, command.Case)
	if err != nil {
		return Result{}, err
	}
	head, err := controller.loadHead(ctx, command.Case)
	if err != nil {
		return Result{}, err
	}
	if err = controller.verifyRecordToHead(ctx, record, head); err != nil {
		return Result{}, err
	}
	verified, err := controller.resolveEvidence(ctx, record.Command)
	if err != nil || verified != record.EvidenceVerifiedDigest {
		return Result{}, newError(Denied, "replay_evidence_invalid", false, err)
	}
	if err = controller.verifyLifecycle(ctx, record.Command, current, now); err != nil {
		return Result{}, err
	}
	if err = controller.verifyPriorAuthorization(ctx, record.Command, head); err != nil {
		return Result{}, err
	}
	decision, _, err := controller.authorize(ctx, record.Command, intent, current, head, verified, now)
	if err != nil {
		return Result{}, err
	}
	if decision.Outcome != Allow {
		return Result{}, newError(Denied, string(decision.ReasonCode), false, nil)
	}
	event, err := allowedAuditEvent(record)
	if err != nil {
		return Result{}, err
	}
	proof, err := controller.appendAudit(ctx, event)
	if err != nil {
		return Result{}, err
	}
	if err = controller.verifyAudit(ctx, receipt, proof); err != nil {
		return Result{}, err
	}
	if _, err = controller.appendAudit(ctx, replayAuditEvent(command, decision, receipt, now)); err != nil {
		return Result{}, err
	}
	return Result{Receipt: receipt, Audit: proof, Replayed: true}, nil
}

func (controller *Controller) authorize(ctx context.Context, command Command, intent string, current CaseSnapshot,
	head Head, verified string, now time.Time) (Decision, AuthorizationRequest, error) {
	request := AuthorizationRequest{SchemaVersion: AuthorizationSchemaVersion, ContractVersion: ContractVersion,
		IntentDigest: intent, Command: cloneCommand(command), CaseState: current.State,
		CaseClassification: current.Classification, CaseRevision: current.Revision,
		RetentionPolicyDigest: current.RetentionPolicyDigest, RetainUntil: current.RetainUntil,
		LegalHold: current.LegalHold, CaseProvenanceDigest: current.ProvenanceDigest,
		EvidenceVerifiedDigest: verified, CurrentHead: cloneHead(head)}
	request.AuthorizationDigest, _ = AuthorizationBindingDigest(request)
	if err := validateAuthorization(request); err != nil {
		return Decision{}, AuthorizationRequest{}, err
	}
	decision, err := controller.authority.AuthorizeCustody(ctx, request)
	if err != nil {
		return Decision{}, AuthorizationRequest{}, mapDependency(ctx, "authority_unavailable", err)
	}
	if validateDecision(decision) != nil || decision.AuthorizationDigest != request.AuthorizationDigest ||
		decision.IntentDigest != intent || decision.Operation != command.Operation || decision.Phase != command.Phase ||
		decision.Case != command.Case || decision.ActorID != command.ActorID ||
		decision.ActorRevision != command.ActorRevision || decision.ExpectedCaseRevision != current.Revision ||
		!sameHead(decision.ExpectedHead, head) || decision.PolicyDigest != command.PolicyDigest ||
		decision.IssuedAt.After(now) || !decision.ExpiresAt.After(now) || decision.ExpiresAt.After(command.Deadline) {
		return Decision{}, AuthorizationRequest{}, newError(Denied, "decision_binding_invalid", false, nil)
	}
	return decision, request, nil
}

func (controller *Controller) buildCommit(ctx context.Context, command Command, intent, idempotency string,
	authorization AuthorizationRequest, decision Decision, head Head,
	verified string, now time.Time) (Record, Receipt, tamperaudit.Event, error) {
	previous, err := controller.previousProvenance(ctx, head)
	if err != nil {
		return Record{}, Receipt{}, tamperaudit.Event{}, err
	}
	record := Record{SchemaVersion: RecordSchemaVersion, ContractVersion: ContractVersion,
		CustodyID: deterministicUUID("COH-CUSTODY-ID-V1\x00", command.RequestID+"\x00"+decision.DecisionDigest),
		Case:      command.Case, Sequence: head.Sequence + 1, PreviousChainHash: head.ChainHash,
		Command: cloneCommand(command), IntentDigest: intent, AuthorizationDigest: authorization.AuthorizationDigest,
		DecisionDigest: decision.DecisionDigest, RevocationDigest: decision.RevocationDigest,
		EvidenceVerifiedDigest: verified, PreviousProvenanceDigest: previous, OccurredAt: now}
	record.ProvenanceDigest, err = RecordProvenanceDigest(record)
	if err != nil {
		return Record{}, Receipt{}, tamperaudit.Event{}, err
	}
	event, err := allowedAuditEvent(record)
	if err != nil {
		return Record{}, Receipt{}, tamperaudit.Event{}, err
	}
	record.AuditEventDigest, err = auditEventBindingDigest(event)
	if err != nil {
		return Record{}, Receipt{}, tamperaudit.Event{}, err
	}
	record.RecordDigest, err = RecordBindingDigest(record)
	if err != nil {
		return Record{}, Receipt{}, tamperaudit.Event{}, err
	}
	record.ChainHash, err = RecordChainHash(record)
	if err != nil || validateRecord(record) != nil {
		return Record{}, Receipt{}, tamperaudit.Event{}, newError(InternalFailure, "record_build_failed", false, err)
	}
	receipt := Receipt{SchemaVersion: ReceiptSchemaVersion, ContractVersion: ContractVersion,
		RequestID: command.RequestID, Case: command.Case, IdempotencyDigest: idempotency, IntentDigest: intent,
		DecisionDigest: decision.DecisionDigest, CustodyID: record.CustodyID, Sequence: record.Sequence,
		RecordDigest: record.RecordDigest, ChainHash: record.ChainHash, AuditEventDigest: record.AuditEventDigest,
		ProvenanceDigest: record.ProvenanceDigest, CreatedAt: now}
	receipt.ReceiptDigest, err = ReceiptBindingDigest(receipt)
	if err != nil || validateReceipt(receipt) != nil {
		return Record{}, Receipt{}, tamperaudit.Event{}, newError(InternalFailure, "receipt_build_failed", false, err)
	}
	return record, receipt, event, nil
}

func (controller *Controller) now() (time.Time, error) {
	now := controller.clock.Now()
	if !validTime(now) {
		return time.Time{}, newError(InternalFailure, "clock_invalid", false, nil)
	}
	return now, nil
}

func mapLedgerError(ctx context.Context, err error) error {
	if CodeOf(err) == Conflict {
		return newError(Conflict, "concurrent_conflict", true, err)
	}
	return mapDependency(ctx, "ledger_append_unavailable", err)
}
