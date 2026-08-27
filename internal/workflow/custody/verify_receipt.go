package custody

import "context"

// VerifyReceipt performs read-only durability, chain, lineage, and audit
// verification for one exact command receipt. It does not append or reauthorize.
func (controller *Controller) VerifyReceipt(ctx context.Context, command Command, receipt Receipt) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if validateCommandShape(command) != nil {
		return newError(InvalidInput, "command_invalid", false, nil)
	}
	intent, err := CommandBindingDigest(command)
	if err != nil {
		return err
	}
	idempotency := IdempotencyBindingDigest(command.IdempotencyKey)
	record, err := controller.loadReceiptRecord(ctx, receipt, command, intent, idempotency)
	if err != nil {
		return err
	}
	head, err := controller.loadHead(ctx, command.Case)
	if err != nil {
		return err
	}
	if err = controller.verifyRecordToHead(ctx, record, head); err != nil {
		return err
	}
	verified, err := controller.resolveEvidence(ctx, command)
	if err != nil || verified != record.EvidenceVerifiedDigest {
		return newError(Denied, "receipt_evidence_invalid", false, err)
	}
	proof, err := controller.auditor.VerifyCustodyEvent(ctx, receipt.Case, receipt.AuditEventDigest, receipt.RecordDigest)
	if err != nil {
		return mapDependency(ctx, "audit_verification_unavailable", err)
	}
	if !validAuditProof(proof) || proof.EventDigest != receipt.AuditEventDigest {
		return newError(Denied, "audit_verification_invalid", false, nil)
	}
	return nil
}
