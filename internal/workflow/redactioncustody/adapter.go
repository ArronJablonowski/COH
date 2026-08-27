// Package redactioncustody adapts governed redaction lineage to the append-only
// chain-of-custody controller.
package redactioncustody

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

type Recorder interface {
	Execute(context.Context, custody.Command) (custody.Result, error)
	VerifyReceipt(context.Context, custody.Command, custody.Receipt) error
}

type LedgerReader interface {
	LoadHead(context.Context, domain.CaseRef) (custody.Head, error)
	ResolveReceipt(context.Context, domain.CaseRef, string) (custody.Receipt, bool, error)
}

type Adapter struct {
	recorder Recorder
	ledger   LedgerReader
}

func New(recorder Recorder, ledger LedgerReader) (*Adapter, error) {
	if recorder == nil || ledger == nil {
		return nil, redactionError(redaction.InvalidInput, "custody_dependencies_required", false)
	}
	return &Adapter{recorder, ledger}, nil
}

func (adapter *Adapter) LoadCustodyHead(ctx context.Context, scope domain.CaseRef) (redaction.CustodyHead, error) {
	head, err := adapter.ledger.LoadHead(ctx, scope)
	if err != nil {
		return redaction.CustodyHead{}, translate(err)
	}
	return toRedactionHead(head), nil
}

func (adapter *Adapter) RecordRedaction(ctx context.Context,
	request redaction.CustodyRequest) (redaction.CustodyProof, bool, error) {
	command, err := custodyCommand(request)
	if err != nil {
		return redaction.CustodyProof{}, false, err
	}
	result, err := adapter.recorder.Execute(ctx, command)
	if err != nil {
		return redaction.CustodyProof{}, false, translate(err)
	}
	if _, err = custody.CanonicalReceipt(result.Receipt); err != nil {
		return redaction.CustodyProof{}, false, redactionError(redaction.Denied, "custody_receipt_invalid", false)
	}
	return toRedactionProof(result), result.Replayed, nil
}

func (adapter *Adapter) VerifyRedaction(ctx context.Context, request redaction.CustodyRequest,
	proof redaction.CustodyProof) error {
	command, err := custodyCommand(request)
	if err != nil {
		return err
	}
	// The complete receipt contains additional signed fields not present in the
	// narrow proof. Resolve it by exact receipt digest before read-only verify.
	resolved, found, resolveErr := adapter.ledger.ResolveReceipt(ctx, command.Case, proof.ReceiptDigest)
	if resolveErr != nil {
		return translate(resolveErr)
	}
	if !found || resolved.ReceiptDigest != proof.ReceiptDigest || resolved.Sequence != proof.Sequence ||
		resolved.RecordDigest != proof.RecordDigest || resolved.ChainHash != proof.ChainHash || resolved.AuditEventDigest != proof.AuditDigest {
		return redactionError(redaction.Denied, "custody_proof_invalid", false)
	}
	if err = adapter.recorder.VerifyReceipt(ctx, command, resolved); err != nil {
		return translate(err)
	}
	return nil
}
