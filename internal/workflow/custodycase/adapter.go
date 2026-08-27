// Package custodycase adapts authoritative case lifecycle state and receipts
// to the narrow, read-only case boundary consumed by chain of custody.
package custodycase

import (
	"context"
	"errors"
	"regexp"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/caselifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Repository interface {
	Load(context.Context, domain.CaseRef) (caselifecycle.Record, bool, error)
	ResolveReceipt(context.Context, domain.CaseRef, string) (caselifecycle.Receipt, bool, error)
}

type Adapter struct{ repository Repository }

func New(repository Repository) (*Adapter, error) {
	if repository == nil {
		return nil, errors.New("custody case repository required")
	}
	return &Adapter{repository: repository}, nil
}

func (adapter *Adapter) LoadCase(ctx context.Context,
	scope domain.CaseRef) (custody.CaseSnapshot, bool, error) {
	record, found, err := adapter.repository.Load(ctx, scope)
	if err != nil || !found {
		return custody.CaseSnapshot{}, found, err
	}
	if _, err = caselifecycle.CanonicalRecord(record); err != nil || record.Case != scope {
		return custody.CaseSnapshot{}, false, errors.New("authoritative case record invalid")
	}
	retentionDigest, err := caselifecycle.RetentionPolicyBindingDigest(record.RetentionPolicyID)
	if err != nil {
		return custody.CaseSnapshot{}, false, errors.New("authoritative retention policy invalid")
	}
	return custody.CaseSnapshot{Case: record.Case, State: string(record.State),
		Classification: string(record.Classification), Revision: record.Revision,
		RetentionPolicyDigest: retentionDigest, RetainUntil: record.RetainUntil,
		LegalHold: record.LegalHold, ProvenanceDigest: record.ProvenanceDigest}, true, nil
}

func (adapter *Adapter) ResolveLifecycleReceipt(ctx context.Context, scope domain.CaseRef,
	receiptDigest string) (custody.LifecycleReceiptSnapshot, bool, error) {
	if !digestPattern.MatchString(receiptDigest) {
		return custody.LifecycleReceiptSnapshot{}, false, errors.New("case lifecycle receipt digest invalid")
	}
	receipt, found, err := adapter.repository.ResolveReceipt(ctx, scope, receiptDigest)
	if err != nil || !found {
		return custody.LifecycleReceiptSnapshot{}, found, err
	}
	if _, err = caselifecycle.CanonicalReceipt(receipt); err != nil || receipt.Case != scope ||
		receipt.Record.Case != scope || receipt.ReceiptDigest != receiptDigest {
		return custody.LifecycleReceiptSnapshot{}, false, errors.New("authoritative case receipt invalid")
	}
	if receipt.Operation != caselifecycle.PlaceHold && receipt.Operation != caselifecycle.ReleaseHold &&
		receipt.Operation != caselifecycle.Delete {
		return custody.LifecycleReceiptSnapshot{}, false, errors.New("case lifecycle receipt operation unsupported")
	}
	return custody.LifecycleReceiptSnapshot{Case: receipt.Case, Operation: string(receipt.Operation),
		Revision: receipt.Record.Revision, ReceiptDigest: receipt.ReceiptDigest,
		ProvenanceDigest: receipt.Record.ProvenanceDigest, LegalHold: receipt.Record.LegalHold}, true, nil
}

var _ custody.CaseStore = (*Adapter)(nil)
