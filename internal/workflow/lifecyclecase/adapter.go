// Package lifecyclecase adapts signed evidence lifecycle operations to the
// authoritative case lifecycle controller and repositories.
package lifecyclecase

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/caselifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Controller interface {
	Execute(context.Context, caselifecycle.Command) (caselifecycle.Result, error)
}

type Repository interface {
	Load(context.Context, domain.CaseRef) (caselifecycle.Record, bool, error)
	ResolveReceipt(context.Context, domain.CaseRef, string) (caselifecycle.Receipt, bool, error)
}

type HoldReleaseIndex interface {
	HasIncompleteHoldRelease(context.Context, domain.CaseRef) (bool, error)
}

type Adapter struct {
	controller Controller
	repository Repository
	releases   HoldReleaseIndex
}

func New(controller Controller, repository Repository, releases HoldReleaseIndex) (*Adapter, error) {
	if controller == nil || repository == nil || releases == nil {
		return nil, lifecycleError(evidencelifecycle.InvalidInput, "case_dependencies_required", false)
	}
	return &Adapter{controller: controller, repository: repository, releases: releases}, nil
}

func (adapter *Adapter) LoadCase(ctx context.Context,
	scope domain.CaseRef) (evidencelifecycle.CaseSnapshot, bool, error) {
	record, found, err := adapter.repository.Load(ctx, scope)
	if err != nil || !found {
		return evidencelifecycle.CaseSnapshot{}, found, translate(err)
	}
	if _, err = caselifecycle.CanonicalRecord(record); err != nil || record.Case != scope {
		return evidencelifecycle.CaseSnapshot{}, false,
			lifecycleError(evidencelifecycle.Denied, "case_record_invalid", false)
	}
	return snapshot(record), true, nil
}

func (adapter *Adapter) ResolveLifecycleReceipt(ctx context.Context, scope domain.CaseRef,
	receiptDigest string) (evidencelifecycle.LifecycleProof, bool, error) {
	if !digestPattern.MatchString(receiptDigest) {
		return evidencelifecycle.LifecycleProof{}, false,
			lifecycleError(evidencelifecycle.InvalidInput, "case_receipt_digest_invalid", false)
	}
	receipt, found, err := adapter.repository.ResolveReceipt(ctx, scope, receiptDigest)
	if err != nil || !found {
		return evidencelifecycle.LifecycleProof{}, found, translate(err)
	}
	proof, err := proofFromReceipt(receipt)
	if err != nil || receipt.Case != scope || receipt.ReceiptDigest != receiptDigest {
		return evidencelifecycle.LifecycleProof{}, false,
			lifecycleError(evidencelifecycle.Denied, "case_receipt_invalid", false)
	}
	return proof, true, nil
}

func (adapter *Adapter) HasIncompleteHoldRelease(ctx context.Context,
	scope domain.CaseRef) (bool, error) {
	return adapter.releases.HasIncompleteHoldRelease(ctx, scope)
}

func (adapter *Adapter) ApplyCaseOperation(ctx context.Context,
	request evidencelifecycle.LifecycleRequest) (evidencelifecycle.LifecycleProof, error) {
	command, err := commandFor(request)
	if err != nil {
		return evidencelifecycle.LifecycleProof{}, err
	}
	result, err := adapter.controller.Execute(ctx, command)
	if err != nil {
		return evidencelifecycle.LifecycleProof{}, translate(err)
	}
	receiptCommand, commandErr := caselifecycle.CanonicalCommand(result.Receipt.Command)
	requestedCommand, requestErr := caselifecycle.CanonicalCommand(command)
	resultRecord, recordErr := caselifecycle.CanonicalRecord(result.Record)
	receiptRecord, receiptRecordErr := caselifecycle.CanonicalRecord(result.Receipt.Record)
	if _, err = caselifecycle.CanonicalReceipt(result.Receipt); err != nil ||
		commandErr != nil || requestErr != nil || recordErr != nil || receiptRecordErr != nil ||
		!bytes.Equal(receiptCommand, requestedCommand) || !bytes.Equal(resultRecord, receiptRecord) {
		return evidencelifecycle.LifecycleProof{},
			lifecycleError(evidencelifecycle.Denied, "case_operation_result_invalid", false)
	}
	proof, err := proofFromReceipt(result.Receipt)
	if err != nil || proof.Operation != request.Operation || proof.Case != request.Case ||
		proof.Revision != request.ExpectedCaseRevision+1 {
		return evidencelifecycle.LifecycleProof{},
			lifecycleError(evidencelifecycle.Denied, "case_operation_result_invalid", false)
	}
	return proof, nil
}

func commandFor(request evidencelifecycle.LifecycleRequest) (caselifecycle.Command, error) {
	operation, ok := toCaseOperation(request.Operation)
	if !ok || !digestPattern.MatchString(request.IdempotencyDigest) {
		return caselifecycle.Command{},
			lifecycleError(evidencelifecycle.InvalidInput, "case_operation_request_invalid", false)
	}
	command := caselifecycle.Command{SchemaVersion: caselifecycle.CommandSchemaVersion,
		ContractVersion: caselifecycle.ContractVersion,
		RequestID: deterministicUUID("COH-EVIDENCE-CASE-REQUEST-ID-V1\x00",
			string(request.Operation)+"\x00"+request.IdempotencyDigest),
		IdempotencyKey: "evidence-lifecycle-" + strings.TrimPrefix(request.IdempotencyDigest, "sha256:"),
		Operation:      operation, Case: request.Case, ActorID: request.ActorID,
		ActorRevision: request.ActorRevision, ReasonDigest: clone(request.ReasonDigest),
		ExportManifestDigest: clone(request.ManifestDigest), PolicyDigest: request.PolicyDigest,
		ExpectedRevision: request.ExpectedCaseRevision, Deadline: request.Deadline}
	if _, err := caselifecycle.CanonicalCommand(command); err != nil {
		return caselifecycle.Command{},
			lifecycleError(evidencelifecycle.InvalidInput, "case_operation_request_invalid", false)
	}
	return command, nil
}

func proofFromReceipt(receipt caselifecycle.Receipt) (evidencelifecycle.LifecycleProof, error) {
	if _, err := caselifecycle.CanonicalReceipt(receipt); err != nil {
		return evidencelifecycle.LifecycleProof{}, err
	}
	if receipt.Record.Case != receipt.Case || receipt.Record.ProvenanceDigest == "" {
		return evidencelifecycle.LifecycleProof{},
			lifecycleError(evidencelifecycle.Denied, "case_receipt_binding_invalid", false)
	}
	operation, ok := fromCaseOperation(receipt.Operation)
	if !ok {
		return evidencelifecycle.LifecycleProof{},
			lifecycleError(evidencelifecycle.Denied, "case_receipt_operation_invalid", false)
	}
	return evidencelifecycle.LifecycleProof{Operation: operation, Case: receipt.Case,
		Revision: receipt.Record.Revision, LegalHold: receipt.Record.LegalHold,
		ReceiptDigest: receipt.ReceiptDigest, ProvenanceDigest: receipt.Record.ProvenanceDigest}, nil
}

func snapshot(record caselifecycle.Record) evidencelifecycle.CaseSnapshot {
	return evidencelifecycle.CaseSnapshot{Case: record.Case, State: string(record.State),
		Classification: string(record.Classification), Revision: record.Revision,
		RetainUntil: record.RetainUntil, LegalHold: record.LegalHold,
		ProvenanceDigest: record.ProvenanceDigest}
}

func toCaseOperation(value evidencelifecycle.Operation) (caselifecycle.Operation, bool) {
	switch value {
	case evidencelifecycle.Export:
		return caselifecycle.Export, true
	case evidencelifecycle.PlaceHold:
		return caselifecycle.PlaceHold, true
	case evidencelifecycle.ReleaseHold:
		return caselifecycle.ReleaseHold, true
	case evidencelifecycle.Delete:
		return caselifecycle.Delete, true
	default:
		return "", false
	}
}

func fromCaseOperation(value caselifecycle.Operation) (evidencelifecycle.Operation, bool) {
	switch value {
	case caselifecycle.Export:
		return evidencelifecycle.Export, true
	case caselifecycle.PlaceHold:
		return evidencelifecycle.PlaceHold, true
	case caselifecycle.ReleaseHold:
		return evidencelifecycle.ReleaseHold, true
	case caselifecycle.Delete:
		return evidencelifecycle.Delete, true
	default:
		return "", false
	}
}

func translate(err error) error {
	if err == nil {
		return nil
	}
	switch caselifecycle.CodeOf(err) {
	case caselifecycle.InvalidInput:
		return lifecycleError(evidencelifecycle.InvalidInput, "case_lifecycle_invalid", false)
	case caselifecycle.Denied:
		return lifecycleError(evidencelifecycle.Denied, "case_lifecycle_denied", false)
	case caselifecycle.NotFound:
		return lifecycleError(evidencelifecycle.NotFound, "case_lifecycle_not_found", false)
	case caselifecycle.Conflict:
		return lifecycleError(evidencelifecycle.Conflict, "case_lifecycle_conflict", true)
	case caselifecycle.Canceled:
		return lifecycleError(evidencelifecycle.Canceled, "case_lifecycle_canceled", false)
	case caselifecycle.Timeout:
		return lifecycleError(evidencelifecycle.Timeout, "case_lifecycle_timeout", true)
	default:
		return lifecycleError(evidencelifecycle.Unavailable, "case_lifecycle_unavailable", true)
	}
}

func lifecycleError(code evidencelifecycle.ErrorCode, reason string, retryable bool) error {
	return &evidencelifecycle.Error{Code: code, Reason: reason, Retryable: retryable}
}

func deterministicUUID(domainName, value string) string {
	sum := sha256.Sum256([]byte(domainName + value))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

func clone(value *string) *string {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

var _ evidencelifecycle.CaseStore = (*Adapter)(nil)
var _ evidencelifecycle.CaseLifecycle = (*Adapter)(nil)
