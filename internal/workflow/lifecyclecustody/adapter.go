package lifecyclecustody

import (
	"context"
	"fmt"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func New(controller Controller, ledger Ledger, verifier Verifier, checkpoints CheckpointResolver,
	repository workflowbase.MetadataStore) (*Adapter, error) {
	if controller == nil || ledger == nil || verifier == nil || checkpoints == nil || repository == nil {
		return nil, lifecycleError(evidencelifecycle.InvalidInput, "custody_dependencies_required", false)
	}
	return &Adapter{controller: controller, ledger: ledger, verifier: verifier,
		checkpoints: checkpoints, repository: repository}, nil
}

var _ evidencelifecycle.Custody = (*Adapter)(nil)

func (adapter *Adapter) LoadCustodyHead(ctx context.Context,
	scope domain.CaseRef) (evidencelifecycle.CustodyHead, error) {
	head, err := adapter.ledger.LoadHead(ctx, scope)
	if err != nil {
		return evidencelifecycle.CustodyHead{}, custodyError(ctx, "custody_head_unavailable", err)
	}
	if !validCustodyHead(head, scope) {
		return evidencelifecycle.CustodyHead{}, lifecycleError(evidencelifecycle.Denied,
			"custody_head_invalid", false)
	}
	return toLifecycleHead(head), nil
}

func (adapter *Adapter) RecordLifecycle(ctx context.Context,
	request evidencelifecycle.CustodyRequest) (evidencelifecycle.CustodyProofSet, error) {
	requestDigest, err := requestDigest(request)
	if err != nil {
		return evidencelifecycle.CustodyProofSet{}, err
	}
	if stored, found, loadErr := adapter.loadRequest(ctx, request.Case, requestDigest); loadErr != nil {
		return evidencelifecycle.CustodyProofSet{}, loadErr
	} else if found {
		return adapter.resolveStored(ctx, stored)
	}
	var prior *evidencelifecycle.CustodyProofSet
	if request.PriorAuthorizationDigest != nil {
		stored, found, loadErr := adapter.loadDigest(ctx, request.Case, *request.PriorAuthorizationDigest)
		if loadErr != nil {
			return evidencelifecycle.CustodyProofSet{}, loadErr
		}
		if !found {
			return evidencelifecycle.CustodyProofSet{}, lifecycleError(evidencelifecycle.NotFound,
				"prior_custody_set_not_found", false)
		}
		resolved, resolveErr := adapter.resolveStored(ctx, stored)
		if resolveErr != nil || len(resolved.Proofs) != len(request.Subjects) {
			return evidencelifecycle.CustodyProofSet{}, lifecycleError(evidencelifecycle.Denied,
				"prior_custody_set_invalid", false)
		}
		prior = &resolved
	}
	initial := toCustodyHead(request.ExpectedHead)
	current := initial
	proofs := make([]evidencelifecycle.CustodyProof, 0, len(request.Subjects))
	storedProofs := make([]storedProof, 0, len(request.Subjects))
	for index, subject := range request.Subjects {
		command := custodyCommand(request, requestDigest, index, subject, current, prior)
		idempotency := custody.IdempotencyBindingDigest(command.IdempotencyKey)
		receipt, found, recoverErr := adapter.ledger.Recover(ctx, request.Case, idempotency)
		if recoverErr != nil {
			return evidencelifecycle.CustodyProofSet{}, custodyError(ctx, "custody_receipt_recovery_unavailable", recoverErr)
		}
		if found {
			if err = adapter.controller.VerifyReceipt(ctx, command, receipt); err != nil {
				return evidencelifecycle.CustodyProofSet{}, custodyError(ctx, "custody_receipt_recovery_invalid", err)
			}
		} else {
			actual, headErr := adapter.ledger.LoadHead(ctx, request.Case)
			if headErr != nil {
				return evidencelifecycle.CustodyProofSet{}, custodyError(ctx, "custody_head_unavailable", headErr)
			}
			if !sameHead(actual, current) {
				return evidencelifecycle.CustodyProofSet{}, lifecycleError(evidencelifecycle.Conflict,
					"custody_head_changed", true)
			}
			result, executeErr := adapter.controller.Execute(ctx, command)
			if executeErr != nil {
				return evidencelifecycle.CustodyProofSet{}, custodyError(ctx, "custody_record_unavailable", executeErr)
			}
			receipt = result.Receipt
			if err = adapter.controller.VerifyReceipt(ctx, command, receipt); err != nil {
				return evidencelifecycle.CustodyProofSet{}, custodyError(ctx, "custody_receipt_invalid", err)
			}
		}
		proof, storedProof, proofErr := proofFromReceipt(receipt, current)
		if proofErr != nil {
			return evidencelifecycle.CustodyProofSet{}, proofErr
		}
		proofs, storedProofs = append(proofs, proof), append(storedProofs, storedProof)
		current = toCustodyHead(proof.Head)
	}
	setDigest, err := evidencelifecycle.CustodyReceiptSetBindingDigest(proofs)
	if err != nil {
		return evidencelifecycle.CustodyProofSet{}, lifecycleError(evidencelifecycle.Denied,
			"custody_receipt_set_invalid", false)
	}
	stored := storedSet{Case: request.Case, RequestDigest: requestDigest, InitialHead: initial,
		Proofs: storedProofs, SetDigest: setDigest}
	if err = adapter.commitSet(ctx, stored); err != nil {
		return evidencelifecycle.CustodyProofSet{}, err
	}
	return evidencelifecycle.CustodyProofSet{ReceiptSetDigest: setDigest,
		Proofs: proofs, Head: toLifecycleHead(current)}, nil
}

func (adapter *Adapter) RecoverLifecycle(ctx context.Context, scope domain.CaseRef,
	receiptSetDigest string) (evidencelifecycle.CustodyProofSet, bool, error) {
	if !validCase(scope) || !digestPattern.MatchString(receiptSetDigest) {
		return evidencelifecycle.CustodyProofSet{}, false,
			lifecycleError(evidencelifecycle.InvalidInput, "custody_set_lookup_invalid", false)
	}
	stored, found, err := adapter.loadDigest(ctx, scope, receiptSetDigest)
	if err != nil || !found {
		return evidencelifecycle.CustodyProofSet{}, found, err
	}
	resolved, err := adapter.resolveStored(ctx, stored)
	return resolved, err == nil, err
}

func (adapter *Adapter) VerifyLifecycle(ctx context.Context, scope domain.CaseRef,
	from, to uint64) (evidencelifecycle.CustodyVerification, error) {
	report, err := adapter.verifier.VerifyInterval(ctx, scope, from, to)
	if err != nil {
		return evidencelifecycle.CustodyVerification{}, custodyError(ctx, "custody_interval_unavailable", err)
	}
	if report.Outcome != custody.VerificationValid || report.ReasonCode != custody.VerifySuccess ||
		report.FromSequence != from || report.ToSequence != to || report.AuditCheckpointID == nil ||
		report.AuditCheckpointDigest == nil || !digestPattern.MatchString(report.ReportDigest) {
		return evidencelifecycle.CustodyVerification{}, lifecycleError(evidencelifecycle.Denied,
			"custody_interval_invalid", false)
	}
	records, err := adapter.ledger.Read(ctx, scope, to-1, 1)
	if err != nil {
		return evidencelifecycle.CustodyVerification{}, custodyError(ctx, "custody_interval_head_unavailable", err)
	}
	if len(records) != 1 {
		return evidencelifecycle.CustodyVerification{}, lifecycleError(evidencelifecycle.Denied,
			"custody_interval_head_invalid", false)
	}
	record := records[0]
	if _, err = custody.CanonicalRecord(record); err != nil || record.Sequence != to ||
		record.ChainHash != report.HeadChainHash {
		return evidencelifecycle.CustodyVerification{}, lifecycleError(evidencelifecycle.Denied,
			"custody_interval_head_invalid", false)
	}
	checkpoint, err := adapter.checkpoints.ResolveCheckpointProof(ctx, scope.OrganizationID, scope.TenantID,
		*report.AuditCheckpointID, *report.AuditCheckpointDigest, to)
	if err != nil {
		return evidencelifecycle.CustodyVerification{}, lifecycleError(evidencelifecycle.Denied,
			"custody_checkpoint_invalid", false)
	}
	last := record.OccurredAt
	return evidencelifecycle.CustodyVerification{FromSequence: from, ToSequence: to,
		Head:         evidencelifecycle.CustodyHead{Case: scope, Sequence: to, ChainHash: record.ChainHash, LastRecordAt: &last},
		CheckpointID: checkpoint.CheckpointID, CheckpointDigest: checkpoint.CheckpointDigest,
		CheckpointSequence: checkpoint.Sequence, CheckpointSigningKeyRevision: checkpoint.SigningKeyRevision,
		CheckpointProofDigest: checkpoint.ProofDigest, ReportDigest: report.ReportDigest}, nil
}

func (adapter *Adapter) resolveStored(ctx context.Context,
	stored storedSet) (evidencelifecycle.CustodyProofSet, error) {
	current := stored.InitialHead
	proofs := make([]evidencelifecycle.CustodyProof, len(stored.Proofs))
	for index, candidate := range stored.Proofs {
		receipt, found, err := adapter.ledger.ResolveReceipt(ctx, stored.Case, candidate.ReceiptDigest)
		if err != nil {
			return evidencelifecycle.CustodyProofSet{}, custodyError(ctx, "custody_set_receipt_unavailable", err)
		}
		if !found {
			return evidencelifecycle.CustodyProofSet{}, lifecycleError(evidencelifecycle.NotFound,
				"custody_set_receipt_not_found", false)
		}
		proof, exact, proofErr := proofFromReceipt(receipt, current)
		if proofErr != nil || exact != candidate {
			return evidencelifecycle.CustodyProofSet{}, lifecycleError(evidencelifecycle.Denied,
				"custody_set_receipt_invalid", false)
		}
		proofs[index], current = proof, toCustodyHead(proof.Head)
	}
	want, err := evidencelifecycle.CustodyReceiptSetBindingDigest(proofs)
	if err != nil || want != stored.SetDigest {
		return evidencelifecycle.CustodyProofSet{}, lifecycleError(evidencelifecycle.Denied,
			"custody_set_digest_invalid", false)
	}
	return evidencelifecycle.CustodyProofSet{ReceiptSetDigest: stored.SetDigest,
		Proofs: proofs, Head: toLifecycleHead(current)}, nil
}

func custodyCommand(request evidencelifecycle.CustodyRequest, requestDigest string, index int,
	subject evidencelifecycle.EvidenceReference, expected custody.Head,
	prior *evidencelifecycle.CustodyProofSet) custody.Command {
	priorDigest := (*string)(nil)
	if prior != nil {
		value := prior.Proofs[index].ReceiptDigest
		priorDigest = &value
	}
	command := custody.Command{SchemaVersion: custody.CommandSchemaVersion, ContractVersion: custody.ContractVersion,
		RequestID: deterministicUUID("COH-LIFECYCLE-CUSTODY-COMMAND-ID-V1\x00",
			requestDigest+fmt.Sprintf("\x00%05d", index+1)),
		IdempotencyKey: "lifecycle-custody-" + strings.TrimPrefix(requestDigest, "sha256:") + fmt.Sprintf("-%05d", index+1),
		Operation:      toCustodyOperation(request.Operation), Phase: toCustodyPhase(request.Phase), Case: request.Case,
		ActorID: request.ActorID, ActorRevision: request.ActorRevision, Subject: toCustodyReference(subject),
		PolicyDigest:         request.PolicyDigest,
		ExpectedCaseRevision: request.ExpectedCaseRevision, ExpectedHead: expected, Deadline: request.Deadline}
	switch request.Operation {
	case evidencelifecycle.Import:
		command.SourceIdentityDigest = clone(request.SourceDigest)
	case evidencelifecycle.Export:
		command.PurposeDigest = clone(request.PurposeDigest)
		command.DestinationDigest = clone(request.DestinationDigest)
		if request.Phase == evidencelifecycle.Completed {
			command.ExternalReceiptDigest = clone(request.PackageDigest)
			command.PriorAuthorizationDigest = priorDigest
		}
	case evidencelifecycle.PlaceHold, evidencelifecycle.ReleaseHold:
		command.ReasonDigest = clone(request.ReasonDigest)
		command.LifecycleReceiptDigest = clone(request.LifecycleReceiptDigest)
		command.ArtifactSetDigest = clone(&request.ArtifactSetDigest)
	case evidencelifecycle.Delete:
		command.ReasonDigest = clone(request.ReasonDigest)
		command.ArtifactSetDigest = clone(&request.ArtifactSetDigest)
		if request.Phase == evidencelifecycle.Completed {
			command.ExternalReceiptDigest = clone(request.DispositionAttestationDigest)
			command.LifecycleReceiptDigest = clone(request.LifecycleReceiptDigest)
			command.PriorAuthorizationDigest = priorDigest
		}
	}
	return command
}

func proofFromReceipt(receipt custody.Receipt, prior custody.Head) (evidencelifecycle.CustodyProof,
	storedProof, error) {
	if _, err := custody.CanonicalReceipt(receipt); err != nil || receipt.Case != prior.Case ||
		receipt.Sequence != prior.Sequence+1 || receipt.Sequence == 0 || receipt.ChainHash == prior.ChainHash {
		return evidencelifecycle.CustodyProof{}, storedProof{},
			lifecycleError(evidencelifecycle.Denied, "custody_receipt_invalid", false)
	}
	last := receipt.CreatedAt
	head := evidencelifecycle.CustodyHead{Case: receipt.Case, Sequence: receipt.Sequence,
		ChainHash: receipt.ChainHash, LastRecordAt: &last}
	proof := evidencelifecycle.CustodyProof{ReceiptDigest: receipt.ReceiptDigest,
		RecordDigest: receipt.RecordDigest, AuditDigest: receipt.AuditEventDigest, Head: head}
	stored := storedProof{ReceiptDigest: receipt.ReceiptDigest, RecordDigest: receipt.RecordDigest,
		AuditDigest: receipt.AuditEventDigest, Sequence: receipt.Sequence, ChainHash: receipt.ChainHash,
		CreatedAt: formatTime(receipt.CreatedAt)}
	return proof, stored, nil
}

func toCustodyOperation(value evidencelifecycle.Operation) custody.Operation {
	switch value {
	case evidencelifecycle.Import:
		return custody.Acquire
	case evidencelifecycle.Export:
		return custody.Export
	case evidencelifecycle.PlaceHold:
		return custody.PlaceHold
	case evidencelifecycle.ReleaseHold:
		return custody.ReleaseHold
	default:
		return custody.Delete
	}
}
func toCustodyPhase(value evidencelifecycle.Phase) custody.Phase {
	if value == evidencelifecycle.Authorized {
		return custody.Authorized
	}
	return custody.Completed
}
func toCustodyReference(value evidencelifecycle.EvidenceReference) custody.EvidenceReference {
	return custody.EvidenceReference{Artifact: value.Artifact, Manifest: value.Manifest,
		ManifestProvenanceDigest: value.ManifestProvenanceDigest,
		IngestionReceiptDigest:   value.IngestionReceiptDigest}
}
func toCustodyHead(value evidencelifecycle.CustodyHead) custody.Head {
	return custody.Head{Case: value.Case, Sequence: value.Sequence, ChainHash: value.ChainHash,
		LastRecordAt: clone(value.LastRecordAt)}
}
func toLifecycleHead(value custody.Head) evidencelifecycle.CustodyHead {
	return evidencelifecycle.CustodyHead{Case: value.Case, Sequence: value.Sequence, ChainHash: value.ChainHash,
		LastRecordAt: clone(value.LastRecordAt)}
}
func validCustodyHead(value custody.Head, scope domain.CaseRef) bool {
	return value.Case == scope && digestPattern.MatchString(value.ChainHash) &&
		(value.Sequence == 0 && value.ChainHash == custody.GenesisHash && value.LastRecordAt == nil ||
			value.Sequence > 0 && value.ChainHash != custody.GenesisHash && value.LastRecordAt != nil)
}
func sameHead(left, right custody.Head) bool {
	if left.Case != right.Case || left.Sequence != right.Sequence || left.ChainHash != right.ChainHash ||
		(left.LastRecordAt == nil) != (right.LastRecordAt == nil) {
		return false
	}
	return left.LastRecordAt == nil || left.LastRecordAt.Equal(*right.LastRecordAt)
}

func custodyError(ctx context.Context, reason string, err error) error {
	if ctx.Err() != nil {
		return contextError(ctx.Err())
	}
	switch custody.CodeOf(err) {
	case custody.InvalidInput:
		return lifecycleError(evidencelifecycle.InvalidInput, reason, false)
	case custody.Denied:
		return lifecycleError(evidencelifecycle.Denied, reason, false)
	case custody.NotFound:
		return lifecycleError(evidencelifecycle.NotFound, reason, false)
	case custody.Conflict:
		return lifecycleError(evidencelifecycle.Conflict, reason, true)
	case custody.Canceled:
		return lifecycleError(evidencelifecycle.Canceled, reason, false)
	case custody.Timeout:
		return lifecycleError(evidencelifecycle.Timeout, reason, true)
	default:
		return lifecycleError(evidencelifecycle.Unavailable, reason, true)
	}
}
