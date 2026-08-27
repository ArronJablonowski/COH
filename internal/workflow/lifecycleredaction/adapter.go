// Package lifecycleredaction independently verifies governed redaction
// ancestry for evidence lifecycle export and deletion operations.
package lifecycleredaction

import (
	"context"
	"regexp"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/custody"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Repository interface {
	ResolveReceipt(context.Context, domain.CaseRef, string) (redaction.Receipt, bool, error)
	ResolveRecord(context.Context, domain.CaseRef, string) (redaction.Record, bool, error)
}

type IngestionResolver interface {
	ResolveReceipt(context.Context, domain.CaseRef, string) (evidenceingest.Receipt, bool, error)
}

type MappingResolver interface {
	ResolveRedactionMapping(context.Context, evidenceingest.Receipt) (redaction.Mapping, error)
}

type CustodyResolver interface {
	ResolveReceipt(context.Context, domain.CaseRef, string) (custody.Receipt, bool, error)
}

type CustodyVerifier interface {
	VerifyRedaction(context.Context, redaction.CustodyRequest, redaction.CustodyProof) error
}

type Auditor interface {
	VerifyRedactionEvent(context.Context, domain.CaseRef, string, string) (redaction.AuditProof, error)
}

type Adapter struct {
	repository Repository
	ingestion  IngestionResolver
	mappings   MappingResolver
	custody    CustodyResolver
	verifier   CustodyVerifier
	auditor    Auditor
}

func New(repository Repository, ingestion IngestionResolver, mappings MappingResolver,
	custodyResolver CustodyResolver, custodyVerifier CustodyVerifier, auditor Auditor) (*Adapter, error) {
	if repository == nil || ingestion == nil || mappings == nil || custodyResolver == nil ||
		custodyVerifier == nil || auditor == nil {
		return nil, lifecycleError(evidencelifecycle.InvalidInput, "redaction_dependencies_required", false)
	}
	return &Adapter{repository: repository, ingestion: ingestion, mappings: mappings,
		custody: custodyResolver, verifier: custodyVerifier, auditor: auditor}, nil
}

var _ evidencelifecycle.RedactionResolver = (*Adapter)(nil)

func (adapter *Adapter) VerifyRedactionReceipts(ctx context.Context, scope domain.CaseRef,
	evidence evidencelifecycle.VerifiedEvidenceSet) ([]evidencelifecycle.RedactionProof, error) {
	if err := ctx.Err(); err != nil {
		return nil, lifecycleError(contextCode(err), "redaction_verification_canceled", false)
	}
	if evidence.Case != scope {
		return nil, lifecycleError(evidencelifecycle.InvalidInput, "redaction_scope_invalid", false)
	}
	proofs := make([]evidencelifecycle.RedactionProof, 0)
	seen := make(map[string]struct{})
	for index, artifact := range evidence.Artifacts {
		if artifact.Role != evidencelifecycle.DerivedArtifact {
			continue
		}
		if artifact.RedactionReceiptDigest == nil || artifact.MappingDigest == nil ||
			!digestPattern.MatchString(*artifact.RedactionReceiptDigest) ||
			!digestPattern.MatchString(*artifact.MappingDigest) {
			return nil, denied("redaction_artifact_binding_invalid")
		}
		if _, duplicate := seen[artifact.Reference.Artifact.Digest]; duplicate {
			return nil, denied("redaction_artifact_duplicate")
		}
		proof, err := adapter.verifyOne(ctx, scope, evidence.Artifacts[:index], artifact)
		if err != nil {
			return nil, err
		}
		seen[artifact.Reference.Artifact.Digest] = struct{}{}
		proofs = append(proofs, proof)
	}
	return proofs, nil
}

func (adapter *Adapter) verifyOne(ctx context.Context, scope domain.CaseRef,
	prior []evidencelifecycle.ManifestArtifact, artifact evidencelifecycle.ManifestArtifact) (
	evidencelifecycle.RedactionProof, error) {
	receipt, found, err := adapter.repository.ResolveReceipt(ctx, scope, *artifact.RedactionReceiptDigest)
	if err != nil {
		return evidencelifecycle.RedactionProof{}, dependency(ctx, "redaction_receipt_unavailable", err)
	}
	if !found {
		return evidencelifecycle.RedactionProof{}, lifecycleError(evidencelifecycle.NotFound,
			"redaction_receipt_not_found", false)
	}
	record, found, err := adapter.repository.ResolveRecord(ctx, scope, receipt.RedactionID)
	if err != nil {
		return evidencelifecycle.RedactionProof{}, dependency(ctx, "redaction_record_unavailable", err)
	}
	if !found || !receiptRecordMatches(receipt, record) || receipt.ReceiptDigest != *artifact.RedactionReceiptDigest ||
		toLifecycleReference(receipt.Derived) != artifact.Reference || receipt.MappingDigest != *artifact.MappingDigest ||
		!sourceInPrior(record.Command.Source, artifact, prior) {
		return evidencelifecycle.RedactionProof{}, denied("redaction_receipt_binding_invalid")
	}
	if _, err = adapter.verifyIngestion(ctx, scope, record.Derived, record.DerivedIngestionReceiptDigest); err != nil {
		return evidencelifecycle.RedactionProof{}, err
	}
	mappingReceipt, err := adapter.verifyIngestion(ctx, scope, record.MappingReference,
		record.MappingIngestionReceiptDigest)
	if err != nil {
		return evidencelifecycle.RedactionProof{}, err
	}
	mapping, err := adapter.mappings.ResolveRedactionMapping(ctx, mappingReceipt)
	if err != nil {
		if ctx.Err() != nil {
			return evidencelifecycle.RedactionProof{}, dependency(ctx, "redaction_mapping_unavailable", err)
		}
		return evidencelifecycle.RedactionProof{}, denied("redaction_mapping_invalid")
	}
	if !mappingMatchesRecord(mapping, record) {
		return evidencelifecycle.RedactionProof{}, denied("redaction_mapping_binding_invalid")
	}
	if err = adapter.verifyCustody(ctx, record); err != nil {
		return evidencelifecycle.RedactionProof{}, err
	}
	proof, err := adapter.auditor.VerifyRedactionEvent(ctx, scope,
		redaction.CompletedAuditEventID(record.RedactionID), record.AuditEventDigest)
	if err != nil {
		return evidencelifecycle.RedactionProof{}, dependency(ctx, "redaction_audit_unavailable", err)
	}
	if proof.EventDigest != record.AuditEventDigest || proof.Sequence == 0 || !digestPattern.MatchString(proof.ChainHash) {
		return evidencelifecycle.RedactionProof{}, denied("redaction_audit_invalid")
	}
	return evidencelifecycle.RedactionProof{ArtifactDigest: record.Derived.Artifact.Digest,
		ReceiptDigest: receipt.ReceiptDigest, MappingDigest: mapping.MappingDigest,
		ProvenanceDigest: record.ProvenanceDigest}, nil
}

func (adapter *Adapter) verifyIngestion(ctx context.Context, scope domain.CaseRef,
	want redaction.EvidenceReference, digest string) (evidenceingest.Receipt, error) {
	receipt, found, err := adapter.ingestion.ResolveReceipt(ctx, scope, digest)
	if err != nil {
		return evidenceingest.Receipt{}, dependency(ctx, "redaction_ingestion_unavailable", err)
	}
	if !found {
		return evidenceingest.Receipt{}, lifecycleError(evidencelifecycle.NotFound,
			"redaction_ingestion_not_found", false)
	}
	if _, err = evidenceingest.CanonicalReceipt(receipt); err != nil || receipt.Case != scope ||
		receipt.ReceiptDigest != digest || receipt.Artifact != want.Artifact || receipt.Manifest != want.Manifest ||
		receipt.ManifestProvenanceDigest != want.ManifestProvenanceDigest {
		return evidenceingest.Receipt{}, denied("redaction_ingestion_binding_invalid")
	}
	return receipt, nil
}

func (adapter *Adapter) verifyCustody(ctx context.Context, record redaction.Record) error {
	receipt, found, err := adapter.custody.ResolveReceipt(ctx, record.Case, record.CustodyReceiptDigest)
	if err != nil {
		return dependency(ctx, "redaction_custody_unavailable", err)
	}
	if !found {
		return lifecycleError(evidencelifecycle.NotFound, "redaction_custody_not_found", false)
	}
	if _, err = custody.CanonicalReceipt(receipt); err != nil || receipt.Case != record.Case ||
		receipt.ReceiptDigest != record.CustodyReceiptDigest {
		return denied("redaction_custody_binding_invalid")
	}
	request := redaction.CustodyRequest{Command: record.Command, Derived: record.Derived,
		MappingDigest: record.MappingDigest, ApprovalDigest: record.ApprovalUseDigest,
		DecisionDigest: record.DecisionDigest, ExpectedHead: record.Command.ExpectedCustodyHead,
		Deadline: record.Command.Deadline}
	proof := redaction.CustodyProof{ReceiptDigest: receipt.ReceiptDigest, RecordDigest: receipt.RecordDigest,
		ChainHash: receipt.ChainHash, Sequence: receipt.Sequence, AuditDigest: receipt.AuditEventDigest}
	if err = adapter.verifier.VerifyRedaction(ctx, request, proof); err != nil {
		return dependency(ctx, "redaction_custody_verification_failed", err)
	}
	return nil
}

func receiptRecordMatches(receipt redaction.Receipt, record redaction.Record) bool {
	if _, err := redaction.CanonicalReceipt(receipt); err != nil {
		return false
	}
	if _, err := redaction.CanonicalRecord(record); err != nil {
		return false
	}
	idempotency, err := redaction.IdempotencyBindingDigest(record.Command.IdempotencyKey)
	return err == nil && receipt.Case == record.Case && receipt.RequestID == record.Command.RequestID &&
		receipt.IdempotencyDigest == idempotency && receipt.IntentDigest == record.IntentDigest &&
		receipt.RedactionID == record.RedactionID &&
		receipt.RecordDigest == record.RecordDigest && receipt.Derived == record.Derived &&
		receipt.MappingReference == record.MappingReference && receipt.MappingDigest == record.MappingDigest &&
		receipt.CustodyReceiptDigest == record.CustodyReceiptDigest &&
		receipt.AuditEventDigest == record.AuditEventDigest && receipt.ProvenanceDigest == record.ProvenanceDigest &&
		receipt.CreatedAt.Equal(record.CreatedAt)
}

func sourceInPrior(source redaction.EvidenceReference, derived evidencelifecycle.ManifestArtifact,
	prior []evidencelifecycle.ManifestArtifact) bool {
	want := toLifecycleReference(source)
	for _, candidate := range prior {
		if candidate.Reference == want && contains(derived.ParentArtifactDigests, want.Artifact.Digest) &&
			contains(derived.ParentManifestDigests, want.Manifest.Digest) {
			return true
		}
	}
	return false
}

func mappingMatchesRecord(mapping redaction.Mapping, record redaction.Record) bool {
	return redaction.ValidateMapping(mapping) == nil && mapping.Case == record.Case &&
		mapping.Source == record.Command.Source && mapping.DerivedArtifact == record.Derived.Artifact &&
		mapping.MappingDigest == record.MappingDigest && mapping.PlanDigest == record.PlanDigest &&
		mapping.RuleDigest == record.Command.RuleDigest && mapping.ReasonDigest == record.Command.ReasonDigest &&
		record.PreviousProvenanceDigest == record.Command.Source.ManifestProvenanceDigest &&
		mapping.PreviousProvenanceDigest == record.PreviousProvenanceDigest
}

func toLifecycleReference(value redaction.EvidenceReference) evidencelifecycle.EvidenceReference {
	return evidencelifecycle.EvidenceReference{Artifact: value.Artifact, Manifest: value.Manifest,
		ManifestProvenanceDigest: value.ManifestProvenanceDigest,
		IngestionReceiptDigest:   value.IngestionReceiptDigest}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func dependency(ctx context.Context, reason string, err error) error {
	if ctx.Err() != nil {
		return lifecycleError(contextCode(ctx.Err()), reason, false)
	}
	return lifecycleError(evidencelifecycle.Unavailable, reason, true)
}

func contextCode(err error) evidencelifecycle.ErrorCode {
	if err == context.DeadlineExceeded {
		return evidencelifecycle.Timeout
	}
	return evidencelifecycle.Canceled
}

func denied(reason string) error {
	return lifecycleError(evidencelifecycle.Denied, reason, false)
}

func lifecycleError(code evidencelifecycle.ErrorCode, reason string, retryable bool) error {
	return &evidencelifecycle.Error{Code: code, Reason: reason, Retryable: retryable}
}
