package lifecycledisposition

import (
	"context"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func New(receipts ReceiptResolver, cas EncryptedCAS, repository workflowbase.MetadataStore,
	clock Clock) (*Adapter, error) {
	if receipts == nil || cas == nil || repository == nil || clock == nil {
		return nil, lifecycleError(evidencelifecycle.InvalidInput, "disposition_dependencies_required", false)
	}
	return &Adapter{receipts: receipts, cas: cas, repository: repository, clock: clock}, nil
}

var _ evidencelifecycle.Disposer = (*Adapter)(nil)

func (adapter *Adapter) DisposeEvidence(ctx context.Context,
	request evidencelifecycle.DispositionRequest) (evidencelifecycle.DispositionAttestation, error) {
	requestDigest, err := dispositionRequestDigest(request)
	if err != nil {
		return evidencelifecycle.DispositionAttestation{}, err
	}
	stored, found, err := adapter.loadOperation(ctx, request.Case, request.OperationID)
	if err != nil {
		return evidencelifecycle.DispositionAttestation{}, err
	}
	if found {
		if stored.RequestDigest != requestDigest {
			return evidencelifecycle.DispositionAttestation{}, lifecycleError(evidencelifecycle.Denied,
				"disposition_changed_replay", false)
		}
	} else {
		stored, err = adapter.buildPlan(ctx, request, requestDigest)
		if err != nil {
			return evidencelifecycle.DispositionAttestation{}, err
		}
		stored, err = adapter.savePlan(ctx, stored)
		if err != nil {
			return evidencelifecycle.DispositionAttestation{}, err
		}
	}
	if stored.Attestation != nil {
		return *stored.Attestation, nil
	}
	for _, object := range stored.Objects {
		if _, disposeErr := adapter.cas.DisposePublished(ctx, object.Reference,
			object.EncryptedObjectDigest, object.KeyRevision); disposeErr != nil {
			return evidencelifecycle.DispositionAttestation{}, dependencyError(ctx,
				"disposition_object_unavailable", disposeErr)
		}
	}
	attestation := buildAttestation(stored)
	attestation.AttestationDigest, err = evidencelifecycle.DispositionBindingDigest(attestation)
	if err != nil {
		return evidencelifecycle.DispositionAttestation{}, lifecycleError(evidencelifecycle.Denied,
			"disposition_attestation_invalid", false)
	}
	stored.Attestation = &attestation
	stored, err = adapter.saveAttestation(ctx, stored)
	if err != nil {
		return evidencelifecycle.DispositionAttestation{}, err
	}
	return *stored.Attestation, nil
}

func (adapter *Adapter) RecoverDisposition(ctx context.Context, scope domain.CaseRef,
	attestationDigest string) (evidencelifecycle.DispositionAttestation, bool, error) {
	if !validCase(scope) || !digestPattern.MatchString(attestationDigest) {
		return evidencelifecycle.DispositionAttestation{}, false,
			lifecycleError(evidencelifecycle.InvalidInput, "disposition_lookup_invalid", false)
	}
	stored, found, err := adapter.loadDigest(ctx, scope, attestationDigest)
	if err != nil || !found {
		return evidencelifecycle.DispositionAttestation{}, found, err
	}
	return *stored.Attestation, true, nil
}

func (adapter *Adapter) buildPlan(ctx context.Context, request evidencelifecycle.DispositionRequest,
	requestDigest string) (storedOperation, error) {
	now := adapter.clock.Now().UTC()
	if !validNow(now) || !request.Deadline.After(now) {
		return storedOperation{}, lifecycleError(evidencelifecycle.Timeout, "disposition_deadline_elapsed", false)
	}
	objects := make([]plannedObject, 0, len(request.Evidence.Artifacts))
	for _, artifact := range request.Evidence.Artifacts {
		reference := artifact.Reference
		receipt, found, err := adapter.receipts.ResolveReceipt(ctx, request.Case,
			reference.IngestionReceiptDigest)
		if err != nil {
			return storedOperation{}, dependencyError(ctx, "disposition_receipt_unavailable", err)
		}
		if _, canonicalErr := evidenceingest.CanonicalReceipt(receipt); !found || canonicalErr != nil ||
			receipt.ReceiptDigest != reference.IngestionReceiptDigest || receipt.Case != request.Case ||
			receipt.Artifact != reference.Artifact || receipt.Manifest != reference.Manifest ||
			receipt.ManifestProvenanceDigest != reference.ManifestProvenanceDigest {
			return storedOperation{}, lifecycleError(evidencelifecycle.Denied,
				"disposition_receipt_invalid", false)
		}
		object, err := adapter.cas.Resolve(ctx, receipt.EncryptedArtifact)
		if err != nil {
			return storedOperation{}, dependencyError(ctx, "disposition_object_resolution_unavailable", err)
		}
		objectDigest, err := evidenceingest.EncryptedObjectBindingDigest(object)
		if err != nil || object.Status != evidenceingest.Published || object.Case != request.Case ||
			object.PlaintextDigest != reference.Artifact.Digest || object.PlaintextLength != reference.Artifact.Length ||
			object.MediaType != reference.Artifact.MediaType || object.Classification != reference.Artifact.Classification ||
			object.KeyRevision == 0 {
			return storedOperation{}, lifecycleError(evidencelifecycle.Denied,
				"disposition_object_invalid", false)
		}
		objects = append(objects, plannedObject{ArtifactDigest: reference.Artifact.Digest,
			IngestionReceiptDigest: reference.IngestionReceiptDigest, Reference: receipt.EncryptedArtifact,
			EncryptedObjectDigest: objectDigest, KeyRevision: object.KeyRevision})
	}
	objects = sortedPlans(objects)
	return storedOperation{Case: request.Case, OperationID: request.OperationID, RequestDigest: requestDigest,
		ArtifactSetDigest:                 request.ArtifactSetDigest,
		AuthorizationCustodyReceiptDigest: request.AuthorizationCustodyReceiptDigest,
		LifecycleReceiptDigest:            request.LifecycleReceiptDigest, AttemptedAt: now, Objects: objects}, nil
}

func buildAttestation(stored storedOperation) evidencelifecycle.DispositionAttestation {
	objects := make([]evidencelifecycle.DispositionObject, len(stored.Objects))
	for index, object := range stored.Objects {
		outcome := evidencelifecycle.DispositionRemoved
		objects[index] = evidencelifecycle.DispositionObject{Ordinal: uint16(index + 1),
			ArtifactDigest: object.ArtifactDigest, EncryptedObjectDigest: object.EncryptedObjectDigest,
			KeyRevision: object.KeyRevision, Outcome: outcome, OutcomeDigest: outcomeDigest(object, outcome)}
	}
	sort.Slice(objects, func(left, right int) bool { return objects[left].ArtifactDigest < objects[right].ArtifactDigest })
	return evidencelifecycle.DispositionAttestation{SchemaVersion: evidencelifecycle.DispositionAttestationSchemaVersion,
		ContractVersion: evidencelifecycle.ContractVersion,
		AttestationID:   deterministicUUID("COH-LIFECYCLE-DISPOSITION-ATTESTATION-V1\x00", stored.RequestDigest),
		Case:            stored.Case, OperationID: stored.OperationID, ArtifactSetDigest: stored.ArtifactSetDigest,
		AuthorizationCustodyReceiptDigest: stored.AuthorizationCustodyReceiptDigest,
		LifecycleReceiptDigest:            stored.LifecycleReceiptDigest, Mechanism: "encrypted_object_removal",
		Objects: objects, AttemptedAt: stored.AttemptedAt, CompletedAt: stored.AttemptedAt}
}

func dependencyError(ctx context.Context, reason string, err error) error {
	if ctx.Err() == context.Canceled {
		return lifecycleError(evidencelifecycle.Canceled, reason, false)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return lifecycleError(evidencelifecycle.Timeout, reason, true)
	}
	if coded, ok := err.(interface{ ErrorCode() string }); ok {
		switch coded.ErrorCode() {
		case "invalid_input":
			return lifecycleError(evidencelifecycle.InvalidInput, reason, false)
		case "denied":
			return lifecycleError(evidencelifecycle.Denied, reason, false)
		case "not_found":
			return lifecycleError(evidencelifecycle.NotFound, reason, false)
		case "conflict":
			return lifecycleError(evidencelifecycle.Conflict, reason, true)
		case "canceled":
			return lifecycleError(evidencelifecycle.Canceled, reason, false)
		case "timeout":
			return lifecycleError(evidencelifecycle.Timeout, reason, true)
		}
	}
	return lifecycleError(evidencelifecycle.Unavailable, reason, true)
}
