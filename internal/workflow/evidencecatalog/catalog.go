package evidencecatalog

import (
	"bytes"
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
	workflowbase "github.com/ArronJablonowski/COH/internal/workflow"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

func (catalog *Catalog) Register(ctx context.Context,
	registration Registration) (evidencelifecycle.VerifiedEvidenceSet, bool, error) {
	verified, err := catalog.verify(ctx, registration)
	if err != nil {
		return evidencelifecycle.VerifiedEvidenceSet{}, false, err
	}
	if existing, found, loadErr := catalog.load(ctx, registration.Case,
		verified.ArtifactSetDigest); loadErr != nil {
		return evidencelifecycle.VerifiedEvidenceSet{}, false, loadErr
	} else if found {
		resolved, resolveErr := catalog.reverify(ctx, existing)
		if resolveErr != nil || !sameSet(resolved, verified) {
			if resolveErr != nil {
				return evidencelifecycle.VerifiedEvidenceSet{}, false, resolveErr
			}
			return evidencelifecycle.VerifiedEvidenceSet{}, false,
				lifecycleError(evidencelifecycle.Denied, "catalog_changed_replay", false)
		}
		return cloneSet(resolved), true, nil
	}
	key := recordKey(registration.Case, verified.ArtifactSetDigest)
	metadata, err := catalogMetadata(key, verified)
	if err != nil {
		return evidencelifecycle.VerifiedEvidenceSet{}, false, err
	}
	transactionKey := rawDigest([]byte("COH-EVIDENCE-ARTIFACT-SET-TRANSACTION-V1\x00" +
		registration.Case.OrganizationID + "\x00" + registration.Case.TenantID + "\x00" +
		registration.Case.CaseID + "\x00" + verified.ArtifactSetDigest))
	result, err := catalog.repository.Transact(ctx, workflowbase.Transaction{
		ContractVersion: workflowbase.StorageContractVersion, IdempotencyKey: transactionKey,
		Mutations: []workflowbase.Mutation{{Kind: workflowbase.MutationPut, Key: key,
			ExpectedRevision: 0, Record: &metadata}},
	})
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageConflict {
			existing, resolveErr := catalog.ResolveEvidenceSet(ctx, registration.Case,
				verified.ArtifactSetDigest)
			if resolveErr == nil && sameSet(existing, verified) {
				return cloneSet(existing), true, nil
			}
			if resolveErr != nil {
				return evidencelifecycle.VerifiedEvidenceSet{}, false, resolveErr
			}
			return evidencelifecycle.VerifiedEvidenceSet{}, false,
				lifecycleError(evidencelifecycle.Denied, "catalog_changed_replay", false)
		}
		return evidencelifecycle.VerifiedEvidenceSet{}, false, storageError(err, "catalog_register")
	}
	if result.Replayed {
		existing, resolveErr := catalog.ResolveEvidenceSet(ctx, registration.Case, verified.ArtifactSetDigest)
		if resolveErr != nil || !sameSet(existing, verified) {
			if resolveErr != nil {
				return evidencelifecycle.VerifiedEvidenceSet{}, false, resolveErr
			}
			return evidencelifecycle.VerifiedEvidenceSet{}, false,
				lifecycleError(evidencelifecycle.Denied, "catalog_replay_invalid", false)
		}
		return cloneSet(existing), true, nil
	}
	return cloneSet(verified), false, nil
}

func (catalog *Catalog) ResolveEvidenceSet(ctx context.Context, scope domain.CaseRef,
	artifactSetDigest string) (evidencelifecycle.VerifiedEvidenceSet, error) {
	if err := contextError(ctx); err != nil {
		return evidencelifecycle.VerifiedEvidenceSet{}, err
	}
	stored, found, err := catalog.load(ctx, scope, artifactSetDigest)
	if err != nil {
		return evidencelifecycle.VerifiedEvidenceSet{}, err
	}
	if !found {
		return evidencelifecycle.VerifiedEvidenceSet{},
			lifecycleError(evidencelifecycle.NotFound, "catalog_not_found", false)
	}
	return catalog.reverify(ctx, stored)
}

func (catalog *Catalog) reverify(ctx context.Context,
	stored evidencelifecycle.VerifiedEvidenceSet) (evidencelifecycle.VerifiedEvidenceSet, error) {
	verified, err := catalog.verify(ctx, Registration{Case: stored.Case, Artifacts: stored.Artifacts})
	if err != nil {
		return evidencelifecycle.VerifiedEvidenceSet{}, err
	}
	if !sameSet(stored, verified) {
		return evidencelifecycle.VerifiedEvidenceSet{},
			lifecycleError(evidencelifecycle.Denied, "catalog_record_binding_invalid", false)
	}
	return cloneSet(verified), nil
}

func (catalog *Catalog) load(ctx context.Context, scope domain.CaseRef,
	artifactSetDigest string) (evidencelifecycle.VerifiedEvidenceSet, bool, error) {
	if !validCase(scope) || !digestPattern.MatchString(artifactSetDigest) {
		return evidencelifecycle.VerifiedEvidenceSet{}, false,
			lifecycleError(evidencelifecycle.InvalidInput, "catalog_scope_invalid", false)
	}
	key := recordKey(scope, artifactSetDigest)
	metadata, err := catalog.repository.Get(ctx, key)
	if err != nil {
		if workflowbase.StorageCode(err) == workflowbase.StorageNotFound {
			return evidencelifecycle.VerifiedEvidenceSet{}, false, nil
		}
		return evidencelifecycle.VerifiedEvidenceSet{}, false, storageError(err, "catalog_load")
	}
	var envelope repositoryEnvelope
	if err = decode(metadata.Canonical, &envelope); err != nil || envelope.Schema != repositorySchema ||
		envelope.Kind != repositoryKind || envelope.ID != key.ID || envelope.OrganizationID != scope.OrganizationID ||
		envelope.TenantID != scope.TenantID || envelope.CaseID != scope.CaseID || envelope.Revision != 1 ||
		envelope.EntryType != "artifact_set" || metadata.Key != key || metadata.Schema != repositorySchema ||
		metadata.Revision != 1 || metadata.Digest != rawDigest(metadata.Canonical) {
		return evidencelifecycle.VerifiedEvidenceSet{}, false,
			lifecycleError(evidencelifecycle.Denied, "catalog_envelope_invalid", false)
	}
	var wire recordWire
	if err = decode(envelope.Data, &wire); err != nil || wire.SchemaVersion != recordSchema ||
		wire.ContractVersion != recordContract {
		return evidencelifecycle.VerifiedEvidenceSet{}, false,
			lifecycleError(evidencelifecycle.Denied, "catalog_record_invalid", false)
	}
	value := recordFromWire(wire)
	if value.Case != scope || value.ArtifactSetDigest != artifactSetDigest {
		return evidencelifecycle.VerifiedEvidenceSet{}, false,
			lifecycleError(evidencelifecycle.Denied, "catalog_record_scope_invalid", false)
	}
	return value, true, nil
}

func catalogMetadata(key workflowbase.RecordKey,
	value evidencelifecycle.VerifiedEvidenceSet) (workflowbase.MetadataRecord, error) {
	data, err := encode(recordToWire(value))
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	envelope := repositoryEnvelope{Schema: repositorySchema, Kind: repositoryKind, ID: key.ID,
		OrganizationID: key.Case.OrganizationID, TenantID: key.Case.TenantID, CaseID: key.Case.CaseID,
		Revision: 1, EntryType: "artifact_set", Data: data}
	canonical, err := encode(envelope)
	if err != nil {
		return workflowbase.MetadataRecord{}, err
	}
	return workflowbase.MetadataRecord{Key: key, Schema: repositorySchema, Revision: 1,
		Canonical: canonical, Digest: rawDigest(canonical)}, nil
}

func sameSet(left, right evidencelifecycle.VerifiedEvidenceSet) bool {
	leftCanonical, leftErr := encode(recordToWire(left))
	rightCanonical, rightErr := encode(recordToWire(right))
	return leftErr == nil && rightErr == nil && bytes.Equal(leftCanonical, rightCanonical)
}

func cloneSet(value evidencelifecycle.VerifiedEvidenceSet) evidencelifecycle.VerifiedEvidenceSet {
	return evidencelifecycle.VerifiedEvidenceSet{Case: value.Case, Artifacts: cloneArtifacts(value.Artifacts),
		Components:        append([]evidencelifecycle.Component(nil), value.Components...),
		ArtifactSetDigest: value.ArtifactSetDigest, LineageDigest: value.LineageDigest,
		ComponentSetDigest: value.ComponentSetDigest}
}
