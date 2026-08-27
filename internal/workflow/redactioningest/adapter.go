// Package redactioningest adapts governed redaction publication to the sole
// immutable encrypted ingestion owner.
package redactioningest

import (
	"context"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

type Ingestor interface {
	Execute(context.Context, evidenceingest.Command, evidenceingest.Source) (evidenceingest.Result, error)
}

type Adapter struct {
	ingestor  Ingestor
	transport evidenceingest.TransportContext
}

func New(ingestor Ingestor, transport evidenceingest.TransportContext) (*Adapter, error) {
	if ingestor == nil {
		return nil, &redaction.Error{Code: redaction.InvalidInput, Reason: "ingestor_required"}
	}
	if _, err := evidenceingest.TransportBindingDigest(transport); err != nil {
		return nil, &redaction.Error{Code: redaction.InvalidInput, Reason: "transport_invalid"}
	}
	return &Adapter{ingestor: ingestor, transport: transport}, nil
}

func (adapter *Adapter) Publish(ctx context.Context, request redaction.PublicationRequest,
	source redaction.DerivedSource) (redaction.PublishedEvidence, error) {
	if err := redaction.ValidatePublicationRequest(request); err != nil {
		return redaction.PublishedEvidence{}, err
	}
	if source == nil {
		return redaction.PublishedEvidence{}, &redaction.Error{Code: redaction.InvalidInput, Reason: "source_required"}
	}
	defer source.Close()
	parents := append([]redaction.EvidenceReference(nil), request.Parents...)
	sort.Slice(parents, func(left, right int) bool {
		if parents[left].Artifact.Digest == parents[right].Artifact.Digest {
			return parents[left].Manifest.Digest < parents[right].Manifest.Digest
		}
		return parents[left].Artifact.Digest < parents[right].Artifact.Digest
	})
	parentArtifacts := make([]domain.ArtifactRef, len(parents))
	parentManifests := make([]string, len(parents))
	for index, parent := range parents {
		parentArtifacts[index], parentManifests[index] = parent.Artifact, parent.Manifest.Digest
	}
	identity := "coh-redaction:" + request.SourceIdentityDigest + ":" + request.RuleDigest + ":" + request.PlanDigest
	command := evidenceingest.Command{SchemaVersion: evidenceingest.CommandSchemaVersion,
		ContractVersion: evidenceingest.ContractVersion, RequestID: request.RequestID,
		IdempotencyKey: request.IdempotencyKey, Case: request.Case, ActorID: request.ActorID,
		ActorRevision: request.ActorRevision, ExpectedDigest: request.ExpectedArtifact.Digest,
		ExpectedLength: request.ExpectedArtifact.Length, MediaType: request.ExpectedArtifact.MediaType,
		Classification: request.ExpectedArtifact.Classification,
		Source: evidenceingest.SourceInput{Kind: evidenceingest.DerivedSource, Identity: identity,
			IdentityDigest: evidenceingest.SourceIdentityDigest(identity), CollectionMethod: "governed_redaction",
			CollectionMethodVersion: redaction.ContractVersion, CollectedAt: request.CreatedAt},
		ParentArtifacts: parentArtifacts, ParentManifestDigests: parentManifests,
		Components: []evidenceingest.ComponentVersion{}, KeyProfile: request.KeyProfile,
		KeyProfileDigest: request.KeyProfileDigest, PolicyDigest: request.PolicyDigest,
		Transport: adapter.transport, Deadline: request.Deadline}
	result, err := adapter.ingestor.Execute(ctx, command, source)
	if err != nil {
		return redaction.PublishedEvidence{}, err
	}
	if _, err = evidenceingest.CanonicalReceipt(result.Receipt); err != nil || result.Artifact != request.ExpectedArtifact ||
		result.Receipt.Case != request.Case || result.Receipt.ActorID != request.ActorID ||
		result.Receipt.ActorRevision != request.ActorRevision || result.Receipt.Artifact != result.Artifact ||
		result.Receipt.Manifest != result.Manifest || result.Receipt.ReceiptDigest == "" {
		return redaction.PublishedEvidence{}, &redaction.Error{Code: redaction.Denied, Reason: "ingestion_result_invalid"}
	}
	return redaction.PublishedEvidence{Reference: redaction.EvidenceReference{Artifact: result.Artifact,
		Manifest: result.Manifest, ManifestProvenanceDigest: result.Receipt.ManifestProvenanceDigest,
		IngestionReceiptDigest: result.Receipt.ReceiptDigest}, ReceiptDigest: result.Receipt.ReceiptDigest}, nil
}

var _ redaction.Publisher = (*Adapter)(nil)
