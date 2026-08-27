package queryevidence

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
)

type EncryptedEvidenceIngestor interface {
	Execute(context.Context, evidenceingest.Command, evidenceingest.Source) (evidenceingest.Result, error)
}

type IngestProfile struct {
	KeyProfile       string
	KeyProfileDigest string
	Transport        evidenceingest.TransportContext
}

type EvidenceIngestAdapter struct {
	ingestor EncryptedEvidenceIngestor
	profile  IngestProfile
}

func NewEvidenceIngestAdapter(ingestor EncryptedEvidenceIngestor, profile IngestProfile) (*EvidenceIngestAdapter, error) {
	if ingestor == nil || !tokenPattern.MatchString(profile.KeyProfile) || !validDigest(profile.KeyProfileDigest) {
		return nil, newError(InvalidInput, "ingest_adapter_configuration_invalid", nil)
	}
	if _, err := evidenceingest.TransportBindingDigest(profile.Transport); err != nil {
		return nil, newError(InvalidInput, "ingest_adapter_configuration_invalid", err)
	}
	return &EvidenceIngestAdapter{ingestor: ingestor, profile: profile}, nil
}

func (adapter *EvidenceIngestAdapter) IngestNativeQuery(ctx context.Context, request ArtifactRequest, source Source) (ArtifactBinding, error) {
	identity := "coh-query:" + request.QueryDigest + ":" + request.ExpectedDigest
	command := evidenceingest.Command{SchemaVersion: evidenceingest.CommandSchemaVersion, ContractVersion: evidenceingest.ContractVersion,
		RequestID: request.RequestID, IdempotencyKey: request.IdempotencyKey, Case: request.Case,
		ActorID: request.ActorID, ActorRevision: request.ActorRevision, ExpectedDigest: request.ExpectedDigest,
		ExpectedLength: request.ExpectedLength, MediaType: request.MediaType, Classification: request.Classification,
		Source: evidenceingest.SourceInput{Kind: evidenceingest.QuerySource, Identity: identity,
			IdentityDigest: evidenceingest.SourceIdentityDigest(identity), CollectionMethod: "coh_query_runtime",
			CollectionMethodVersion: ContractVersion, CollectedAt: request.CollectedAt},
		Components: []evidenceingest.ComponentVersion{{Kind: evidenceingest.QueryComponent, Name: "query-runtime",
			Version: ContractVersion, Digest: request.QueryDigest}},
		KeyProfile: adapter.profile.KeyProfile, KeyProfileDigest: adapter.profile.KeyProfileDigest,
		PolicyDigest: request.PolicyDigest, Transport: adapter.profile.Transport, Deadline: request.Deadline}
	result, err := adapter.ingestor.Execute(ctx, command, source)
	if err != nil {
		return ArtifactBinding{}, err
	}
	if _, err = evidenceingest.CanonicalReceipt(result.Receipt); err != nil || result.Artifact.Digest != request.ExpectedDigest ||
		result.Artifact.Length != request.ExpectedLength || result.Artifact.MediaType != request.MediaType ||
		result.Artifact.Classification != request.Classification || result.Receipt.Case != request.Case ||
		result.Receipt.ActorID != request.ActorID || result.Receipt.ActorRevision != request.ActorRevision ||
		result.Receipt.Artifact != result.Artifact || result.Receipt.Manifest != result.Manifest {
		return ArtifactBinding{}, newError(Conflict, "evidence_ingest_result_invalid", nil)
	}
	return ArtifactBinding{Artifact: artifactRef(result.Artifact), Manifest: artifactRef(result.Manifest),
		ManifestProvenanceDigest: result.Receipt.ManifestProvenanceDigest,
		IngestionReceiptDigest:   result.Receipt.ReceiptDigest}, nil
}

func artifactRef(value domain.ArtifactRef) ArtifactRef {
	return ArtifactRef{Digest: value.Digest, MediaType: value.MediaType, Classification: value.Classification, Length: value.Length}
}

var _ NativeQueryIngestor = (*EvidenceIngestAdapter)(nil)
