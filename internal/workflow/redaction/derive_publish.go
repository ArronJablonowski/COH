package redaction

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/ArronJablonowski/COH/internal/domain"
)

type derivationService struct {
	transformer Transformer
	publisher   Publisher
}

type publicationResult struct {
	Derivation Derivation
	Derived    PublishedEvidence
	Mapping    PublishedEvidence
}

func newDerivationService(transformer Transformer, publisher Publisher) (*derivationService, error) {
	if transformer == nil || publisher == nil {
		return nil, newError(InvalidInput, "derivation_dependencies_required", false, nil)
	}
	return &derivationService{transformer, publisher}, nil
}

func (service *derivationService) deriveAndPublish(ctx context.Context, state authorizedState) (publicationResult, error) {
	request := DerivationRequest{Case: state.Command.Case, Source: state.Command.Source, Verified: state.Source,
		Rule: cloneRule(state.Rule), Plan: clonePlan(state.Plan), CreatedAt: state.AuthorizedAt,
		PreviousProvenanceDigest: state.Command.Source.ManifestProvenanceDigest, Deadline: state.Command.Deadline}
	derivation, derivedSource, err := service.transformer.Derive(ctx, request)
	if err != nil {
		return publicationResult{}, mapDependency(ctx, "transform_unavailable", err)
	}
	want, digestErr := DerivationBindingDigest(request, derivation)
	if digestErr != nil || want != derivation.DerivationDigest || derivedSource == nil {
		return publicationResult{}, newError(Denied, string(ReasonTransformInvalid), false, digestErr)
	}
	derivedRequest := publicationRequest(state, DerivedPublication, derivation.DerivedArtifact,
		[]EvidenceReference{state.Command.Source})
	derived, err := service.publisher.Publish(ctx, derivedRequest, derivedSource)
	if err != nil {
		return publicationResult{}, mapDependency(ctx, "derived_publish_unavailable", err)
	}
	if !publishedMatches(derived, derivation.DerivedArtifact) {
		return publicationResult{}, newError(Denied, "derived_publication_invalid", false, nil)
	}
	mappingBytes, err := CanonicalMapping(derivation.Mapping)
	if err != nil {
		return publicationResult{}, err
	}
	mappingArtifact := domain.ArtifactRef{Digest: contentDigest(mappingBytes), MediaType: mappingMediaType,
		Classification: state.Command.Source.Artifact.Classification, Length: int64(len(mappingBytes))}
	mappingRequest := publicationRequest(state, MappingPublication, mappingArtifact,
		[]EvidenceReference{state.Command.Source})
	mappingSource := &sensitiveBytes{value: mappingBytes}
	defer mappingSource.clear()
	mapping, err := service.publisher.Publish(ctx, mappingRequest, mappingSource)
	if err != nil {
		return publicationResult{}, mapDependency(ctx, "mapping_publish_unavailable", err)
	}
	if !publishedMatches(mapping, mappingArtifact) {
		return publicationResult{}, newError(Denied, "mapping_publication_invalid", false, nil)
	}
	return publicationResult{derivation, derived, mapping}, nil
}

func publicationRequest(state authorizedState, role PublicationRole, artifact domain.ArtifactRef,
	parents []EvidenceReference) PublicationRequest {
	suffix := string(role)
	return PublicationRequest{Role: role, RequestID: deterministicUUID("COH-REDACTION-PUBLICATION-ID-V1\x00",
		state.Command.RequestID+"\x00"+suffix), IdempotencyKey: state.Command.IdempotencyKey + ":" + suffix,
		Case: state.Command.Case, ActorID: state.Command.ActorID, ActorRevision: state.Command.ActorRevision,
		ExpectedArtifact: artifact, Parents: append([]EvidenceReference(nil), parents...),
		SourceIdentityDigest: state.Source.SourceIdentityDigest, RuleDigest: state.Rule.RuleDigest,
		PlanDigest: state.Plan.PlanDigest, PolicyDigest: state.Command.PolicyDigest, KeyProfile: state.Command.KeyProfile,
		KeyProfileDigest: state.Command.KeyProfileDigest, CreatedAt: state.AuthorizedAt, Deadline: state.Command.Deadline}
}

func publishedMatches(value PublishedEvidence, artifact domain.ArtifactRef) bool {
	return validEvidence(value.Reference) && value.Reference.Artifact == artifact &&
		value.ReceiptDigest == value.Reference.IngestionReceiptDigest
}

type sensitiveBytes struct {
	value  []byte
	offset int
}

func (source *sensitiveBytes) ReadContext(ctx context.Context, destination []byte) (int, error) {
	if err := contextError(ctx); err != nil {
		source.clear()
		return 0, err
	}
	if source.offset == len(source.value) {
		source.clear()
		return 0, io.EOF
	}
	count := copy(destination, source.value[source.offset:])
	source.offset += count
	return count, nil
}
func (source *sensitiveBytes) Close() error { source.clear(); return nil }
func (source *sensitiveBytes) clear() {
	for index := range source.value {
		source.value[index] = 0
	}
	source.value = nil
	source.offset = 0
}

func contentDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func deterministicUUID(domainName, input string) string {
	sum := sha256.Sum256([]byte(domainName + input))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
