package entityresolution

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain/mappingregistry"
)

type ObservationEvidence struct {
	EnvelopeID             string
	EnvelopeDigest         string
	Classification         string
	SourceIdentityDigest   string
	TransformationDigest   string
	ArtifactDigest         string
	RawManifestDigest      string
	IngestReceiptDigest    string
	SourceProvenanceDigest string
	MappingManifestDigest  string
	MappingRevision        uint64
	MappingOutcomeDigest   string
}

type ObservationInput struct {
	ObservationID               string
	OperationID                 string
	Scope                       Scope
	MatchDigest                 string
	DerivationKeyRevision       uint64
	Hint                        mappingregistry.EmittedEntityHint
	Evidence                    ObservationEvidence
	ObservedAt                  string
	SupersedesObservationDigest *string
}

func NewObservation(ctx context.Context, input ObservationInput) (Observation, []byte, string, error) {
	if err := checkContext(ctx); err != nil {
		return Observation{}, nil, "", err
	}
	observation := Observation{
		SchemaVersion: ObservationSchemaVersion, ContractVersion: ContractVersion, MethodVersion: MethodVersion,
		ObservationID: input.ObservationID, OperationID: input.OperationID, Scope: input.Scope,
		Identifier: IdentifierBinding{Role: input.Hint.Role, IdentifierType: input.Hint.IdentifierType,
			Normalization: input.Hint.Normalization, MatchDigest: input.MatchDigest,
			DerivationKeyRevision: input.DerivationKeyRevision},
		ConfidenceCeilingMillionths: input.Hint.ConfidenceCeilingMillionths,
		Evidence: EvidenceBinding{
			EnvelopeID: input.Evidence.EnvelopeID, EnvelopeDigest: input.Evidence.EnvelopeDigest,
			Classification: input.Evidence.Classification, SourceIdentityDigest: input.Evidence.SourceIdentityDigest,
			TransformationDigest: input.Evidence.TransformationDigest, ArtifactDigest: input.Evidence.ArtifactDigest,
			RawManifestDigest: input.Evidence.RawManifestDigest, IngestReceiptDigest: input.Evidence.IngestReceiptDigest,
			SourceProvenanceDigest: input.Evidence.SourceProvenanceDigest, MappingManifestDigest: input.Evidence.MappingManifestDigest,
			MappingRevision: input.Evidence.MappingRevision, MappingOutcomeDigest: input.Evidence.MappingOutcomeDigest,
			RuleID: input.Hint.RuleID, OutputField: input.Hint.OutputPath,
			OutputFieldDigest: digestBytes([]byte(input.Hint.OutputPath)), SourceFieldDigest: input.Hint.SourceFieldDigest,
		},
		ObservedAt: input.ObservedAt, Validity: "current", SupersedesObservationDigest: input.SupersedesObservationDigest,
	}
	canonical, digest, err := CanonicalObservation(ctx, observation)
	if err != nil {
		return Observation{}, nil, "", err
	}
	return observation, canonical, digest, nil
}
