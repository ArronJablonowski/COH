package e11integration

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/ArronJablonowski/COH/internal/domain/entityresolution"
	"github.com/ArronJablonowski/COH/internal/domain/investigationprojection"
	"github.com/ArronJablonowski/COH/internal/domain/mappingregistry"
	"github.com/ArronJablonowski/COH/internal/domain/normalizedevent"
	"github.com/ArronJablonowski/COH/internal/domain/temporaltime"
)

type Chain struct {
	Envelope             normalizedevent.ValidatedEnvelope
	MappingOutcome       mappingregistry.Outcome
	MappingOutcomeDigest string
	Observation          entityresolution.Observation
	ObservationDigest    string
	Entity               entityresolution.Entity
	EntityRef            entityresolution.EntityRef
	TimeRecord           temporaltime.Record
	TimeRecordDigest     string
	TimeComparison       temporaltime.Comparison
	TimeComparisonDigest string
	Facts                []investigationprojection.Fact
	StateVersion         investigationprojection.StateVersion
}

type BindingError struct{ Stage string }

func (err *BindingError) Error() string {
	return fmt.Sprintf("COH-E11 integration binding failed: %s", err.Stage)
}

func Verify(ctx context.Context, chain Chain) error {
	if ctx == nil {
		return &BindingError{Stage: "context"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	decoded, err := normalizedevent.Decode(ctx, chain.Envelope.CanonicalBytes())
	if err != nil || decoded.Digest() != chain.Envelope.Digest() {
		return &BindingError{Stage: "envelope"}
	}
	envelope := decoded.Value()
	_, mappingDigest, err := mappingregistry.CanonicalOutcome(ctx, chain.MappingOutcome)
	if err != nil || mappingDigest != chain.MappingOutcomeDigest || chain.MappingOutcome.NormalizedEnvelopeDigest == nil ||
		*chain.MappingOutcome.NormalizedEnvelopeDigest != decoded.Digest() ||
		chain.MappingOutcome.MappingDigest != envelope.Normalization.MappingSetDigest {
		return &BindingError{Stage: "mapping"}
	}
	_, observationDigest, err := entityresolution.CanonicalObservation(ctx, chain.Observation)
	if err != nil || observationDigest != chain.ObservationDigest || !observationBinds(chain.Observation, envelope,
		decoded.Digest(), chain.MappingOutcome, chain.MappingOutcomeDigest) {
		return &BindingError{Stage: "entity_observation"}
	}
	if err := entityresolution.ValidateEntityRevision(ctx, chain.Entity, chain.EntityRef); err != nil ||
		chain.Entity.Scope != chain.Observation.Scope || !slices.Contains(chain.Entity.MemberObservations,
		entityresolution.ObservationRef{ObservationID: chain.Observation.ObservationID,
			ObservationDigest: chain.ObservationDigest}) {
		return &BindingError{Stage: "entity_revision"}
	}
	_, timeDigest, err := temporaltime.CanonicalRecord(ctx, chain.TimeRecord)
	if err != nil || timeDigest != chain.TimeRecordDigest || !timeBinds(chain.TimeRecord, envelope, decoded.Digest()) {
		return &BindingError{Stage: "time_record"}
	}
	_, comparisonDigest, err := temporaltime.CanonicalComparison(ctx, chain.TimeComparison)
	if err != nil || comparisonDigest != chain.TimeComparisonDigest ||
		chain.TimeComparison.Left.RecordDigest != timeDigest && chain.TimeComparison.Right.RecordDigest != timeDigest {
		return &BindingError{Stage: "time_comparison"}
	}
	if !stateBinds(chain.StateVersion, chain.MappingOutcome, chain.EntityRef, envelope) {
		return &BindingError{Stage: "state_version"}
	}
	for index, fact := range chain.Facts {
		if _, _, factErr := investigationprojection.CanonicalFact(ctx, fact); factErr != nil ||
			!factBinds(fact, envelope, decoded.Digest(), chain.MappingOutcome, chain.MappingOutcomeDigest,
				chain.EntityRef, timeDigest, comparisonDigest, chain.StateVersion) {
			return &BindingError{Stage: fmt.Sprintf("fact_%d", index+1)}
		}
	}
	for _, kind := range []investigationprojection.Kind{investigationprojection.Correlation,
		investigationprojection.Hypothesis, investigationprojection.Timeline} {
		reducer, reducerErr := investigationprojection.NewReducer(kind)
		if reducerErr != nil {
			return &BindingError{Stage: "reducer"}
		}
		var state *investigationprojection.ReductionState
		for _, fact := range chain.Facts {
			state, reducerErr = reducer.Reduce(ctx, state, fact, chain.StateVersion)
			if reducerErr != nil {
				return &BindingError{Stage: "replay"}
			}
		}
		if state == nil || state.FactCount != uint64(len(chain.Facts)) {
			return &BindingError{Stage: "watermark"}
		}
	}
	return nil
}

func observationBinds(observation entityresolution.Observation, envelope normalizedevent.Envelope, envelopeDigest string,
	mapping mappingregistry.Outcome, mappingDigest string) bool {
	return observation.Scope == (entityresolution.Scope{OrganizationID: envelope.Case.OrganizationID,
		TenantID: envelope.Case.TenantID, CaseID: envelope.Case.CaseID}) &&
		observation.Evidence.EnvelopeID == envelope.EnvelopeID && observation.Evidence.EnvelopeDigest == envelopeDigest &&
		observation.Evidence.Classification == envelope.Classification &&
		observation.Evidence.SourceIdentityDigest == envelope.Source.IdentityDigest &&
		observation.Evidence.TransformationDigest == envelope.Normalization.TransformationDigest &&
		observation.Evidence.ArtifactDigest == envelope.Lineage.RawArtifact.Digest &&
		observation.Evidence.RawManifestDigest == envelope.Lineage.RawManifestDigest &&
		observation.Evidence.IngestReceiptDigest == envelope.Lineage.IngestReceiptDigest &&
		observation.Evidence.SourceProvenanceDigest == envelope.Lineage.SourceProvenanceDigest &&
		observation.Evidence.MappingManifestDigest == mapping.MappingDigest &&
		observation.Evidence.MappingRevision == mapping.RegistryRevision &&
		observation.Evidence.MappingOutcomeDigest == mappingDigest
}

func timeBinds(record temporaltime.Record, envelope normalizedevent.Envelope, envelopeDigest string) bool {
	return record.Case == (temporaltime.Case{OrganizationID: envelope.Case.OrganizationID,
		TenantID: envelope.Case.TenantID, CaseID: envelope.Case.CaseID}) &&
		record.SourceBinding.EnvelopeID == envelope.EnvelopeID && record.SourceBinding.EnvelopeDigest == envelopeDigest &&
		record.SourceBinding.ArtifactDigest == envelope.Lineage.RawArtifact.Digest &&
		record.SourceBinding.ManifestDigest == envelope.Lineage.RawManifestDigest &&
		record.SourceBinding.IngestReceiptDigest == envelope.Lineage.IngestReceiptDigest &&
		record.SourceBinding.SourceProvenanceDigest == envelope.Lineage.SourceProvenanceDigest &&
		record.SourceBinding.SourceIdentityDigest == envelope.Source.IdentityDigest
}

func stateBinds(version investigationprojection.StateVersion, mapping mappingregistry.Outcome,
	entity entityresolution.EntityRef, envelope normalizedevent.Envelope) bool {
	return version.NormalizedEventSchemaVersion == envelope.SchemaVersion &&
		version.MappingContractVersion == mappingregistry.ContractVersion &&
		version.MappingManifestDigest == mapping.MappingDigest && version.MappingRevision == mapping.RegistryRevision &&
		version.EntityContractVersion == entityresolution.ContractVersion && version.EntityHeadDigest == entity.RecordDigest &&
		version.TimeContractVersion == temporaltime.ContractVersion
}

func factBinds(fact investigationprojection.Fact, envelope normalizedevent.Envelope, envelopeDigest string,
	mapping mappingregistry.Outcome, mappingDigest string, entity entityresolution.EntityRef, timeDigest,
	comparisonDigest string, version investigationprojection.StateVersion) bool {
	wantedScope := investigationprojection.Scope{OrganizationID: envelope.Case.OrganizationID,
		TenantID: envelope.Case.TenantID, CaseID: envelope.Case.CaseID}
	wantedEntity := investigationprojection.EntityRef{EntityID: entity.EntityID, Revision: entity.Revision,
		RecordDigest: entity.RecordDigest}
	binding := fact.Binding
	if fact.Scope != wantedScope || binding.ArtifactDigest != envelope.Lineage.RawArtifact.Digest ||
		binding.ManifestDigest != envelope.Lineage.RawManifestDigest ||
		binding.IngestReceiptDigest != envelope.Lineage.IngestReceiptDigest ||
		binding.SourceProvenanceDigest != envelope.Lineage.SourceProvenanceDigest ||
		binding.NormalizedEventDigest != envelopeDigest || binding.NormalizedEventSchemaVersion != envelope.SchemaVersion ||
		binding.MappingOutcomeDigest != mappingDigest || binding.MappingManifestDigest != mapping.MappingDigest ||
		binding.MappingRevision != mapping.RegistryRevision || binding.AuthoritativeStateDigest != version.AuthoritativeStateDigest ||
		!slices.Equal(binding.EntityRefs, []investigationprojection.EntityRef{wantedEntity}) ||
		!slices.Equal(fact.EntityRefs, binding.EntityRefs) || len(binding.TimeRefs) != 1 || len(fact.TimeRefs) != 1 {
		return false
	}
	for _, reference := range []investigationprojection.TimeRef{binding.TimeRefs[0], fact.TimeRefs[0]} {
		if reference.TimeRecordDigest != timeDigest || reference.ComparisonDigest == nil ||
			*reference.ComparisonDigest != comparisonDigest {
			return false
		}
	}
	return true
}

func IsBindingError(err error) bool {
	var target *BindingError
	return errors.As(err, &target)
}
