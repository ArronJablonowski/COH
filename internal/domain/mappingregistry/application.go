package mappingregistry

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/ArronJablonowski/COH/internal/domain/normalizedevent"
	"github.com/ArronJablonowski/COH/internal/helper/domaincontract"
)

type applicationResult struct {
	Envelope       normalizedevent.ValidatedEnvelope
	Coverage       string
	AppliedRules   []string
	UnmappedPaths  []string
	LossyPaths     []string
	EntityHints    []EmittedEntityHint
	ReverseResults []ReverseResult
}

func applyVerifiedMapping(ctx context.Context, command Command, selected verifiedMapping, input normalizedevent.ValidatedEnvelope) (applicationResult, error) {
	if err := checkContext(ctx); err != nil {
		return applicationResult{}, err
	}
	if command.Operation != Apply || command.MappingDigest != selected.ManifestDigest ||
		selected.Signed.ManifestDigest != selected.ManifestDigest || selected.RegistryRevision == 0 ||
		command.ExpectedRegistryRevision != 0 && command.ExpectedRegistryRevision != selected.RegistryRevision {
		return applicationResult{}, newError(InvalidInput, ManifestDigestMismatch, nil)
	}
	_, currentDigest, err := CanonicalManifest(ctx, selected.Signed.Manifest)
	if err != nil || currentDigest != selected.ManifestDigest {
		return applicationResult{}, newError(DeniedError, ManifestDigestMismatch, err)
	}
	value := input.Value()
	if !exactEnvelopeBinding(command, input, value) || !sameSource(selected.Signed.Manifest.Source, command.Source) {
		return applicationResult{}, newError(DeniedError, EvidenceBindingMismatch, nil)
	}
	originalValue, err := domaincontract.DecodeUnique(value.Original.Fields)
	if err != nil {
		return applicationResult{}, newError(InvalidInput, CoverageInvalid, err)
	}
	original, ok := originalValue.(map[string]any)
	if !ok {
		return applicationResult{}, newError(InvalidInput, CoverageInvalid, nil)
	}
	inventory, err := inventoryOriginal(ctx, original, selected.Signed.Manifest.Limits)
	if err != nil {
		return applicationResult{}, err
	}
	mapped, err := executeMapping(ctx, selected.Signed.Manifest, original)
	if err != nil {
		return applicationResult{}, err
	}
	coverage, unmapped, vendorPartial, err := classifyCoverage(selected.Signed.Manifest, inventory, mapped)
	if err != nil {
		return applicationResult{}, err
	}
	reverse, hints, err := validateReverseAndHints(selected.Signed.Manifest, original, mapped)
	if err != nil {
		return applicationResult{}, err
	}
	resultEnvelope, err := constructEnvelope(ctx, command, selected, input, value, mapped, coverage, vendorPartial)
	if err != nil {
		return applicationResult{}, err
	}
	return applicationResult{
		Envelope: resultEnvelope, Coverage: coverage,
		AppliedRules: append([]string(nil), mapped.AppliedRules...), UnmappedPaths: unmapped,
		LossyPaths: append([]string(nil), mapped.LossyPaths...), EntityHints: hints, ReverseResults: reverse,
	}, nil
}

func exactEnvelopeBinding(command Command, input normalizedevent.ValidatedEnvelope, value normalizedevent.Envelope) bool {
	wantedCase := Case{OrganizationID: value.Case.OrganizationID, TenantID: value.Case.TenantID, CaseID: value.Case.CaseID}
	binding := command.SourceBinding
	if command.Case != wantedCase || binding.EnvelopeID != value.EnvelopeID || binding.EnvelopeDigest != input.Digest() ||
		binding.ArtifactDigest != value.Lineage.RawArtifact.Digest || binding.ManifestDigest != value.Lineage.RawManifestDigest ||
		binding.IngestReceiptDigest != value.Lineage.IngestReceiptDigest || binding.SourceProvenanceDigest != value.Lineage.SourceProvenanceDigest ||
		binding.OriginalFieldsDigest != value.Original.FieldsDigest {
		return false
	}
	source := command.Source
	if source.SourceKind != value.Source.Kind || source.CollectionMethod != value.Source.CollectionMethod ||
		source.CollectionMethodVersion != value.Source.CollectionMethodVersion {
		return false
	}
	return source.SourceIdentityDigest == nil || *source.SourceIdentityDigest == value.Source.IdentityDigest
}

func constructEnvelope(ctx context.Context, command Command, selected verifiedMapping, input normalizedevent.ValidatedEnvelope,
	value normalizedevent.Envelope, mapped mappingResult, coverage string, vendorPartial []string) (normalizedevent.ValidatedEnvelope, error) {
	value.EnvelopeID = command.OperationID
	value.OCSF = normalizedevent.OCSF{Version: normalizedevent.OCSFVersion, SchemaCommit: normalizedevent.OCSFCommit,
		Event: append(json.RawMessage(nil), mapped.OCSF...), EventDigest: digestBytes(mapped.OCSF)}
	if string(mapped.ECS) == "{}" {
		value.ECS = nil
	} else {
		value.ECS = &normalizedevent.ECS{Version: normalizedevent.ECSVersion, SchemaCommit: normalizedevent.ECSCommit,
			Fields: append(json.RawMessage(nil), mapped.ECS...), FieldsDigest: digestBytes(mapped.ECS)}
	}
	manifest := selected.Signed.Manifest
	value.Normalization = normalizedevent.Normalization{
		MappingSetDigest: selected.ManifestDigest,
		Normalizer:       normalizedevent.Component{Name: manifest.Name, Version: manifest.Version, Digest: selected.ManifestDigest},
		Coverage:         coverage, UnmappedVendorPaths: append([]string(nil), vendorPartial...),
	}
	parents := append(append([]string(nil), value.Lineage.ParentEnvelopeDigests...), input.Digest())
	value.Lineage.ParentEnvelopeDigests = sortedUnique(parents)
	transformation, err := normalizedevent.TransformationDigest(value)
	if err != nil {
		return normalizedevent.ValidatedEnvelope{}, newError(InvalidInput, CoverageInvalid, err)
	}
	value.Normalization.TransformationDigest = transformation
	encoded, err := json.Marshal(value)
	if err != nil {
		return normalizedevent.ValidatedEnvelope{}, newError(InvalidInput, CoverageInvalid, err)
	}
	validated, err := normalizedevent.Decode(ctx, encoded)
	if err != nil {
		return normalizedevent.ValidatedEnvelope{}, normalizeEnvelopeError(err)
	}
	return validated, nil
}

func normalizeEnvelopeError(err error) error {
	switch normalizedevent.Code(err) {
	case normalizedevent.Canceled:
		return newError(CanceledError, ContextCanceled, err)
	case normalizedevent.Timeout:
		return newError(TimeoutError, ContextDeadline, err)
	default:
		return newError(InvalidInput, CoverageInvalid, err)
	}
}

func vendorPaths(paths []string) []string {
	result := make([]string, len(paths))
	for index, path := range paths {
		result[index] = strings.TrimPrefix(path, "original.")
	}
	sort.Strings(result)
	return result
}
