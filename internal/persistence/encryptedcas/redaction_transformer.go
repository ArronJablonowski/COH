package encryptedcas

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/redaction"
)

func (store *Store) Derive(ctx context.Context,
	request redaction.DerivationRequest) (redaction.Derivation, redaction.DerivedSource, error) {
	if err := contextError(ctx); err != nil {
		return redaction.Derivation{}, nil, err
	}
	if store == nil || store.redactionRules == nil || redaction.ValidateDerivationRequest(request) != nil {
		return redaction.Derivation{}, nil, newError(InvalidInput, "redaction_request_invalid", nil)
	}
	if request.Source.Artifact.MediaType != request.Plan.OutputMediaType ||
		(request.Plan.OutputMediaType != "text/plain" && request.Plan.OutputMediaType != "application/octet-stream") {
		return redaction.Derivation{}, nil, newError(Denied, "redaction_media_profile_unsupported", nil)
	}
	material, found, err := store.redactionRules.ResolveRedactionRule(ctx, request.Rule.RuleDigest)
	if err != nil {
		return redaction.Derivation{}, nil, normalize("redaction_rule_material_unavailable", err)
	}
	if !found || !validRuleMaterial(material, request.Rule) {
		return redaction.Derivation{}, nil, newError(Denied, "redaction_rule_material_invalid", nil)
	}
	defer zero(material.Mask)
	defer zero(material.Token)
	object, reader, err := store.openRedactionPass(ctx, request)
	if err != nil {
		return redaction.Derivation{}, nil, err
	}
	first := newTransformStream(reader, request.Plan, material)
	buffer := make([]byte, 64*1024)
	defer zero(buffer)
	for {
		_, readErr := first.ReadContext(ctx, buffer)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return redaction.Derivation{}, nil, readErr
		}
	}
	derivedArtifact := domain.ArtifactRef{Digest: first.outputDigest(), MediaType: request.Plan.OutputMediaType,
		Classification: request.Plan.OutputClassification, Length: first.outputPos}
	mapping := redaction.Mapping{SchemaVersion: redaction.MappingSchemaVersion, ContractVersion: redaction.ContractVersion,
		MappingID: deterministicRedactionUUID(request.Plan.PlanDigest, derivedArtifact.Digest), Case: request.Case,
		Source: request.Source, DerivedArtifact: derivedArtifact, PlanDigest: request.Plan.PlanDigest,
		RuleDigest: request.Rule.RuleDigest, ReasonDigest: request.Plan.ReasonDigest,
		ApprovalFingerprintDigest: request.Plan.ApprovalFingerprintDigest, Entries: append([]redaction.MappingEntry(nil), first.entries...),
		CreatedAt: request.CreatedAt, PreviousProvenanceDigest: request.PreviousProvenanceDigest}
	mapping.ProvenanceDigest, err = redaction.MappingProvenanceDigest(mapping)
	if err != nil {
		return redaction.Derivation{}, nil, newError(Denied, "redaction_mapping_provenance_invalid", err)
	}
	mapping.MappingDigest, err = redaction.MappingBindingDigest(mapping)
	if err != nil || redaction.ValidateMapping(mapping) != nil {
		return redaction.Derivation{}, nil, newError(Denied, "redaction_mapping_invalid", err)
	}
	derivation := redaction.Derivation{DerivedArtifact: derivedArtifact, Mapping: mapping}
	derivationDigest, err := redaction.DerivationBindingDigest(request, derivation)
	if err != nil {
		return redaction.Derivation{}, nil, newError(Denied, "redaction_derivation_invalid", err)
	}
	source := &redactionReplaySource{store: store, request: request, material: cloneRuleMaterial(material),
		expectedObject: object, expectedArtifact: derivedArtifact, expectedEntries: append([]redaction.MappingEntry(nil), first.entries...)}
	derivation.DerivationDigest = derivationDigest
	return derivation, source, nil
}

func (store *Store) openRedactionPass(ctx context.Context, request redaction.DerivationRequest) (
	evidenceingest.EncryptedObject, *plaintextReader, error) {
	path, locator, err := store.finalPath(request.Case, request.Source.Artifact.Digest)
	if err != nil {
		return evidenceingest.EncryptedObject{}, nil, err
	}
	object, err := store.inspectPublished(path, request.Case, locator)
	if err != nil || object.PlaintextDigest != request.Source.Artifact.Digest ||
		object.PlaintextLength != request.Source.Artifact.Length || object.MediaType != request.Source.Artifact.MediaType ||
		object.Classification != request.Source.Artifact.Classification {
		return evidenceingest.EncryptedObject{}, nil, newError(Denied, "redaction_source_object_invalid", err)
	}
	reader, err := store.openRedactionReader(ctx, object)
	return object, reader, err
}

type redactionReplaySource struct {
	store            *Store
	request          redaction.DerivationRequest
	material         RedactionRuleMaterial
	expectedObject   evidenceingest.EncryptedObject
	expectedArtifact domain.ArtifactRef
	expectedEntries  []redaction.MappingEntry
	stream           *transformStream
	verified         bool
	terminalErr      error
}

func (source *redactionReplaySource) ReadContext(ctx context.Context, destination []byte) (int, error) {
	if source.terminalErr != nil {
		return 0, source.terminalErr
	}
	if source.verified {
		return 0, io.EOF
	}
	if source.stream == nil {
		object, reader, err := source.store.openRedactionPass(ctx, source.request)
		if err != nil {
			source.terminalErr = err
			return 0, err
		}
		if !samePlainObject(object, source.expectedObject) || object.CiphertextDigest != source.expectedObject.CiphertextDigest ||
			object.LocatorDigest != source.expectedObject.LocatorDigest {
			reader.close()
			source.terminalErr = newError(Denied, "redaction_source_drift", nil)
			return 0, source.terminalErr
		}
		source.stream = newTransformStream(reader, source.request.Plan, source.material)
	}
	count, err := source.stream.ReadContext(ctx, destination)
	if errors.Is(err, io.EOF) {
		if source.stream.outputDigest() != source.expectedArtifact.Digest || source.stream.outputPos != source.expectedArtifact.Length ||
			!sameMappingEntries(source.stream.entries, source.expectedEntries) {
			source.terminalErr = newError(Denied, "redaction_second_pass_drift", nil)
			return count, source.terminalErr
		}
		source.verified = true
		zero(source.material.Mask)
		zero(source.material.Token)
		return count, io.EOF
	}
	if err != nil {
		source.terminalErr = err
	}
	return count, err
}

func (source *redactionReplaySource) Close() error {
	if source.stream != nil {
		source.stream.close()
	}
	zero(source.material.Mask)
	zero(source.material.Token)
	source.material.Mask, source.material.Token = nil, nil
	if !source.verified && source.terminalErr == nil {
		source.terminalErr = newError(Canceled, "redaction_source_closed", context.Canceled)
	}
	return nil
}

func validRuleMaterial(material RedactionRuleMaterial, rule redaction.RuleSet) bool {
	if material.RuleDigest != rule.RuleDigest {
		return false
	}
	maskAllowed, tokenAllowed := containsReplacement(rule.PermittedModes, redaction.Mask), containsReplacement(rule.PermittedModes, redaction.Token)
	if maskAllowed != (len(material.Mask) == 1) || maskAllowed && rawDigest(material.Mask) != *rule.MaskDigest {
		return false
	}
	if !maskAllowed && len(material.Mask) != 0 {
		return false
	}
	if tokenAllowed != (len(material.Token) > 0 && len(material.Token) <= 4096) || tokenAllowed && rawDigest(material.Token) != *rule.TokenDigest {
		return false
	}
	return tokenAllowed || len(material.Token) == 0
}

func containsReplacement(values []redaction.ReplacementMode, target redaction.ReplacementMode) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func cloneRuleMaterial(value RedactionRuleMaterial) RedactionRuleMaterial {
	value.Mask = append([]byte(nil), value.Mask...)
	value.Token = append([]byte(nil), value.Token...)
	return value
}

func sameMappingEntries(left, right []redaction.MappingEntry) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func deterministicRedactionUUID(planDigest, artifactDigest string) string {
	sum := sha256.Sum256([]byte("COH-REDACTION-MAPPING-ID-V1\x00" + planDigest + "\x00" + artifactDigest))
	sum[6] = sum[6]&0x0f | 0x70
	sum[8] = sum[8]&0x3f | 0x80
	encoded := hex.EncodeToString(sum[:16])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}

var _ redaction.Transformer = (*Store)(nil)
