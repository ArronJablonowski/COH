package evidencecatalog

import (
	"context"
	"regexp"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/evidenceingest"
	"github.com/ArronJablonowski/COH/internal/workflow/evidencelifecycle"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func (catalog *Catalog) verify(ctx context.Context, registration Registration) (
	evidencelifecycle.VerifiedEvidenceSet, error) {
	if err := contextError(ctx); err != nil {
		return evidencelifecycle.VerifiedEvidenceSet{}, err
	}
	if !validCase(registration.Case) {
		return evidencelifecycle.VerifiedEvidenceSet{},
			lifecycleError(evidencelifecycle.InvalidInput, "catalog_case_invalid", false)
	}
	artifacts := cloneArtifacts(registration.Artifacts)
	artifactSetDigest, err := evidencelifecycle.ArtifactSetBindingDigest(artifacts)
	if err != nil {
		return evidencelifecycle.VerifiedEvidenceSet{},
			lifecycleError(evidencelifecycle.InvalidInput, "catalog_artifacts_invalid", false)
	}
	manifests := make([]evidenceingest.ArtifactManifest, len(artifacts))
	for index := range artifacts {
		entry := artifacts[index]
		receipt, found, resolveErr := catalog.receipts.ResolveReceipt(ctx, registration.Case,
			entry.Reference.IngestionReceiptDigest)
		if resolveErr != nil {
			return evidencelifecycle.VerifiedEvidenceSet{}, ingestionError(resolveErr, "catalog_receipt")
		}
		if !found {
			return evidencelifecycle.VerifiedEvidenceSet{},
				lifecycleError(evidencelifecycle.NotFound, "catalog_receipt_not_found", false)
		}
		if _, canonicalErr := evidenceingest.CanonicalReceipt(receipt); canonicalErr != nil ||
			receipt.Case != registration.Case || receipt.ReceiptDigest != entry.Reference.IngestionReceiptDigest ||
			receipt.Artifact != entry.Reference.Artifact || receipt.Manifest != entry.Reference.Manifest ||
			receipt.ManifestProvenanceDigest != entry.Reference.ManifestProvenanceDigest {
			return evidencelifecycle.VerifiedEvidenceSet{},
				lifecycleError(evidencelifecycle.Denied, "catalog_receipt_binding_invalid", false)
		}
		manifest, manifestErr := catalog.manifests.ResolveArtifactManifest(ctx, receipt)
		if manifestErr != nil {
			if err := contextError(ctx); err != nil {
				return evidencelifecycle.VerifiedEvidenceSet{}, err
			}
			return evidencelifecycle.VerifiedEvidenceSet{},
				lifecycleError(evidencelifecycle.Denied, "catalog_manifest_invalid", false)
		}
		if !manifestMatchesEntry(manifest, entry, artifacts[:index]) {
			return evidencelifecycle.VerifiedEvidenceSet{},
				lifecycleError(evidencelifecycle.Denied, "catalog_manifest_binding_invalid", false)
		}
		manifests[index] = manifest
	}
	components := catalogComponents(artifacts, manifests)
	componentDigest, err := evidencelifecycle.ComponentSetBindingDigest(components)
	if err != nil {
		return evidencelifecycle.VerifiedEvidenceSet{},
			lifecycleError(evidencelifecycle.Denied, "catalog_components_invalid", false)
	}
	lineageDigest, err := evidencelifecycle.LineageBindingDigest(artifacts)
	if err != nil {
		return evidencelifecycle.VerifiedEvidenceSet{},
			lifecycleError(evidencelifecycle.Denied, "catalog_lineage_invalid", false)
	}
	return evidencelifecycle.VerifiedEvidenceSet{Case: registration.Case, Artifacts: artifacts,
		Components: components, ArtifactSetDigest: artifactSetDigest, LineageDigest: lineageDigest,
		ComponentSetDigest: componentDigest}, nil
}

func manifestMatchesEntry(manifest evidenceingest.ArtifactManifest,
	entry evidencelifecycle.ManifestArtifact, prior []evidencelifecycle.ManifestArtifact) bool {
	if _, err := evidenceingest.CanonicalManifest(manifest); err != nil || manifest.Artifact != entry.Reference.Artifact ||
		manifest.ProvenanceDigest != entry.Reference.ManifestProvenanceDigest ||
		len(manifest.ParentArtifacts) != len(entry.ParentArtifactDigests) ||
		len(manifest.ParentManifestDigests) != len(entry.ParentManifestDigests) {
		return false
	}
	if entry.Role == evidencelifecycle.DerivedArtifact && manifest.Source.Kind != evidenceingest.DerivedSource ||
		entry.Role == evidencelifecycle.ImportedArtifact && manifest.Source.Kind != evidenceingest.ImportSource ||
		entry.Role == evidencelifecycle.SourceArtifact &&
			(manifest.Source.Kind == evidenceingest.DerivedSource || manifest.Source.Kind == evidenceingest.ImportSource) {
		return false
	}
	priorArtifacts := make(map[string]domain.ArtifactRef, len(prior))
	priorManifests := make(map[string]struct{}, len(prior))
	for _, candidate := range prior {
		priorArtifacts[candidate.Reference.Artifact.Digest] = candidate.Reference.Artifact
		priorManifests[candidate.Reference.Manifest.Digest] = struct{}{}
	}
	for index, parent := range manifest.ParentArtifacts {
		if parent.Digest != entry.ParentArtifactDigests[index] || priorArtifacts[parent.Digest] != parent {
			return false
		}
	}
	for index, parent := range manifest.ParentManifestDigests {
		if parent != entry.ParentManifestDigests[index] {
			return false
		}
		if _, found := priorManifests[parent]; !found {
			return false
		}
	}
	return true
}

func catalogComponents(artifacts []evidencelifecycle.ManifestArtifact,
	manifests []evidenceingest.ArtifactManifest) []evidencelifecycle.Component {
	values := make([]evidencelifecycle.Component, 0, len(manifests)*2)
	for index, manifest := range manifests {
		values = append(values, evidencelifecycle.Component{Kind: "policy", Name: "evidence_ingestion",
			Version: evidenceingest.ContractVersion, Digest: manifest.PolicyDigest})
		for _, component := range manifest.Components {
			values = append(values, evidencelifecycle.Component{Kind: string(component.Kind), Name: component.Name,
				Version: component.Version, Digest: component.Digest})
		}
		if artifacts[index].Role == evidencelifecycle.DerivedArtifact {
			values = append(values, evidencelifecycle.Component{Kind: "transform", Name: "governed_redaction",
				Version: evidenceingest.ContractVersion, Digest: *artifacts[index].RedactionReceiptDigest})
		}
	}
	sort.Slice(values, func(left, right int) bool { return componentKey(values[left]) < componentKey(values[right]) })
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || componentKey(result[len(result)-1]) != componentKey(value) {
			result = append(result, value)
		}
	}
	return append([]evidencelifecycle.Component(nil), result...)
}

func componentKey(value evidencelifecycle.Component) string {
	return value.Kind + "\x00" + value.Name + "\x00" + value.Version + "\x00" + value.Digest
}

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func cloneArtifacts(values []evidencelifecycle.ManifestArtifact) []evidencelifecycle.ManifestArtifact {
	result := make([]evidencelifecycle.ManifestArtifact, len(values))
	for index, value := range values {
		result[index] = value
		result[index].ParentArtifactDigests = append([]string(nil), value.ParentArtifactDigests...)
		result[index].ParentManifestDigests = append([]string(nil), value.ParentManifestDigests...)
		result[index].RedactionReceiptDigest = clonePointer(value.RedactionReceiptDigest)
		result[index].MappingDigest = clonePointer(value.MappingDigest)
	}
	return result
}

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
