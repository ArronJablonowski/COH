package custody

import (
	"context"
	"slices"
	"sort"

	"github.com/ArronJablonowski/COH/internal/domain"
)

func (controller *Controller) resolveEvidence(ctx context.Context, command Command) (string, error) {
	subject, err := controller.evidence.ResolveEvidence(ctx, command.Case, command.Subject)
	if err != nil {
		return "", mapDependency(ctx, "evidence_resolution_unavailable", err)
	}
	if !validVerifiedEvidence(subject) || subject.Reference != command.Subject {
		return "", newError(Denied, "evidence_verification_invalid", false, nil)
	}
	verificationDigests := []string{subject.VerificationDigest}
	parents := make([]VerifiedEvidence, len(command.Parents))
	for index, reference := range command.Parents {
		parents[index], err = controller.evidence.ResolveEvidence(ctx, command.Case, reference)
		if err != nil {
			return "", mapDependency(ctx, "parent_resolution_unavailable", err)
		}
		if !validVerifiedEvidence(parents[index]) || parents[index].Reference != reference {
			return "", newError(Denied, "parent_verification_invalid", false, nil)
		}
		verificationDigests = append(verificationDigests, parents[index].VerificationDigest)
	}
	if command.Operation == Acquire && (subject.SourceIdentityDigest != *command.SourceIdentityDigest ||
		len(subject.ParentArtifacts) != 0 || len(subject.ParentManifestDigests) != 0) {
		return "", newError(Denied, "acquisition_source_invalid", false, nil)
	}
	if command.Operation == Transform || command.Operation == Redact {
		artifacts := make([]domain.ArtifactRef, len(command.Parents))
		manifests := make([]string, len(command.Parents))
		for index, parent := range command.Parents {
			artifacts[index], manifests[index] = parent.Artifact, parent.Manifest.Digest
		}
		sort.Slice(artifacts, func(left, right int) bool { return artifacts[left].Digest < artifacts[right].Digest })
		sort.Strings(manifests)
		if !slices.Equal(subject.ParentArtifacts, artifacts) ||
			!slices.Equal(subject.ParentManifestDigests, manifests) {
			return "", newError(Denied, "lineage_verification_invalid", false, nil)
		}
	}
	canonical, err := canonicalValue(struct {
		Subject string   `json:"subject"`
		Parents []string `json:"parents"`
	}{subject.VerificationDigest, verificationDigests[1:]})
	if err != nil {
		return "", err
	}
	return digest("COH-CUSTODY-VERIFIED-EVIDENCE-SET-V1\x00", canonical), nil
}

func validVerifiedEvidence(value VerifiedEvidence) bool {
	if !validEvidence(value.Reference) || !allDigests(value.SourceIdentityDigest, value.VerificationDigest) ||
		len(value.ParentArtifacts) != len(value.ParentManifestDigests) || len(value.ParentArtifacts) > 128 {
		return false
	}
	previousArtifact, previousManifest := "", ""
	for index, artifact := range value.ParentArtifacts {
		manifest := value.ParentManifestDigests[index]
		if !validArtifact(artifact) || !digestPattern.MatchString(manifest) ||
			previousArtifact != "" && artifact.Digest <= previousArtifact ||
			previousManifest != "" && manifest <= previousManifest {
			return false
		}
		previousArtifact, previousManifest = artifact.Digest, manifest
	}
	return true
}
