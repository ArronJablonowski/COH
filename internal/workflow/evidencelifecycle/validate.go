package evidencelifecycle

import (
	"math"
	"sort"
	"time"
)

func ValidateCommand(value Command, now time.Time) error {
	if err := validateCommandShape(value); err != nil {
		return err
	}
	if !validTime(now) || !value.Deadline.After(now) {
		return newError(InvalidInput, "command_deadline_invalid", false, nil)
	}
	return nil
}

func validateCommandShape(value Command) error {
	if value.SchemaVersion != CommandSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.RequestID) || !validOpaque(value.IdempotencyKey, 1, 256) ||
		!validOperation(value.Operation) || !validCase(value.Case) || !uuidPattern.MatchString(value.ActorID) ||
		!validRevision(value.ActorRevision) || !allPointerDigests(value.ArtifactSetDigest, value.PackageDigest,
		value.SourceDigest, value.PurposeDigest, value.DestinationDigest, value.ReasonDigest, value.ApprovalDigest) ||
		!digestPattern.MatchString(value.PolicyDigest) || !validRevision(value.ExpectedCaseRevision) ||
		!validHead(value.ExpectedCustodyHead) || value.ExpectedCustodyHead.Case != value.Case ||
		!validLimits(value.Limits) || !validTime(value.Deadline) || !validCommandFields(value) {
		return newError(InvalidInput, "command_invalid", false, nil)
	}
	return nil
}

func validCommandFields(value Command) bool {
	artifactSet, packageDigest, source := value.ArtifactSetDigest, value.PackageDigest, value.SourceDigest
	purpose, destination, reason, approval := value.PurposeDigest, value.DestinationDigest, value.ReasonDigest, value.ApprovalDigest
	switch value.Operation {
	case Export:
		return artifactSet != nil && purpose != nil && destination != nil && approval != nil &&
			allNil(packageDigest, source, reason)
	case Import:
		return packageDigest != nil && source != nil && allNil(artifactSet, purpose, destination, reason, approval)
	case PlaceHold, ReleaseHold:
		return artifactSet != nil && reason != nil && allNil(packageDigest, source, purpose, destination, approval)
	case Delete:
		return artifactSet != nil && reason != nil && approval != nil && allNil(packageDigest, source, purpose, destination)
	default:
		return false
	}
}

func ValidateExportManifest(value ExportManifest) error {
	if err := validateManifestShape(value, true); err != nil {
		return err
	}
	artifactSet, err := ArtifactSetBindingDigest(value.Artifacts)
	if err != nil || artifactSet != value.ArtifactSetDigest {
		return newError(Denied, "artifact_set_digest_invalid", false, err)
	}
	want, err := ManifestBindingDigest(value)
	if err != nil || want != value.ManifestDigest {
		return newError(Denied, "manifest_digest_invalid", false, err)
	}
	return nil
}

func validateManifestShape(value ExportManifest, bound bool) error {
	if value.SchemaVersion != ExportManifestSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.ManifestID) || value.PackageVersion != PackageVersion || !validCase(value.Case) ||
		!validRevision(value.CaseRevision) || !validClassification(value.Classification) ||
		!uuidPattern.MatchString(value.ActorID) || !validRevision(value.ActorRevision) ||
		!allDigests(value.PurposeDigest, value.DestinationDigest, value.ArtifactSetDigest, value.PolicyDigest,
			value.DecisionDigest, value.ApprovalDigest, value.RevocationDigest, value.CustodyReportDigest,
			value.AuditCheckpointDigest, value.AuditProofDigest, value.IdempotencyDigest,
			value.PreviousProvenanceDigest) || !uuidPattern.MatchString(value.AuditCheckpointID) ||
		!validRevision(value.CustodyFromSequence) || value.CustodyToSequence < value.CustodyFromSequence ||
		value.CustodyToSequence > math.MaxInt64 || !validRevision(value.AuditCheckpointSequence) ||
		!validRevision(value.AuditSigningKeyRevision) || value.SigningAlgorithm != SigningAlgorithm ||
		!tokenPattern.MatchString(value.SigningKeyID) || !validRevision(value.SigningKeyRevision) ||
		value.Compression != NoCompression || !validLimits(value.Limits) || !validTime(value.CreatedAt) ||
		!validTime(value.ValidUntil) || !value.ValidUntil.After(value.CreatedAt) ||
		(bound && !digestPattern.MatchString(value.ManifestDigest)) || (!bound && value.ManifestDigest != "") ||
		!validManifestArtifacts(value.Artifacts, value.Classification, value.Limits.MaximumArtifacts) ||
		!validComponents(value.Components) {
		return newError(InvalidInput, "manifest_invalid", false, nil)
	}
	return nil
}

func validManifestArtifacts(values []ManifestArtifact, classification string, maximum uint16) bool {
	if len(values) == 0 || len(values) > int(maximum) {
		return false
	}
	seenArtifacts, seenManifests := make(map[string]struct{}, len(values)), make(map[string]struct{}, len(values))
	for index, value := range values {
		if value.Ordinal != uint16(index+1) || !validArtifactRole(value.Role) || !validEvidence(value.Reference) ||
			classificationRank(value.Reference.Artifact.Classification) > classificationRank(classification) ||
			!sortedUniqueDigests(value.ParentArtifactDigests) ||
			!sortedUniqueDigests(value.ParentManifestDigests) || len(value.ParentArtifactDigests) != len(value.ParentManifestDigests) ||
			!allPointerDigests(value.RedactionReceiptDigest, value.MappingDigest) ||
			(value.Role == DerivedArtifact) != (value.RedactionReceiptDigest != nil) ||
			(value.Role == DerivedArtifact) != (value.MappingDigest != nil) {
			return false
		}
		if _, exists := seenArtifacts[value.Reference.Artifact.Digest]; exists {
			return false
		}
		if _, exists := seenManifests[value.Reference.Manifest.Digest]; exists {
			return false
		}
		for _, parent := range value.ParentArtifactDigests {
			if _, exists := seenArtifacts[parent]; !exists {
				return false
			}
		}
		for _, parent := range value.ParentManifestDigests {
			if _, exists := seenManifests[parent]; !exists {
				return false
			}
		}
		seenArtifacts[value.Reference.Artifact.Digest] = struct{}{}
		seenManifests[value.Reference.Manifest.Digest] = struct{}{}
	}
	return true
}

func validComponents(values []Component) bool {
	if len(values) == 0 || len(values) > 4096 {
		return false
	}
	previous := ""
	for _, value := range values {
		key := value.Kind + "\x00" + value.Name + "\x00" + value.Version + "\x00" + value.Digest
		if !validComponentKind(value.Kind) || !tokenPattern.MatchString(value.Name) ||
			!validOpaque(value.Version, 1, 128) || !digestPattern.MatchString(value.Digest) ||
			previous != "" && key <= previous {
			return false
		}
		previous = key
	}
	return true
}

func ValidateDetachedSignature(value DetachedSignature) error {
	if value.SchemaVersion != DetachedSignatureSchemaVersion || value.ContractVersion != ContractVersion ||
		value.Algorithm != SigningAlgorithm || !tokenPattern.MatchString(value.KeyID) ||
		!validRevision(value.KeyRevision) || !digestPattern.MatchString(value.ManifestDigest) ||
		!signaturePattern.MatchString(value.Signature) {
		return newError(InvalidInput, "signature_invalid", false, nil)
	}
	return nil
}

func ValidatePackageHeader(value PackageHeader) error {
	if err := validateHeaderShape(value, true); err != nil {
		return err
	}
	want, err := HeaderBindingDigest(value)
	if err != nil || want != value.HeaderDigest {
		return newError(Denied, "header_digest_invalid", false, err)
	}
	return nil
}

func validateHeaderShape(value PackageHeader, bound bool) error {
	if value.SchemaVersion != PackageHeaderSchemaVersion || value.ContractVersion != ContractVersion ||
		value.Magic != PackageMagic || value.PackageVersion != PackageVersion || value.Compression != NoCompression ||
		value.ManifestLength <= 0 || value.ManifestLength > 16<<20 || value.SignatureLength < 64 ||
		value.SignatureLength > 4096 || value.ArtifactCount == 0 || value.ArtifactCount > 4096 ||
		value.PackageLength <= value.ManifestLength+value.SignatureLength || value.PackageLength > 4<<40 ||
		(bound && !digestPattern.MatchString(value.HeaderDigest)) || (!bound && value.HeaderDigest != "") {
		return newError(InvalidInput, "header_invalid", false, nil)
	}
	return nil
}

func sortedUniqueDigests(values []string) bool {
	return sort.SliceIsSorted(values, func(left, right int) bool { return values[left] < values[right] }) &&
		allUniqueValid(values)
}

func allUniqueValid(values []string) bool {
	previous := ""
	for _, value := range values {
		if !digestPattern.MatchString(value) || value == previous {
			return false
		}
		previous = value
	}
	return true
}

func validArtifactRole(value ArtifactRole) bool {
	return value == SourceArtifact || value == DerivedArtifact || value == ImportedArtifact
}

func validComponentKind(value string) bool {
	return value == "policy" || value == "model" || value == "tool" || value == "query" || value == "transform"
}

func classificationRank(value string) int {
	for index, candidate := range []string{"public", "internal", "confidential", "restricted"} {
		if value == candidate {
			return index
		}
	}
	return math.MaxInt
}
