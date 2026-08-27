package entityresolution

import (
	"context"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	fieldPattern  = regexp.MustCompile(`^(ocsf|ecs)(\.[a-z][a-z0-9_-]*)+$`)
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func validateObservation(ctx context.Context, value Observation) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if value.SchemaVersion != ObservationSchemaVersion || value.ContractVersion != ContractVersion ||
		value.MethodVersion != MethodVersion || !uuidPattern.MatchString(value.ObservationID) ||
		!uuidPattern.MatchString(value.OperationID) || !validScope(value.Scope) || !validIdentifier(value.Identifier) ||
		value.ConfidenceCeilingMillionths > 1_000_000 || !validEvidence(value.Evidence) ||
		!validTimestamp(value.ObservedAt) || !slices.Contains([]string{"current", "rejected", "expired", "superseded"}, value.Validity) ||
		value.SupersedesObservationDigest != nil && !digestPattern.MatchString(*value.SupersedesObservationDigest) {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	return nil
}

func validScope(value Scope) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) && uuidPattern.MatchString(value.CaseID)
}

func validIdentifier(value IdentifierBinding) bool {
	if !digestPattern.MatchString(value.MatchDigest) || value.DerivationKeyRevision == 0 || value.DerivationKeyRevision > math.MaxInt64 {
		return false
	}
	switch value.Role {
	case "host.name":
		return value.IdentifierType == "hostname" && slices.Contains([]string{"identity", "lowercase_ascii"}, value.Normalization)
	case "user.name":
		return value.IdentifierType == "username" && slices.Contains([]string{"identity", "lowercase_ascii"}, value.Normalization)
	case "network.ip":
		return slices.Contains([]string{"ipv4", "ipv6"}, value.IdentifierType) && value.Normalization == "ip_canonical"
	case "process.id":
		return value.IdentifierType == "process_id" && value.Normalization == "decimal_canonical"
	case "file.hash":
		return value.IdentifierType == "sha256" && value.Normalization == "sha256_lowercase"
	case "cloud.resource_id":
		return value.IdentifierType == "cloud_resource_id" && value.Normalization == "identity"
	default:
		return false
	}
}

func validEvidence(value EvidenceBinding) bool {
	if !uuidPattern.MatchString(value.EnvelopeID) || !validClassification(value.Classification) ||
		value.MappingRevision == 0 || value.MappingRevision > math.MaxInt64 || !tokenPattern.MatchString(value.RuleID) ||
		!validOutputField(value.OutputField) ||
		value.OutputFieldDigest != digestBytes([]byte(value.OutputField)) {
		return false
	}
	for _, digest := range []string{value.EnvelopeDigest, value.SourceIdentityDigest, value.TransformationDigest,
		value.ArtifactDigest, value.RawManifestDigest, value.IngestReceiptDigest, value.SourceProvenanceDigest,
		value.MappingManifestDigest, value.MappingOutcomeDigest, value.OutputFieldDigest, value.SourceFieldDigest} {
		if !digestPattern.MatchString(digest) {
			return false
		}
	}
	return true
}

func validOutputField(value string) bool {
	if len(value) > 1024 || !fieldPattern.MatchString(value) {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 || len(parts) > 17 {
		return false
	}
	for _, part := range parts[1:] {
		if len(part) == 0 || len(part) > 128 {
			return false
		}
	}
	return true
}

func validClassification(value string) bool {
	return slices.Contains([]string{"public", "internal", "confidential", "restricted"}, value)
}

func validTimestamp(value string) bool {
	parsed, err := time.Parse(timestampLayout, value)
	return err == nil && parsed.Format(timestampLayout) == value && strings.HasSuffix(value, "Z")
}
