package profilecomposition

import (
	"regexp"
	"slices"
	"strings"
	"time"
)

var (
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuid7Pattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	timePattern   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

func validateEnvelope(value Envelope) error {
	if value.SchemaVersion != EnvelopeSchemaVersion || value.ContractVersion != ContractVersion ||
		value.Layer.SchemaVersion != LayerSchemaVersion || value.Layer.ContractVersion != ContractVersion {
		return newError(Unsupported, "unsupported_contract")
	}
	if !validDigest(value.LayerDigest) || len(value.Signatures) == 0 || len(value.Signatures) > 8 {
		return newError(InvalidInput, "envelope")
	}
	if err := validateLayer(value.Layer); err != nil {
		return err
	}
	identities := make([]string, len(value.Signatures))
	publishers, reviewers := 0, 0
	for index, signature := range value.Signatures {
		if !oneOf(signature.Role, "publisher", "reviewer") || !validUUID7(signature.SignerID) ||
			!validToken(signature.KeyID) || signature.KeyRevision == 0 || signature.KeyRevision > MaximumRevision ||
			signature.Algorithm != SignatureAlgorithm || !validTimestamp(signature.SignedAt) ||
			len(signature.Signature) != 86 {
			return newError(InvalidInput, "signature")
		}
		if signature.Role == "publisher" {
			publishers++
		} else {
			reviewers++
		}
		identities[index] = signatureIdentity(signature)
	}
	if publishers != 1 || reviewers == 0 || !sortedUnique(identities) {
		return newError(Denied, "signature_set")
	}
	return nil
}

func validateLayer(value Layer) error {
	issued, issuedOK := parseTimestamp(value.IssuedAt)
	notBefore, notBeforeOK := parseTimestamp(value.NotBefore)
	expires, expiresOK := parseTimestamp(value.ExpiresAt)
	if !validUUID7(value.LayerID) || !validToken(value.Name) ||
		!oneOf(value.Kind, "baseline", "connectivity", "deployment", "overlay", "site", "surface") ||
		value.Revision == 0 || value.Revision > MaximumRevision || value.Precedence > 1000000 ||
		!validOptionalDigest(value.PredecessorDigest) || !validOptionalDigest(value.RollbackAuthorizationDigest) ||
		!issuedOK || !notBeforeOK || !expiresOK || notBefore.Before(issued) || !expires.After(notBefore) {
		return newError(InvalidInput, "layer")
	}
	if value.Revision == 1 && value.PredecessorDigest != "" || value.Revision > 1 && value.PredecessorDigest == "" {
		return newError(InvalidInput, "predecessor")
	}
	if err := validateTarget(value.Target); err != nil {
		return err
	}
	if len(value.Parents) > 32 {
		return newError(InvalidInput, "parents")
	}
	parentIDs := make([]string, len(value.Parents))
	for index, parent := range value.Parents {
		if !validUUID7(parent.LayerID) || parent.Revision == 0 || parent.Revision > MaximumRevision ||
			!validDigest(parent.LayerDigest) || parent.LayerID == value.LayerID {
			return newError(InvalidInput, "parent")
		}
		parentIDs[index] = parent.LayerID + "\x00" + parent.LayerDigest
	}
	if !sortedUnique(parentIDs) {
		return newError(InvalidInput, "parent_order")
	}
	return validateContribution(value.Contribution, value.Target)
}

func validateTarget(value Target) error {
	if !validEnumSet(value.DeploymentKinds, 3, "compose", "native_server", "native_workstation") ||
		!validEnumSet(value.ConnectivityModes, 3, "air_gapped", "connected", "restricted_connected") ||
		!validEnumSet(value.Platforms, 4, "darwin_arm64", "linux_amd64", "linux_arm64", "windows_amd64") ||
		!validEnumSet(value.Surfaces, 5, "api", "cli", "headless", "test", "web") {
		return newError(InvalidInput, "target")
	}
	return nil
}

func validateContribution(value Contribution, target Target) error {
	if !validArtifact(value.DeploymentProfile) || len(value.CapabilityBundles) == 0 || len(value.CapabilityBundles) > 64 ||
		len(value.PolicyBundles) == 0 || len(value.PolicyBundles) > 32 ||
		!validArtifacts(value.CapabilityBundles) || !validArtifacts(value.PolicyBundles) ||
		!validTokenSet(value.EndpointReferences, 64) || !validTokenSet(value.Permissions, 128) ||
		!validOptionalDigest(value.OfflineBundleDigest) || !validLimits(value.Limits) {
		return newError(InvalidInput, "contribution")
	}
	airGap := slices.Contains(target.ConnectivityModes, "air_gapped")
	if airGap && value.OfflineBundleDigest == "" || !airGap && value.OfflineBundleDigest != "" {
		return newError(Denied, "offline_bundle")
	}
	return nil
}

func validLimits(value Limits) bool {
	return value.MaxConcurrency > 0 && value.MaxConcurrency <= 1024 &&
		value.MaxContextBytes > 0 && value.MaxContextBytes <= 67108864 &&
		value.MaxDurationMS > 0 && value.MaxDurationMS <= 86400000 &&
		value.MaxEvidenceBytes > 0 && value.MaxEvidenceBytes <= 1073741824 &&
		value.MaxModelTokens > 0 && value.MaxModelTokens <= 1048576 && value.MaxToolCalls <= 100000
}

func validArtifact(value ArtifactRef) bool {
	return validToken(value.ID) && value.Revision > 0 && value.Revision <= MaximumRevision && validDigest(value.Digest)
}
func validArtifacts(values []ArtifactRef) bool {
	identities := make([]string, len(values))
	for index, value := range values {
		if !validArtifact(value) {
			return false
		}
		identities[index] = value.ID + "\x00" + value.Digest
	}
	return sortedUnique(identities)
}
func validEnumSet(values []string, maximum int, allowed ...string) bool {
	if len(values) == 0 || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !slices.Contains(allowed, value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}
func validTokenSet(values []string, maximum int) bool {
	if values == nil || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validToken(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}
func sortedUnique(values []string) bool {
	if values == nil || !slices.IsSorted(values) {
		return false
	}
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return false
		}
	}
	return true
}
func signatureIdentity(value Signature) string {
	return value.Role + "\x00" + value.SignerID + "\x00" + value.KeyID
}
func validToken(value string) bool {
	return tokenPattern.MatchString(value) && strings.TrimSpace(value) == value
}
func validUUID7(value string) bool          { return uuid7Pattern.MatchString(value) }
func validDigest(value string) bool         { return digestPattern.MatchString(value) }
func validOptionalDigest(value string) bool { return value == "" || validDigest(value) }
func validTimestamp(value string) bool      { _, ok := parseTimestamp(value); return ok }
func parseTimestamp(value string) (time.Time, bool) {
	if !timePattern.MatchString(value) {
		return time.Time{}, false
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	return parsed, err == nil
}
func oneOf(value string, allowed ...string) bool { return slices.Contains(allowed, value) }
