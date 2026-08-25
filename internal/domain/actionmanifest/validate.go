package actionmanifest

import (
	"encoding/base64"
	"regexp"
	"slices"
	"time"
)

var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^[1-9][0-9]{0,8}([.][0-9]{1,9}){0,2}$`)
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func Validate(manifest Manifest) error {
	if manifest.SchemaVersion != ManifestSchemaVersion || manifest.ContractVersion != ContractVersion {
		return contractError(Denied, "unsupported_contract")
	}
	if !uuidPattern.MatchString(manifest.ManifestID) || !uuidPattern.MatchString(manifest.WorkflowTaskID) ||
		!uuidPattern.MatchString(manifest.OrganizationID) || !uuidPattern.MatchString(manifest.TenantID) ||
		!uuidPattern.MatchString(manifest.CaseID) || !uuidPattern.MatchString(manifest.RequestorActorID) ||
		!uuidPattern.MatchString(manifest.ActionOwnerActorID) {
		return contractError(InvalidInput, "manifest_scope")
	}
	if !tokenPattern.MatchString(manifest.ActionType) || !tokenPattern.MatchString(manifest.Operation) ||
		!validTier(manifest.ActionTier) {
		return contractError(InvalidInput, "manifest_action")
	}
	if !validDigestSet(manifest.TargetDigests, 1, 256) || !validDigestSet(manifest.ExclusionDigests, 0, 256) ||
		setsOverlap(manifest.TargetDigests, manifest.ExclusionDigests) {
		return contractError(InvalidInput, "manifest_targets")
	}
	if !digestPattern.MatchString(manifest.ArgumentsDigest) || !digestPattern.MatchString(manifest.PayloadDigest) {
		return contractError(InvalidInput, "manifest_payload")
	}
	if !tokenPattern.MatchString(manifest.Tool.Name) || !versionPattern.MatchString(manifest.Tool.Version) ||
		!digestPattern.MatchString(manifest.Tool.Digest) {
		return contractError(InvalidInput, "manifest_tool")
	}
	if !digestPattern.MatchString(manifest.PolicyDigest) || manifest.PolicyRevision == 0 {
		return contractError(InvalidInput, "manifest_policy")
	}
	if !validOptionalDigest(manifest.ROEDigest) || !validOptionalDigest(manifest.CredentialReferenceDigest) ||
		!validOptionalDigest(manifest.RollbackDigest) {
		return contractError(InvalidInput, "manifest_digest")
	}
	if !tokenPattern.MatchString(manifest.CredentialClass) ||
		(manifest.CredentialClass == "none") != (manifest.CredentialReferenceDigest == nil) {
		return contractError(InvalidInput, "manifest_credential")
	}
	if !tokenPattern.MatchString(manifest.ExecutionZone) || !digestPattern.MatchString(manifest.IsolationProfileDigest) {
		return contractError(InvalidInput, "manifest_execution")
	}
	validFrom, fromErr := time.Parse(timestampLayout, manifest.ValidFrom)
	validUntil, untilErr := time.Parse(timestampLayout, manifest.ValidUntil)
	if fromErr != nil || untilErr != nil || !validUntil.After(validFrom) || validUntil.Sub(validFrom) > MaximumValidity {
		return contractError(InvalidInput, "manifest_time")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(manifest.ManifestNonce)
	if err != nil || len(nonce) != 32 {
		return contractError(InvalidInput, "manifest_nonce")
	}
	if manifest.MaximumUseCount == 0 || manifest.MaximumUseCount > 1000 {
		return contractError(InvalidInput, "manifest_use")
	}
	if manifest.SafetyWatchActorID != nil && !uuidPattern.MatchString(*manifest.SafetyWatchActorID) {
		return contractError(InvalidInput, "manifest_safety")
	}
	switch manifest.ActionTier {
	case "T2", "T3":
		if manifest.RollbackDigest == nil {
			return contractError(InvalidInput, "manifest_safety")
		}
	case "T4":
		if manifest.ROEDigest == nil || manifest.RollbackDigest == nil || manifest.SafetyWatchActorID == nil || manifest.MaximumUseCount != 1 {
			return contractError(InvalidInput, "manifest_safety")
		}
	}
	return nil
}

func validTier(value string) bool {
	return value == "T0" || value == "T1" || value == "T2" || value == "T3" || value == "T4"
}

func validDigestSet(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !digestPattern.MatchString(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func setsOverlap(left, right []string) bool {
	for _, value := range left {
		if _, found := slices.BinarySearch(right, value); found {
			return true
		}
	}
	return false
}

func validOptionalDigest(value *string) bool {
	return value == nil || digestPattern.MatchString(*value)
}
