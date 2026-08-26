package opaengine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/policy"
)

var (
	uuidPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	tokenPattern  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	modulePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_./-]{0,122}\.rego$`)
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

func validateAuthority(authority policy.BundleAuthority) error {
	if !authority.Active || authority.KeyRevision == 0 || !tokenPattern.MatchString(authority.KeyID) ||
		authority.Algorithm != SignatureAlgorithm || len(authority.PublicKey) != 32 {
		return policy.NewError(policy.Denied, "policy_signer_revoked")
	}
	return nil
}

func validateBundle(bundle policyBundle) error {
	metadata := bundle.bundleMetadata
	if metadata.SchemaVersion != BundleSchemaVersion || metadata.ContractVersion != BundleContractVersion ||
		!uuidPattern.MatchString(metadata.BundleID) || !uuidPattern.MatchString(metadata.OrganizationID) ||
		!uuidPattern.MatchString(metadata.TenantID) || metadata.PolicyRevision == 0 ||
		metadata.Entrypoint != DecisionEntrypoint {
		return policy.NewError(policy.InvalidInput, "bundle_metadata")
	}
	validFrom, fromErr := time.Parse(timestampLayout, metadata.ValidFrom)
	validUntil, untilErr := time.Parse(timestampLayout, metadata.ValidUntil)
	if fromErr != nil || untilErr != nil || !validUntil.After(validFrom) || validUntil.Sub(validFrom) > MaximumBundleValidity {
		return policy.NewError(policy.InvalidInput, "bundle_validity")
	}
	if len(bundle.Modules) == 0 || len(bundle.Modules) > MaximumBundleModules || bundle.Data == nil {
		return policy.NewError(policy.InvalidInput, "bundle_profile")
	}
	for index, module := range bundle.Modules {
		if !modulePattern.MatchString(module.Path) || strings.Contains(module.Path, "..") ||
			strings.Contains(module.Path, "//") || !utf8.ValidString(module.Source) ||
			len(module.Source) == 0 || len(module.Source) > MaximumModuleBytes ||
			(index > 0 && module.Path <= bundle.Modules[index-1].Path) {
			return policy.NewError(policy.InvalidInput, "bundle_profile")
		}
	}
	return nil
}

func validateRequest(request policy.Request) error {
	manifest := request.Manifest.Manifest()
	if !uuidPattern.MatchString(request.EvaluationID) ||
		(request.Phase != policy.IntentCreated && request.Phase != policy.PreDispatch) ||
		!digestPattern.MatchString(request.Manifest.ManifestDigest) || !uuidPattern.MatchString(request.Actor.ActorID) ||
		request.Actor.Revision == 0 || !sortedTokens(request.Actor.Roles) || !sortedTokens(request.Actor.Permissions) ||
		!tokenPattern.MatchString(request.Runtime.DataRoute) || !validValidatorState(request.Runtime.ValidatorState) {
		return policy.NewError(policy.InvalidInput, "evaluation_input")
	}
	if request.Actor.ActorID != manifest.RequestorActorID || request.Actor.OrganizationID != manifest.OrganizationID ||
		request.Actor.TenantID != manifest.TenantID || request.Actor.CaseID != manifest.CaseID {
		return policy.NewError(policy.Denied, "actor_scope_mismatch")
	}
	if !request.Actor.Active {
		return policy.NewError(policy.Denied, "actor_revoked")
	}
	if !request.Runtime.ToolRegistered {
		return policy.NewError(policy.Denied, "unknown_tool")
	}
	if !request.Runtime.TargetsAuthorized {
		return policy.NewError(policy.Denied, "unknown_target")
	}
	if !request.Runtime.TenantAuthorized {
		return policy.NewError(policy.Denied, "unknown_tenant")
	}
	if !request.Runtime.DataRouteAuthorized {
		return policy.NewError(policy.Denied, "unknown_data_route")
	}
	if !request.Runtime.CapabilityFieldsKnown {
		return policy.NewError(policy.Denied, "unknown_capability_field")
	}
	if request.Runtime.ValidatorState != "qualified" {
		return policy.NewError(policy.Denied, "validator_unqualified")
	}
	if request.Runtime.EmergencyStopActive {
		return policy.NewError(policy.Denied, "emergency_stop_active")
	}
	return nil
}

func sortedTokens(values []string) bool {
	if len(values) == 0 || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !tokenPattern.MatchString(value) || (index > 0 && value == values[index-1]) {
			return false
		}
	}
	return true
}

func validValidatorState(value string) bool {
	return value == "qualified" || value == "stale" || value == "failed" || value == "unknown"
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return policy.NewError(policy.InvalidInput, "context_required")
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return policy.NewError(policy.Timeout, "request_timeout")
		}
		return policy.NewError(policy.Canceled, "request_canceled")
	}
	return nil
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func sameAuthority(current policy.BundleAuthority, loaded bundleMetadata) bool {
	return current.Active && current.Algorithm == SignatureAlgorithm && current.KeyID == loaded.SignerKeyID &&
		current.KeyRevision == loaded.SignerKeyRevision && digestBytes(current.PublicKey) == loaded.SignerKeyDigest
}
