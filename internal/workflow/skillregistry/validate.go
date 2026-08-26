package skillregistry

import (
	"crypto/subtle"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^[1-9][0-9]{0,8}[.][0-9]{1,9}[.][0-9]{1,9}$`)
)

func validateManifest(value Manifest) error {
	if value.SchemaVersion != ManifestSchemaVersion || value.ContractVersion != ContractVersion {
		return newError(Denied, "unsupported_manifest_contract", false, nil)
	}
	if !validUUID(value.ManifestID) || !validUUID(value.OwnerActorID) || !validUUID(value.PublisherActorID) ||
		!validUUID(value.ReviewID) || !tokenPattern.MatchString(value.SkillName) ||
		!versionPattern.MatchString(value.SkillVersion) || !validDigest(value.ContentDigest) ||
		!validDigest(value.TestSuiteDigest) || !validDigest(value.TestEvidenceDigest) ||
		!validDigest(value.ThreatModelDigest) || !validOptionalDigest(value.PreviousManifestDigest) {
		return newError(InvalidInput, "manifest_identity_invalid", false, nil)
	}
	if value.OwnerActorID == value.PublisherActorID || value.ReviewDecision != "approved" ||
		value.ReviewRevision == 0 || !validDigest(value.ReviewEvidenceDigest) ||
		!validUUIDSet(value.ReviewerActorIDs, 1, 16) {
		return newError(Denied, "manifest_review_invalid", false, nil)
	}
	for _, reviewer := range value.ReviewerActorIDs {
		if reviewer == value.OwnerActorID || reviewer == value.PublisherActorID {
			return newError(Denied, "reviewer_not_independent", false, nil)
		}
	}
	if value.Resources == nil || len(value.Resources) > MaximumResources {
		return newError(InvalidInput, "manifest_resources_invalid", false, nil)
	}
	for index, resource := range value.Resources {
		if index > 0 && value.Resources[index-1].Name >= resource.Name ||
			!tokenPattern.MatchString(resource.Name) || !validDigest(resource.Digest) ||
			!validMediaType(resource.MediaType) || !validClassification(resource.Classification) ||
			resource.Length <= 0 || resource.Length > 1<<30 {
			return newError(InvalidInput, "manifest_resources_invalid", false, nil)
		}
	}
	if !validTokenSet(value.Permissions, 1, MaximumPermissions) {
		return newError(InvalidInput, "manifest_permissions_invalid", false, nil)
	}
	if !validTime(value.ReviewedAt) || !validTime(value.ValidFrom) || !validTime(value.ValidUntil) ||
		value.ReviewedAt.After(value.ValidFrom) || !value.ValidUntil.After(value.ValidFrom) ||
		value.ValidUntil.Sub(value.ValidFrom) > MaximumValidity {
		return newError(InvalidInput, "manifest_validity_invalid", false, nil)
	}
	return nil
}

func validateCommand(value ChangeCommand) error {
	if value.SchemaVersion != CommandSchemaVersion || value.ContractVersion != ContractVersion {
		return newError(Denied, "unsupported_command_contract", false, nil)
	}
	if !validUUID(value.CommandID) || !validUUID(value.OrganizationID) || !validUUID(value.TenantID) ||
		!validUUID(value.CaseID) || !validUUID(value.TaskID) || !validUUID(value.ActorID) ||
		!tokenPattern.MatchString(value.SkillName) || !validDigest(value.TargetManifestDigest) ||
		!validOptionalDigest(value.ExpectedCurrentDigest) || !validDigest(value.ReasonDigest) {
		return newError(InvalidInput, "command_identity_invalid", false, nil)
	}
	if value.Action != Promote && value.Action != Rollback && value.Action != Revoke {
		return newError(InvalidInput, "command_action_invalid", false, nil)
	}
	if !validTime(value.CreatedAt) || !validTime(value.Deadline) || !value.Deadline.After(value.CreatedAt) ||
		value.Deadline.Sub(value.CreatedAt) > 24*time.Hour {
		return newError(InvalidInput, "command_validity_invalid", false, nil)
	}
	if value.ExpectedRevision == 0 && value.ExpectedCurrentDigest != "" ||
		value.ExpectedRevision > 0 && value.ExpectedCurrentDigest == "" ||
		value.Action != Promote && value.ExpectedRevision == 0 {
		return newError(Denied, "command_state_binding_invalid", false, nil)
	}
	return nil
}

func validateSigningAuthority(value SigningAuthority) bool {
	return validUUID(value.ActorID) && tokenPattern.MatchString(value.KeyID) &&
		value.KeyRevision > 0 && value.ApprovalRevision > 0 && value.Active && value.Approved &&
		len(value.PublicKey) == 32
}

func validateReview(manifest Manifest, review ReviewAuthority, reviewers []SigningAuthority) error {
	if !review.Active || review.Decision != "approved" || review.ReviewID != manifest.ReviewID ||
		review.Revision != manifest.ReviewRevision || review.EvidenceDigest != manifest.ReviewEvidenceDigest ||
		!slices.Equal(review.ReviewerIDs, manifest.ReviewerActorIDs) ||
		len(reviewers) != len(manifest.ReviewerActorIDs) {
		return newError(Denied, "review_authority_invalid", false, nil)
	}
	for index, authority := range reviewers {
		if !validateSigningAuthority(authority) || authority.ActorID != manifest.ReviewerActorIDs[index] {
			return newError(Denied, "reviewer_authority_invalid", false, nil)
		}
	}
	return nil
}

func validatePolicy(value PolicyDecision, command ChangeCommand, now time.Time) error {
	if value.SchemaVersion != PolicySchemaVersion || value.ContractVersion != ContractVersion ||
		!validUUID(value.DecisionID) || !validDigest(value.DecisionDigest) || !validDigest(value.PolicyDigest) ||
		value.Revision == 0 || value.Outcome != "allow" || !validTime(value.IssuedAt) ||
		!validTime(value.ExpiresAt) || value.IssuedAt.After(now) || !now.Before(value.ExpiresAt) ||
		value.ExpiresAt.Sub(value.IssuedAt) > 24*time.Hour {
		return newError(Denied, "policy_decision_invalid", false, nil)
	}
	expected, err := policyDecisionDigest(value)
	if err != nil || !constantDigest(expected, value.DecisionDigest) {
		return newError(Denied, "policy_decision_digest_invalid", false, err)
	}
	if value.OrganizationID != command.OrganizationID || value.TenantID != command.TenantID ||
		value.CaseID != command.CaseID || value.TaskID != command.TaskID || value.ActorID != command.ActorID ||
		value.Action != command.Action || value.SkillName != command.SkillName ||
		subtle.ConstantTimeCompare([]byte(value.ManifestDigest), []byte(command.TargetManifestDigest)) != 1 {
		return newError(Denied, "policy_scope_mismatch", false, nil)
	}
	return nil
}

func validateResolveRequest(value ResolveRequest, now time.Time) error {
	if value.SchemaVersion != ResolveSchemaVersion || value.ContractVersion != ContractVersion ||
		!validUUID(value.RequestID) || !validUUID(value.OrganizationID) || !validUUID(value.TenantID) ||
		!validUUID(value.CaseID) || !validUUID(value.TaskID) || !validUUID(value.ActorID) ||
		!tokenPattern.MatchString(value.SkillName) || !validDigest(value.ExpectedManifestDigest) ||
		!tokenPattern.MatchString(value.RequiredPermission) || !validDigest(value.PolicyDigest) ||
		!validTime(value.Deadline) || !now.Before(value.Deadline) {
		return newError(InvalidInput, "resolution_request_invalid", false, nil)
	}
	return nil
}

func validateAccess(value AccessDecision, request ResolveRequest, now time.Time) error {
	if value.SchemaVersion != AccessSchemaVersion || value.ContractVersion != ContractVersion ||
		!validUUID(value.DecisionID) || !validDigest(value.DecisionDigest) || !validDigest(value.PolicyDigest) ||
		value.Revision == 0 || value.Outcome != "allow" || !validTime(value.IssuedAt) ||
		!validTime(value.ExpiresAt) || value.IssuedAt.After(now) || !now.Before(value.ExpiresAt) ||
		value.ExpiresAt.Sub(value.IssuedAt) > 24*time.Hour {
		return newError(Denied, "access_decision_invalid", false, nil)
	}
	expected, err := accessDecisionDigest(value)
	if err != nil || !constantDigest(expected, value.DecisionDigest) {
		return newError(Denied, "access_decision_digest_invalid", false, err)
	}
	if value.OrganizationID != request.OrganizationID || value.TenantID != request.TenantID ||
		value.CaseID != request.CaseID || value.TaskID != request.TaskID || value.ActorID != request.ActorID ||
		value.SkillName != request.SkillName || value.ManifestDigest != request.ExpectedManifestDigest ||
		value.Permission != request.RequiredPermission || value.PolicyDigest != request.PolicyDigest {
		return newError(Denied, "access_scope_mismatch", false, nil)
	}
	return nil
}

func validateState(value State) error {
	if value.SchemaVersion != StateSchemaVersion || value.ContractVersion != ContractVersion ||
		!validUUID(value.OrganizationID) || !validUUID(value.TenantID) ||
		!tokenPattern.MatchString(value.SkillName) || value.Status != Promoted && value.Status != Revoked ||
		!validDigest(value.CurrentManifestDigest) || !validOptionalDigest(value.PreviousManifestDigest) ||
		value.LastAction != Promote && value.LastAction != Rollback && value.LastAction != Revoke ||
		!validDigest(value.LastCommandDigest) || !validDigest(value.IdempotencyDigest) ||
		!validDigest(value.PolicyDecisionDigest) || !validDigest(value.ReviewEvidenceDigest) ||
		!validDigest(value.AuditReceiptDigest) || !validOptionalDigest(value.PreviousProvenanceDigest) ||
		!validDigest(value.ProvenanceDigest) || !validTime(value.CreatedAt) || !validTime(value.UpdatedAt) ||
		value.UpdatedAt.Before(value.CreatedAt) || value.Revision == 0 {
		return newError(Denied, "registry_state_invalid", false, nil)
	}
	if value.Revision == 1 && value.PreviousProvenanceDigest != "" ||
		value.Revision > 1 && value.PreviousProvenanceDigest == "" ||
		value.Status == Revoked && value.LastAction != Revoke {
		return newError(Denied, "registry_state_lineage_invalid", false, nil)
	}
	expected, err := provenanceDigest(value)
	if err != nil || expected != value.ProvenanceDigest {
		return newError(Denied, "registry_provenance_invalid", false, err)
	}
	return nil
}

func validateAuditEvent(value AuditEvent) error {
	if !validUUID(value.EventID) || !validUUID(value.OrganizationID) || !validUUID(value.TenantID) ||
		!validUUID(value.CaseID) || !validUUID(value.TaskID) || !validUUID(value.ActorID) ||
		!tokenPattern.MatchString(value.SkillName) || !validDigest(value.ManifestDigest) ||
		!validDigest(value.PolicyDigest) || !validDigest(value.ReviewDigest) ||
		!validTime(value.OccurredAt) || value.Outcome != "allowed" {
		return newError(InvalidInput, "audit_event_invalid", false, nil)
	}
	if value.Action != Resolve && value.Action != AuditAction(Promote) &&
		value.Action != AuditAction(Rollback) && value.Action != AuditAction(Revoke) {
		return newError(InvalidInput, "audit_action_invalid", false, nil)
	}
	if value.Action == Resolve && value.CommandDigest != "" ||
		value.Action != Resolve && !validDigest(value.CommandDigest) {
		return newError(InvalidInput, "audit_command_invalid", false, nil)
	}
	return nil
}

func validUUID(value string) bool           { return uuidPattern.MatchString(value) }
func validDigest(value string) bool         { return digestPattern.MatchString(value) }
func validOptionalDigest(value string) bool { return value == "" || validDigest(value) }

func validTime(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && offset == 0 && value.Equal(value.Truncate(time.Nanosecond))
}

func validUUIDSet(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !validUUID(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validTokenSet(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum || !slices.IsSorted(values) {
		return false
	}
	for index, value := range values {
		if !tokenPattern.MatchString(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func validMediaType(value string) bool {
	return utf8.ValidString(value) && len(value) >= 3 && len(value) <= 127 &&
		!strings.ContainsAny(value, " \t\r\n") && strings.Count(value, "/") == 1
}

func validClassification(value string) bool {
	return value == "public" || value == "internal" || value == "confidential" || value == "restricted"
}
