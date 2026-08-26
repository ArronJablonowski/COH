package skilldiscovery

import (
	"crypto/subtle"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/skillregistry"
)

var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	tokenPattern   = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)
	versionPattern = regexp.MustCompile(`^[1-9][0-9]{0,8}[.][0-9]{1,9}[.][0-9]{1,9}$`)
)

func validCase(value domain.CaseRef) bool {
	return uuidPattern.MatchString(value.OrganizationID) && uuidPattern.MatchString(value.TenantID) &&
		uuidPattern.MatchString(value.CaseID)
}

func validTime(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && offset == 0 && value.Equal(value.Truncate(time.Nanosecond))
}

func validCommon(requestID, idempotency string, scope domain.CaseRef, taskID, actorID,
	policy, permission string, deadline, now time.Time) bool {
	return uuidPattern.MatchString(requestID) && validOpaque(idempotency, 1, MaximumIdempotencyBytes) &&
		validCase(scope) && uuidPattern.MatchString(taskID) && uuidPattern.MatchString(actorID) &&
		digestPattern.MatchString(policy) && tokenPattern.MatchString(permission) &&
		validTime(deadline) && now.Before(deadline) && deadline.Sub(now) <= MaximumDiscoveryValidity
}

func validateSearch(value SearchRequest, now time.Time) error {
	if value.SchemaVersion != SearchSchemaVersion || value.ContractVersion != ContractVersion ||
		!validCommon(value.RequestID, value.IdempotencyKey, value.Case, value.TaskID, value.ActorID,
			value.PolicyDigest, value.RequiredPermission, value.Deadline, now) ||
		value.Limit == 0 || value.Limit > MaximumPageSize || !validQuery(value.Query) ||
		!validOptionalDigest(value.Cursor) || !validOptionalDigest(value.ExpectedSnapshotDigest) ||
		(value.Cursor == "") != (value.ExpectedSnapshotDigest == "") {
		return newError(InvalidInput, "search_request_invalid", false, nil)
	}
	return nil
}

func validateDetail(value DetailRequest, now time.Time) error {
	if value.SchemaVersion != DetailSchemaVersion || value.ContractVersion != ContractVersion ||
		!validCommon(value.RequestID, value.IdempotencyKey, value.Case, value.TaskID, value.ActorID,
			value.PolicyDigest, value.RequiredPermission, value.Deadline, now) ||
		!tokenPattern.MatchString(value.SkillName) || !digestPattern.MatchString(value.ExpectedManifestDigest) ||
		!validOpaque(value.SearchIdempotencyKey, 1, MaximumIdempotencyBytes) ||
		!digestPattern.MatchString(value.ExpectedSearchResultDigest) {
		return newError(InvalidInput, "detail_request_invalid", false, nil)
	}
	return nil
}

func validateResource(value ResourceRequest, now time.Time) error {
	if value.SchemaVersion != ResourceSchemaVersion || value.ContractVersion != ContractVersion ||
		!validCommon(value.RequestID, value.IdempotencyKey, value.Case, value.TaskID, value.ActorID,
			value.PolicyDigest, value.RequiredPermission, value.Deadline, now) ||
		!tokenPattern.MatchString(value.SkillName) || !digestPattern.MatchString(value.ExpectedManifestDigest) ||
		!tokenPattern.MatchString(value.ResourceName) || !digestPattern.MatchString(value.ResourceDigest) ||
		!validOpaque(value.DetailIdempotencyKey, 1, MaximumIdempotencyBytes) ||
		!digestPattern.MatchString(value.ExpectedDetailResultDigest) {
		return newError(InvalidInput, "resource_request_invalid", false, nil)
	}
	return nil
}

func validateDecision(value Decision, request AuthorizationRequest, now time.Time) error {
	if value.SchemaVersion != DecisionSchemaVersion || value.ContractVersion != ContractVersion ||
		!uuidPattern.MatchString(value.DecisionID) || !uuidPattern.MatchString(value.RequestID) ||
		!digestPattern.MatchString(value.DecisionDigest) ||
		!digestPattern.MatchString(value.PolicyDigest) || !validCase(value.Case) ||
		!uuidPattern.MatchString(value.TaskID) || !uuidPattern.MatchString(value.ActorID) ||
		(value.Phase != CompactSearch && value.Phase != DetailExpand && value.Phase != ResourceFetch) ||
		!validOptionalToken(value.SkillName) || !validOptionalDigest(value.ManifestDigest) ||
		!tokenPattern.MatchString(value.RequiredPermission) || !validOptionalToken(value.ResourceName) ||
		!validOptionalDigest(value.ResourceDigest) || !digestPattern.MatchString(value.QueryDigest) ||
		!digestPattern.MatchString(value.SnapshotDigest) || !validOptionalDigest(value.Cursor) ||
		!validOptionalDigest(value.ParentResultDigest) ||
		value.Outcome != "allow" || value.Revision == 0 || !validTime(value.IssuedAt) ||
		!validTime(value.Deadline) || !validTime(value.ExpiresAt) || value.IssuedAt.After(now) ||
		!now.Before(value.ExpiresAt) || !now.Before(value.Deadline) ||
		value.ExpiresAt.Sub(value.IssuedAt) > MaximumDiscoveryValidity {
		return newError(Denied, "decision_invalid", false, nil)
	}
	if value.Phase == CompactSearch && (value.PageLimit == 0 || value.PageLimit > MaximumPageSize) ||
		value.Phase != CompactSearch && value.PageLimit != 0 {
		return newError(Denied, "decision_page_limit_invalid", false, nil)
	}
	if value.Phase == CompactSearch && value.ParentResultDigest != "" ||
		value.Phase != CompactSearch && !digestPattern.MatchString(value.ParentResultDigest) {
		return newError(Denied, "decision_parent_result_invalid", false, nil)
	}
	if value.Phase != CompactSearch && (value.SkillName == "" || value.ManifestDigest == "") ||
		(value.SkillName == "") != (value.ManifestDigest == "") {
		return newError(Denied, "decision_target_invalid", false, nil)
	}
	expected, err := decisionDigest(value)
	if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(value.DecisionDigest)) != 1 {
		return newError(Denied, "decision_digest_invalid", false, err)
	}
	if value.RequestID != request.RequestID || value.PolicyDigest != request.PolicyDigest || value.Case != request.Case ||
		value.TaskID != request.TaskID || value.ActorID != request.ActorID || value.Phase != request.Phase ||
		value.SkillName != request.SkillName || value.ManifestDigest != request.ManifestDigest ||
		value.RequiredPermission != request.RequiredPermission || value.ResourceName != request.ResourceName ||
		value.ResourceDigest != request.ResourceDigest || value.QueryDigest != request.QueryDigest ||
		value.SnapshotDigest != request.SnapshotDigest || value.Cursor != request.Cursor ||
		value.PageLimit != request.PageLimit || value.ParentResultDigest != request.ParentResultDigest ||
		value.Deadline != request.Deadline {
		return newError(Denied, "decision_scope_mismatch", false, nil)
	}
	return nil
}

func validateCatalog(value skillregistry.CatalogSnapshot, scope domain.CaseRef) error {
	if value.SchemaVersion != skillregistry.CatalogSchemaVersion ||
		value.ContractVersion != skillregistry.ContractVersion ||
		value.OrganizationID != scope.OrganizationID || value.TenantID != scope.TenantID ||
		!digestPattern.MatchString(value.SnapshotDigest) || value.Entries == nil ||
		len(value.Entries) > skillregistry.MaximumCatalogEntries {
		return newError(Denied, "catalog_snapshot_invalid", false, nil)
	}
	for index, entry := range value.Entries {
		if !tokenPattern.MatchString(entry.SkillName) || !digestPattern.MatchString(entry.ManifestDigest) ||
			entry.StateRevision == 0 || !digestPattern.MatchString(entry.ProvenanceDigest) ||
			index > 0 && value.Entries[index-1].SkillName >= entry.SkillName {
			return newError(Denied, "catalog_entry_invalid", false, nil)
		}
	}
	return nil
}

func validateResolved(value skillregistry.ResolvedSkill, name, manifest, provenance string) error {
	if value.SkillName != name || value.ManifestDigest != manifest || value.ProvenanceDigest != provenance ||
		!versionPattern.MatchString(value.SkillVersion) || !digestPattern.MatchString(value.ContentDigest) ||
		!uuidPattern.MatchString(value.OwnerActorID) || !uuidPattern.MatchString(value.ReviewID) ||
		value.ReviewRevision == 0 || value.Resources == nil || len(value.Resources) > skillregistry.MaximumResources ||
		value.Permissions == nil || len(value.Permissions) > skillregistry.MaximumPermissions ||
		!slices.IsSorted(value.Permissions) {
		return newError(Denied, "resolved_skill_invalid", false, nil)
	}
	for index, resource := range value.Resources {
		if !tokenPattern.MatchString(resource.Name) || !digestPattern.MatchString(resource.Digest) ||
			resource.MediaType == "" || resource.Classification == "" || resource.Length <= 0 ||
			index > 0 && value.Resources[index-1].Name >= resource.Name {
			return newError(Denied, "resolved_resource_invalid", false, nil)
		}
	}
	return nil
}

func validateSearchResult(value SearchResult) error {
	expected, err := searchResultDigest(value)
	if err != nil || expected != value.ResultDigest || value.Skills == nil ||
		len(value.Skills) > MaximumPageSize || !digestPattern.MatchString(value.SnapshotDigest) ||
		!validOptionalDigest(value.NextCursor) || value.Replayed {
		return newError(Denied, "search_result_invalid", false, err)
	}
	for index, skill := range value.Skills {
		if !tokenPattern.MatchString(skill.SkillName) || !versionPattern.MatchString(skill.SkillVersion) ||
			!digestPattern.MatchString(skill.ManifestDigest) || !digestPattern.MatchString(skill.ProvenanceDigest) ||
			index > 0 && value.Skills[index-1].SkillName >= skill.SkillName {
			return newError(Denied, "compact_skill_invalid", false, nil)
		}
	}
	return nil
}

func validateDetailResult(value DetailResult) error {
	expected, err := detailResultDigest(value)
	if err != nil || expected != value.ResultDigest || value.Replayed {
		return newError(Denied, "detail_result_invalid", false, err)
	}
	return validateResolved(skillregistry.ResolvedSkill{SkillName: value.SkillName,
		SkillVersion: value.SkillVersion, ManifestDigest: value.ManifestDigest,
		ContentDigest: value.ContentDigest, Resources: value.Resources, Permissions: value.Permissions,
		OwnerActorID: value.OwnerActorID, ReviewID: value.ReviewID,
		ReviewRevision: value.ReviewRevision, ProvenanceDigest: value.ProvenanceDigest},
		value.SkillName, value.ManifestDigest, value.ProvenanceDigest)
}

func validateResourceResult(value ResourceResult) error {
	expected, err := resourceResultDigest(value)
	if err != nil || expected != value.ResultDigest || value.Replayed ||
		!tokenPattern.MatchString(value.SkillName) || !digestPattern.MatchString(value.ManifestDigest) ||
		!tokenPattern.MatchString(value.ResourceName) || !digestPattern.MatchString(value.ProvenanceDigest) ||
		!digestPattern.MatchString(value.Artifact.Digest) || len(value.Artifact.MediaType) < 3 ||
		len(value.Artifact.MediaType) > 127 || !strings.Contains(value.Artifact.MediaType, "/") ||
		!tokenPattern.MatchString(value.Artifact.Classification) || value.Artifact.Length <= 0 ||
		value.Artifact.Length > 1<<30 {
		return newError(Denied, "resource_result_invalid", false, err)
	}
	return nil
}

func validQuery(value string) bool {
	if !utf8.ValidString(value) || len(value) > MaximumQueryBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func validOpaque(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len(value) >= minimum && len(value) <= maximum &&
		strings.TrimSpace(value) == value && !strings.ContainsRune(value, '\x00')
}

func validOptionalDigest(value string) bool { return value == "" || digestPattern.MatchString(value) }
func validOptionalToken(value string) bool  { return value == "" || tokenPattern.MatchString(value) }
