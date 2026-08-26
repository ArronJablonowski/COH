package agentloop

import (
	"context"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/skillregistry"
)

const SkillLookupActivityName = "coh.agent-loop.skill-lookup.v1"

type SkillLookupRequest struct {
	RequestID              string
	Case                   domain.CaseRef
	TaskID                 string
	ActorID                string
	SkillName              string
	ExpectedManifestDigest string
	RequiredPermission     string
	PolicyDigest           string
	Deadline               time.Time
}

type SkillResourceRef struct {
	Name           string
	Digest         string
	MediaType      string
	Classification string
	Length         int64
}

type SkillLookupResult struct {
	SkillName        string
	SkillVersion     string
	ManifestDigest   string
	ContentDigest    string
	Resources        []SkillResourceRef
	Permissions      []string
	OwnerActorID     string
	ReviewID         string
	ReviewRevision   uint64
	ProvenanceDigest string
}

// SkillLookupAuthority resolves the exact current policy, publisher, and
// reviewer snapshots. It grants no connector, executor, filesystem, model, or
// generic callback capability.
type SkillLookupAuthority interface {
	AuthorizeSkill(context.Context, SkillLookupRequest) (
		skillregistry.AccessDecision, skillregistry.ResolutionAuthority, error)
}

type SkillLookupActivity struct {
	registry  skillregistry.Registry
	authority SkillLookupAuthority
}

func NewSkillLookupActivity(registry skillregistry.Registry,
	authority SkillLookupAuthority) (*SkillLookupActivity, error) {
	if registry == nil || authority == nil {
		return nil, newError(InvalidInput, "new_skill_lookup", "dependencies_required", false, nil)
	}
	return &SkillLookupActivity{registry: registry, authority: authority}, nil
}

func (activity *SkillLookupActivity) Lookup(ctx context.Context,
	request SkillLookupRequest) (SkillLookupResult, error) {
	if activity == nil || activity.registry == nil || activity.authority == nil {
		return SkillLookupResult{}, newError(InvalidInput, "skill_lookup", "activity_required", false, nil)
	}
	if err := validateContext(ctx, "skill_lookup"); err != nil {
		return SkillLookupResult{}, err
	}
	if !uuidV7Pattern.MatchString(request.RequestID) || !validateCase(request.Case) ||
		!uuidV7Pattern.MatchString(request.TaskID) || !uuidV7Pattern.MatchString(request.ActorID) ||
		!tokenPattern.MatchString(request.SkillName) || !digestPattern.MatchString(request.ExpectedManifestDigest) ||
		!tokenPattern.MatchString(request.RequiredPermission) || !digestPattern.MatchString(request.PolicyDigest) ||
		request.Deadline.IsZero() || request.Deadline.Location() != time.UTC {
		return SkillLookupResult{}, newError(InvalidInput, "skill_lookup", "request_invalid", false, nil)
	}
	decision, authority, err := activity.authority.AuthorizeSkill(ctx, request)
	if err != nil {
		return SkillLookupResult{}, err
	}
	resolved, err := activity.registry.Resolve(ctx, skillregistry.ResolveRequest{
		SchemaVersion: skillregistry.ResolveSchemaVersion, ContractVersion: skillregistry.ContractVersion,
		RequestID: request.RequestID, OrganizationID: request.Case.OrganizationID,
		TenantID: request.Case.TenantID, CaseID: request.Case.CaseID, TaskID: request.TaskID,
		ActorID: request.ActorID, SkillName: request.SkillName,
		ExpectedManifestDigest: request.ExpectedManifestDigest,
		RequiredPermission:     request.RequiredPermission, PolicyDigest: request.PolicyDigest,
		Deadline: request.Deadline,
	}, decision, authority)
	if err != nil {
		return SkillLookupResult{}, mapSkillError(err)
	}
	resources := make([]SkillResourceRef, len(resolved.Resources))
	for index, resource := range resolved.Resources {
		resources[index] = SkillResourceRef{Name: resource.Name, Digest: resource.Digest,
			MediaType: resource.MediaType, Classification: resource.Classification, Length: resource.Length}
	}
	return SkillLookupResult{
		SkillName: resolved.SkillName, SkillVersion: resolved.SkillVersion,
		ManifestDigest: resolved.ManifestDigest, ContentDigest: resolved.ContentDigest,
		Resources: resources, Permissions: append([]string(nil), resolved.Permissions...),
		OwnerActorID: resolved.OwnerActorID, ReviewID: resolved.ReviewID,
		ReviewRevision: resolved.ReviewRevision, ProvenanceDigest: resolved.ProvenanceDigest,
	}, nil
}

func mapSkillError(err error) error {
	switch skillregistry.CodeOf(err) {
	case skillregistry.InvalidInput:
		return newError(InvalidInput, "skill_lookup", "registry_input_invalid", false, err)
	case skillregistry.Denied:
		return newError(Denied, "skill_lookup", "registry_denied", false, err)
	case skillregistry.NotFound:
		return newError(NotFound, "skill_lookup", "skill_not_found", false, err)
	case skillregistry.Conflict:
		return newError(Conflict, "skill_lookup", "registry_conflict", false, err)
	case skillregistry.Canceled:
		return newError(Canceled, "skill_lookup", "lookup_canceled", false, err)
	case skillregistry.Timeout:
		return newError(Timeout, "skill_lookup", "lookup_timeout", false, err)
	default:
		return newError(Unavailable, "skill_lookup", "registry_unavailable",
			skillregistry.Retryable(err), err)
	}
}
