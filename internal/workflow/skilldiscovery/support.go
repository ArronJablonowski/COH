package skilldiscovery

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ArronJablonowski/COH/internal/workflow/skillregistry"
)

func (controller *Controller) authorize(ctx context.Context, request AuthorizationRequest,
	now time.Time) (Decision, skillregistry.AccessDecision, skillregistry.ResolutionAuthority, error) {
	decision, access, authority, err := controller.authority.AuthorizeDiscovery(ctx, request)
	if err != nil {
		return Decision{}, skillregistry.AccessDecision{}, skillregistry.ResolutionAuthority{},
			mapDependency(ctx, "authority_unavailable", err)
	}
	if err := validateDecision(decision, request, now); err != nil {
		return Decision{}, skillregistry.AccessDecision{}, skillregistry.ResolutionAuthority{}, err
	}
	return decision, access, authority, nil
}

func (controller *Controller) resolve(ctx context.Context, request AuthorizationRequest,
	access skillregistry.AccessDecision, authority skillregistry.ResolutionAuthority,
	expectedProvenance string) (skillregistry.ResolvedSkill, error) {
	resolved, err := controller.registry.Resolve(ctx, skillregistry.ResolveRequest{
		SchemaVersion: skillregistry.ResolveSchemaVersion, ContractVersion: skillregistry.ContractVersion,
		RequestID: request.RequestID, OrganizationID: request.Case.OrganizationID,
		TenantID: request.Case.TenantID, CaseID: request.Case.CaseID, TaskID: request.TaskID,
		ActorID: request.ActorID, SkillName: request.SkillName,
		ExpectedManifestDigest: request.ManifestDigest, RequiredPermission: request.RequiredPermission,
		PolicyDigest: request.PolicyDigest, Deadline: request.Deadline,
	}, access, authority)
	if err != nil {
		return skillregistry.ResolvedSkill{}, mapRegistryError(err)
	}
	if expectedProvenance == "" {
		expectedProvenance = resolved.ProvenanceDigest
	}
	if err := validateResolved(resolved, request.SkillName, request.ManifestDigest, expectedProvenance); err != nil {
		return skillregistry.ResolvedSkill{}, err
	}
	return cloneResolved(resolved), nil
}

func (controller *Controller) ready(ctx context.Context) error {
	if controller == nil || controller.catalog == nil || controller.registry == nil ||
		controller.authority == nil || controller.retriever == nil || controller.store == nil || controller.clock == nil {
		return newError(Unavailable, "controller_unavailable", true, nil)
	}
	return contextError(ctx)
}

func (controller *Controller) now() (time.Time, error) {
	now := controller.clock.Now().UTC()
	if !validTime(now) {
		return time.Time{}, newError(Internal, "clock_invalid", false, nil)
	}
	return now, nil
}

func operationContext(parent context.Context, deadline, now time.Time) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, deadline.Sub(now))
}

func searchOffset(request SearchRequest, snapshot string, maximum int) (int, error) {
	if request.Cursor == "" {
		return 0, nil
	}
	for offset := 1; offset <= maximum; offset++ {
		if cursorFor(request, snapshot, offset) == request.Cursor {
			return offset, nil
		}
	}
	return 0, newError(Denied, "cursor_invalid_or_stale", false, nil)
}

func mapRegistryError(err error) error {
	switch skillregistry.CodeOf(err) {
	case skillregistry.InvalidInput:
		return newError(InvalidInput, "registry_input_invalid", false, err)
	case skillregistry.Denied:
		return newError(Denied, "registry_denied", false, err)
	case skillregistry.NotFound:
		return newError(NotFound, "skill_not_found", false, err)
	case skillregistry.Conflict:
		return newError(Conflict, "registry_conflict", false, err)
	case skillregistry.Canceled:
		return newError(Canceled, "request_canceled", false, err)
	case skillregistry.Timeout:
		return newError(Timeout, "request_timeout", false, err)
	default:
		return newError(Unavailable, "registry_unavailable", skillregistry.Retryable(err), err)
	}
}

func mapDependency(ctx context.Context, reason string, err error) error {
	var typed *Error
	if errors.As(err, &typed) {
		return err
	}
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	if errors.Is(err, context.Canceled) {
		return newError(Canceled, "request_canceled", false, err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return newError(Timeout, "request_timeout", false, err)
	}
	return newError(Unavailable, reason, true, err)
}

func cloneResolved(value skillregistry.ResolvedSkill) skillregistry.ResolvedSkill {
	value.Resources = slices.Clone(value.Resources)
	value.Permissions = slices.Clone(value.Permissions)
	return value
}

func cloneSearch(value SearchResult) SearchResult {
	value.Skills = slices.Clone(value.Skills)
	return value
}

func cloneDetail(value DetailResult) DetailResult {
	value.Resources = slices.Clone(value.Resources)
	value.Permissions = slices.Clone(value.Permissions)
	return value
}
