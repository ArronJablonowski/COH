package agentloop

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/workflow/skilldiscovery"
)

const SkillDiscoveryActivityName = "coh.agent-loop.skill-discovery.v1"

// ProgressiveSkillDiscovery is the only skill capability supplied to the
// agent loop. It cannot promote skills, retrieve arbitrary content, execute a
// skill, or bypass phase authorization.
type ProgressiveSkillDiscovery interface {
	Search(context.Context, skilldiscovery.SearchRequest) (skilldiscovery.SearchResult, error)
	Detail(context.Context, skilldiscovery.DetailRequest) (skilldiscovery.DetailResult, error)
	Resource(context.Context, skilldiscovery.ResourceRequest) (skilldiscovery.ResourceResult, error)
}

type SkillDiscoveryActivity struct{ discovery ProgressiveSkillDiscovery }

func NewSkillDiscoveryActivity(discovery ProgressiveSkillDiscovery) (*SkillDiscoveryActivity, error) {
	if discovery == nil {
		return nil, newError(InvalidInput, "skill_discovery", "dependency_required", false, nil)
	}
	return &SkillDiscoveryActivity{discovery: discovery}, nil
}

func (activity *SkillDiscoveryActivity) Search(ctx context.Context,
	request skilldiscovery.SearchRequest) (skilldiscovery.SearchResult, error) {
	if activity == nil || activity.discovery == nil {
		return skilldiscovery.SearchResult{}, newError(Unavailable, "skill_discovery", "activity_unavailable", true, nil)
	}
	result, err := activity.discovery.Search(ctx, request)
	if err != nil {
		return skilldiscovery.SearchResult{}, mapDiscoveryError(err)
	}
	return result, nil
}

func (activity *SkillDiscoveryActivity) Detail(ctx context.Context,
	request skilldiscovery.DetailRequest) (skilldiscovery.DetailResult, error) {
	if activity == nil || activity.discovery == nil {
		return skilldiscovery.DetailResult{}, newError(Unavailable, "skill_discovery", "activity_unavailable", true, nil)
	}
	result, err := activity.discovery.Detail(ctx, request)
	if err != nil {
		return skilldiscovery.DetailResult{}, mapDiscoveryError(err)
	}
	return result, nil
}

func (activity *SkillDiscoveryActivity) Resource(ctx context.Context,
	request skilldiscovery.ResourceRequest) (skilldiscovery.ResourceResult, error) {
	if activity == nil || activity.discovery == nil {
		return skilldiscovery.ResourceResult{}, newError(Unavailable, "skill_discovery", "activity_unavailable", true, nil)
	}
	result, err := activity.discovery.Resource(ctx, request)
	if err != nil {
		return skilldiscovery.ResourceResult{}, mapDiscoveryError(err)
	}
	return result, nil
}

func mapDiscoveryError(err error) error {
	switch skilldiscovery.CodeOf(err) {
	case skilldiscovery.InvalidInput:
		return newError(InvalidInput, "skill_discovery", "request_invalid", false, err)
	case skilldiscovery.Denied:
		return newError(Denied, "skill_discovery", "discovery_denied", false, err)
	case skilldiscovery.NotFound:
		return newError(NotFound, "skill_discovery", "skill_not_found", false, err)
	case skilldiscovery.Conflict:
		return newError(Conflict, "skill_discovery", "discovery_conflict", false, err)
	case skilldiscovery.Canceled:
		return newError(Canceled, "skill_discovery", "discovery_canceled", false, err)
	case skilldiscovery.Timeout:
		return newError(Timeout, "skill_discovery", "discovery_timeout", false, err)
	default:
		return newError(Unavailable, "skill_discovery", "discovery_unavailable",
			skilldiscovery.Retryable(err), err)
	}
}
