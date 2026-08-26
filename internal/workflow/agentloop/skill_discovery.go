package agentloop

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/workflow/retrievalguard"
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

// HostileContentGuard is the only content-release capability supplied to
// model-facing retrieval activities. It returns immutable sanitized data refs.
type HostileContentGuard interface {
	Inspect(context.Context, retrievalguard.Request) (retrievalguard.Result, error)
}

type SkillResourceRequest struct {
	Discovery                skilldiscovery.ResourceRequest
	ActorRevision            uint64
	InspectionIdempotencyKey string
	InspectionProfile        retrievalguard.InspectionProfile
}

type SkillResourceResult struct {
	SkillName              string
	ManifestDigest         string
	ResourceName           string
	SourceDigest           string
	SourceProvenanceDigest string
	Inspection             retrievalguard.InspectionResult
	AuditEventDigest       string
	ProvenanceDigest       string
	Replayed               bool
}

type SkillDiscoveryActivity struct {
	discovery ProgressiveSkillDiscovery
	guard     HostileContentGuard
}

func NewSkillDiscoveryActivity(discovery ProgressiveSkillDiscovery, guard HostileContentGuard) (*SkillDiscoveryActivity, error) {
	if discovery == nil || guard == nil {
		return nil, newError(InvalidInput, "skill_discovery", "dependencies_required", false, nil)
	}
	return &SkillDiscoveryActivity{discovery: discovery, guard: guard}, nil
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

func (activity *SkillDiscoveryActivity) Resource(ctx context.Context, request SkillResourceRequest) (SkillResourceResult, error) {
	if activity == nil || activity.discovery == nil || activity.guard == nil {
		return SkillResourceResult{}, newError(Unavailable, "skill_discovery", "activity_unavailable", true, nil)
	}
	result, err := activity.discovery.Resource(ctx, request.Discovery)
	if err != nil {
		return SkillResourceResult{}, mapDiscoveryError(err)
	}
	guarded, err := activity.guard.Inspect(ctx, retrievalguard.Request{
		SchemaVersion: retrievalguard.RequestSchemaVersion, ContractVersion: retrievalguard.ContractVersion,
		RequestID: request.Discovery.RequestID, IdempotencyKey: request.InspectionIdempotencyKey,
		Case: request.Discovery.Case, TaskID: request.Discovery.TaskID, ActorID: request.Discovery.ActorID,
		ActorRevision: request.ActorRevision,
		Source: retrievalguard.Source{Kind: retrievalguard.DocumentSource, Artifact: result.Artifact,
			Trust: retrievalguard.UntrustedContent, ProvenanceDigest: result.ProvenanceDigest},
		Profile: request.InspectionProfile, PolicyDigest: request.Discovery.PolicyDigest,
		Deadline: request.Discovery.Deadline,
	})
	if err != nil {
		return SkillResourceResult{}, mapRetrievalError("skill_resource", err)
	}
	return SkillResourceResult{SkillName: result.SkillName, ManifestDigest: result.ManifestDigest,
		ResourceName: result.ResourceName, SourceDigest: result.Artifact.Digest,
		SourceProvenanceDigest: result.ProvenanceDigest, Inspection: guarded.Inspection,
		AuditEventDigest: guarded.AuditEventDigest, ProvenanceDigest: guarded.ProvenanceDigest,
		Replayed: result.Replayed || guarded.Replayed}, nil
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
