package skilldiscovery

import (
	"context"
	"slices"
	"strings"

	"github.com/ArronJablonowski/COH/internal/workflow/skillregistry"
)

type Controller struct {
	catalog   skillregistry.Catalog
	registry  Registry
	authority Authority
	retriever Retriever
	store     Store
	clock     Clock
}

func New(catalog skillregistry.Catalog, registry Registry, authority Authority,
	retriever Retriever, store Store, clock Clock) (*Controller, error) {
	if catalog == nil || registry == nil || authority == nil || retriever == nil || store == nil || clock == nil {
		return nil, newError(InvalidInput, "dependencies_required", false, nil)
	}
	return &Controller{catalog: catalog, registry: registry, authority: authority,
		retriever: retriever, store: store, clock: clock}, nil
}

func (controller *Controller) Search(ctx context.Context, request SearchRequest) (SearchResult, error) {
	if err := controller.ready(ctx); err != nil {
		return SearchResult{}, err
	}
	now, err := controller.now()
	if err != nil {
		return SearchResult{}, err
	}
	if err := validateSearch(request, now); err != nil {
		return SearchResult{}, err
	}
	ctx, cancel := operationContext(ctx, request.Deadline, now)
	defer cancel()
	intent, err := intentDigest(request)
	if err != nil {
		return SearchResult{}, err
	}
	idempotency := idempotencyDigest(request.IdempotencyKey)
	if _, _, err := controller.loadReplay(ctx, request.Case, request.TaskID, CompactSearch,
		idempotency, intent); err != nil {
		return SearchResult{}, err
	}
	snapshot, err := controller.catalog.LoadCatalog(ctx, request.Case.OrganizationID, request.Case.TenantID)
	if err != nil {
		return SearchResult{}, mapRegistryError(err)
	}
	if err := validateCatalog(snapshot, request.Case); err != nil {
		return SearchResult{}, err
	}
	if request.ExpectedSnapshotDigest != "" && request.ExpectedSnapshotDigest != snapshot.SnapshotDigest {
		return SearchResult{}, newError(Denied, "stale_catalog_snapshot", false, nil)
	}
	query := strings.ToLower(request.Query)
	matching := make([]skillregistry.PromotedSkillRef, 0, len(snapshot.Entries))
	for _, entry := range snapshot.Entries {
		if query == "" || strings.Contains(strings.ToLower(entry.SkillName), query) {
			matching = append(matching, entry)
		}
	}
	offset, err := searchOffset(request, snapshot.SnapshotDigest, len(matching))
	if err != nil {
		return SearchResult{}, err
	}
	gate := AuthorizationRequest{RequestID: request.RequestID, Case: request.Case,
		TaskID: request.TaskID, ActorID: request.ActorID, PolicyDigest: request.PolicyDigest,
		Phase: CompactSearch, RequiredPermission: request.RequiredPermission,
		QueryDigest: queryDigest(request.Query), SnapshotDigest: snapshot.SnapshotDigest,
		Cursor: request.Cursor, PageLimit: request.Limit, Deadline: request.Deadline}
	gateDecision, _, _, err := controller.authorize(ctx, gate, now)
	if err != nil {
		return SearchResult{}, err
	}
	decisionDigests := []string{gateDecision.DecisionDigest}
	end := offset + int(request.Limit)
	if end > len(matching) {
		end = len(matching)
	}
	result := SearchResult{Skills: make([]CompactSkill, 0, end-offset), SnapshotDigest: snapshot.SnapshotDigest}
	for index, entry := range matching[offset:end] {
		if err := contextError(ctx); err != nil {
			return SearchResult{}, err
		}
		candidateRequestID := operationRequestID(request.RequestID, CompactSearch, entry.SkillName, offset+index)
		authorization := gate
		authorization.RequestID = candidateRequestID
		authorization.SkillName = entry.SkillName
		authorization.ManifestDigest = entry.ManifestDigest
		decision, access, authority, err := controller.authorize(ctx, authorization, now)
		if err != nil {
			return SearchResult{}, err
		}
		resolved, err := controller.resolve(ctx, authorization, access, authority, entry.ProvenanceDigest)
		if err != nil {
			return SearchResult{}, err
		}
		decisionDigests = append(decisionDigests, decision.DecisionDigest)
		result.Skills = append(result.Skills, CompactSkill{SkillName: resolved.SkillName,
			SkillVersion: resolved.SkillVersion, ManifestDigest: resolved.ManifestDigest,
			ProvenanceDigest: resolved.ProvenanceDigest})
	}
	if end < len(matching) {
		result.NextCursor = cursorFor(request, snapshot.SnapshotDigest, end)
	}
	result.ResultDigest, err = searchResultDigest(result)
	if err != nil {
		return SearchResult{}, err
	}
	record, err := newRecord(request.Case, request.TaskID, request.ActorID, request.PolicyDigest,
		request.RequiredPermission, CompactSearch, idempotency, intent,
		decisionDigests, &result, nil, nil, now)
	if err != nil {
		return SearchResult{}, err
	}
	stored, replayed, err := controller.commit(ctx, request.IdempotencyKey, record)
	if err != nil {
		return SearchResult{}, err
	}
	result = cloneSearch(*stored.Search)
	result.Replayed = replayed
	return result, nil
}

func (controller *Controller) Detail(ctx context.Context, request DetailRequest) (DetailResult, error) {
	if err := controller.ready(ctx); err != nil {
		return DetailResult{}, err
	}
	now, err := controller.now()
	if err != nil {
		return DetailResult{}, err
	}
	if err := validateDetail(request, now); err != nil {
		return DetailResult{}, err
	}
	ctx, cancel := operationContext(ctx, request.Deadline, now)
	defer cancel()
	intent, _ := intentDigest(request)
	idempotency := idempotencyDigest(request.IdempotencyKey)
	if _, _, err := controller.loadReplay(ctx, request.Case, request.TaskID, DetailExpand,
		idempotency, intent); err != nil {
		return DetailResult{}, err
	}
	parent, err := controller.loadParent(ctx, request.Case, request.TaskID, request.ActorID,
		request.PolicyDigest, request.RequiredPermission, CompactSearch, request.SearchIdempotencyKey)
	if err != nil {
		return DetailResult{}, err
	}
	if parent.Search == nil || parent.Search.ResultDigest != request.ExpectedSearchResultDigest ||
		slices.IndexFunc(parent.Search.Skills, func(skill CompactSkill) bool {
			return skill.SkillName == request.SkillName && skill.ManifestDigest == request.ExpectedManifestDigest
		}) < 0 {
		return DetailResult{}, newError(Denied, "compact_parent_mismatch", false, nil)
	}
	authorization := AuthorizationRequest{RequestID: request.RequestID, Case: request.Case,
		TaskID: request.TaskID, ActorID: request.ActorID, PolicyDigest: request.PolicyDigest,
		Phase: DetailExpand, SkillName: request.SkillName, ManifestDigest: request.ExpectedManifestDigest,
		RequiredPermission: request.RequiredPermission, QueryDigest: queryDigest(""),
		SnapshotDigest:     request.ExpectedManifestDigest,
		ParentResultDigest: request.ExpectedSearchResultDigest, Deadline: request.Deadline}
	decision, access, authority, err := controller.authorize(ctx, authorization, now)
	if err != nil {
		return DetailResult{}, err
	}
	resolved, err := controller.resolve(ctx, authorization, access, authority, "")
	if err != nil {
		return DetailResult{}, err
	}
	result := DetailResult{SkillName: resolved.SkillName, SkillVersion: resolved.SkillVersion,
		ManifestDigest: resolved.ManifestDigest, ContentDigest: resolved.ContentDigest,
		Resources: slices.Clone(resolved.Resources), Permissions: slices.Clone(resolved.Permissions),
		OwnerActorID: resolved.OwnerActorID, ReviewID: resolved.ReviewID,
		ReviewRevision: resolved.ReviewRevision, ProvenanceDigest: resolved.ProvenanceDigest}
	result.ResultDigest, err = detailResultDigest(result)
	if err != nil {
		return DetailResult{}, err
	}
	record, err := newRecord(request.Case, request.TaskID, request.ActorID, request.PolicyDigest,
		request.RequiredPermission, DetailExpand, idempotency, intent,
		[]string{decision.DecisionDigest}, nil, &result, nil, now)
	if err != nil {
		return DetailResult{}, err
	}
	stored, replayed, err := controller.commit(ctx, request.IdempotencyKey, record)
	if err != nil {
		return DetailResult{}, err
	}
	result = cloneDetail(*stored.Detail)
	result.Replayed = replayed
	return result, nil
}

func (controller *Controller) Resource(ctx context.Context, request ResourceRequest) (ResourceResult, error) {
	if err := controller.ready(ctx); err != nil {
		return ResourceResult{}, err
	}
	now, err := controller.now()
	if err != nil {
		return ResourceResult{}, err
	}
	if err := validateResource(request, now); err != nil {
		return ResourceResult{}, err
	}
	ctx, cancel := operationContext(ctx, request.Deadline, now)
	defer cancel()
	intent, _ := intentDigest(request)
	idempotency := idempotencyDigest(request.IdempotencyKey)
	if _, _, err := controller.loadReplay(ctx, request.Case, request.TaskID, ResourceFetch,
		idempotency, intent); err != nil {
		return ResourceResult{}, err
	}
	parent, err := controller.loadParent(ctx, request.Case, request.TaskID, request.ActorID,
		request.PolicyDigest, request.RequiredPermission, DetailExpand, request.DetailIdempotencyKey)
	if err != nil {
		return ResourceResult{}, err
	}
	if parent.Detail == nil || parent.Detail.ResultDigest != request.ExpectedDetailResultDigest ||
		parent.Detail.SkillName != request.SkillName ||
		parent.Detail.ManifestDigest != request.ExpectedManifestDigest ||
		slices.IndexFunc(parent.Detail.Resources, func(resource skillregistry.Resource) bool {
			return resource.Name == request.ResourceName && resource.Digest == request.ResourceDigest
		}) < 0 {
		return ResourceResult{}, newError(Denied, "detail_parent_mismatch", false, nil)
	}
	authorization := AuthorizationRequest{RequestID: request.RequestID, Case: request.Case,
		TaskID: request.TaskID, ActorID: request.ActorID, PolicyDigest: request.PolicyDigest,
		Phase: ResourceFetch, SkillName: request.SkillName, ManifestDigest: request.ExpectedManifestDigest,
		RequiredPermission: request.RequiredPermission, ResourceName: request.ResourceName,
		ResourceDigest: request.ResourceDigest, QueryDigest: queryDigest(""),
		SnapshotDigest:     request.ExpectedManifestDigest,
		ParentResultDigest: request.ExpectedDetailResultDigest, Deadline: request.Deadline}
	decision, access, authority, err := controller.authorize(ctx, authorization, now)
	if err != nil {
		return ResourceResult{}, err
	}
	resolved, err := controller.resolve(ctx, authorization, access, authority, "")
	if err != nil {
		return ResourceResult{}, err
	}
	index := slices.IndexFunc(resolved.Resources, func(resource skillregistry.Resource) bool {
		return resource.Name == request.ResourceName
	})
	if index < 0 || resolved.Resources[index].Digest != request.ResourceDigest {
		return ResourceResult{}, newError(Denied, "resource_manifest_mismatch", false, nil)
	}
	resource := resolved.Resources[index]
	artifact, err := controller.retriever.ResolveResource(ctx, RetrievalRequest{RequestID: request.RequestID,
		Case: request.Case, TaskID: request.TaskID, ActorID: request.ActorID,
		PolicyDigest: request.PolicyDigest, SkillName: request.SkillName,
		ManifestDigest: request.ExpectedManifestDigest, Resource: resource,
		ProvenanceDigest: resolved.ProvenanceDigest, DecisionDigest: decision.DecisionDigest,
		Deadline: request.Deadline})
	if err != nil {
		return ResourceResult{}, mapDependency(ctx, "retriever_unavailable", err)
	}
	if artifact.Digest != resource.Digest || artifact.MediaType != resource.MediaType ||
		artifact.Classification != resource.Classification || artifact.Length != resource.Length {
		return ResourceResult{}, newError(Denied, "retrieved_artifact_mismatch", false, nil)
	}
	result := ResourceResult{SkillName: request.SkillName, ManifestDigest: request.ExpectedManifestDigest,
		ResourceName: request.ResourceName, Artifact: artifact, ProvenanceDigest: resolved.ProvenanceDigest}
	result.ResultDigest, err = resourceResultDigest(result)
	if err != nil {
		return ResourceResult{}, err
	}
	record, err := newRecord(request.Case, request.TaskID, request.ActorID, request.PolicyDigest,
		request.RequiredPermission, ResourceFetch, idempotency, intent,
		[]string{decision.DecisionDigest}, nil, nil, &result, now)
	if err != nil {
		return ResourceResult{}, err
	}
	stored, replayed, err := controller.commit(ctx, request.IdempotencyKey, record)
	if err != nil {
		return ResourceResult{}, err
	}
	result = *stored.Resource
	result.Replayed = replayed
	return result, nil
}
