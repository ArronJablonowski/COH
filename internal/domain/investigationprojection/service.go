package investigationprojection

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"sync"
	"time"
)

type cachedProjection struct {
	query            Query
	stateVersion     StateVersion
	watermark        Watermark
	checkpointDigest string
	projectionDigest string
	projection       Projection
}

type currentHead struct {
	version   StateVersion
	watermark Watermark
}

type Service struct {
	dependencies Dependencies
	mu           sync.RWMutex
	heads        map[Scope]currentHead
	cache        map[string]cachedProjection
}

func NewService(dependencies Dependencies) (*Service, error) {
	if nilPort(dependencies.Authority) || nilPort(dependencies.Facts) || nilPort(dependencies.Checkpoints) ||
		nilPort(dependencies.Evidence) {
		return nil, newError(InvalidInputError, DependencyUnavailable, nil)
	}
	return &Service{dependencies: dependencies, heads: make(map[Scope]currentHead),
		cache: make(map[string]cachedProjection)}, nil
}

// NotifyCurrent is called by the trusted authoritative-head subscription. It
// invalidates every cached result for the scope except an exact head/version
// match. It performs no storage I/O.
func (service *Service) NotifyCurrent(scope Scope, version StateVersion, watermark Watermark) error {
	if service == nil || !validScope(scope) || !validStateVersion(version) || !validWatermark(watermark) ||
		version.AuthoritativeStateDigest != watermark.AuthoritativeStateDigest {
		return newError(InvalidInputError, InvalidInput, nil)
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	service.heads[scope] = currentHead{version: version, watermark: watermark}
	for key, entry := range service.cache {
		if entry.query.Scope == scope && (entry.query.StateVersion != version || !sameWatermark(entry.watermark, watermark)) {
			delete(service.cache, key)
		}
	}
	return nil
}

func (service *Service) Read(ctx context.Context, query Query) (Projection, error) {
	if service == nil {
		return Projection{}, newError(InvalidInputError, DependencyUnavailable, nil)
	}
	if err := checkContext(ctx); err != nil {
		return Projection{}, err
	}
	if projection, found := service.loadCached(query); found {
		deadline, _ := time.Parse(timestampLayout, query.Deadline)
		if !time.Now().Before(deadline) {
			return Projection{}, newError(TimeoutError, ContextDeadline, context.DeadlineExceeded)
		}
		return projection, nil
	}
	if err := validateBoundQuery(ctx, query); err != nil {
		return Projection{}, err
	}
	deadline, _ := time.Parse(timestampLayout, query.Deadline)
	workContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	target, err := service.verifyTarget(workContext, query)
	if err != nil {
		return Projection{}, serviceError(workContext, err)
	}
	projection, err := service.build(workContext, query, target)
	if err != nil {
		return Projection{}, serviceError(workContext, err)
	}
	return cloneProjection(projection), nil
}

func (service *Service) verifyTarget(ctx context.Context, query Query) (Watermark, error) {
	if query.Consistency == "exact" {
		if err := service.dependencies.Authority.VerifyExact(ctx, query.Scope, query.StateVersion, *query.RequestedWatermark); err != nil {
			return Watermark{}, err
		}
		return *query.RequestedWatermark, nil
	}
	watermark, err := service.dependencies.Authority.VerifyCurrent(ctx, query.Scope, query.StateVersion)
	if err != nil {
		return Watermark{}, err
	}
	if !validWatermark(watermark) || watermark.AuthoritativeStateDigest != query.StateVersion.AuthoritativeStateDigest {
		return Watermark{}, newError(DeniedError, AuthorityDenied, nil)
	}
	if err := service.NotifyCurrent(query.Scope, query.StateVersion, watermark); err != nil {
		return Watermark{}, err
	}
	return watermark, nil
}

func (service *Service) build(ctx context.Context, query Query, target Watermark) (Projection, error) {
	reducer, err := NewReducer(query.Kind)
	if err != nil {
		return Projection{}, err
	}
	projection, checkpoint, found, err := service.dependencies.Checkpoints.LoadLatest(ctx, query.Scope, query.Kind)
	if err != nil {
		return Projection{}, err
	}
	var state *ReductionState
	var previousCheckpointDigest *string
	if found {
		state, err = verifiedReductionState(ctx, projection, checkpoint)
		if err != nil {
			return Projection{}, err
		}
		digest := checkpoint.CheckpointDigest
		previousCheckpointDigest = &digest
		if state.StateVersion == query.StateVersion && (query.Consistency == "current" && state.Watermark.Sequence > target.Sequence ||
			state.Watermark.Sequence == target.Sequence && !sameWatermark(state.Watermark, target)) {
			return Projection{}, newError(ConflictError, IntegrityFailure, nil)
		}
		if state.StateVersion != query.StateVersion || state.Watermark.Sequence > target.Sequence ||
			state.Watermark.Sequence == target.Sequence && !sameWatermark(state.Watermark, target) {
			state = nil
		}
	}
	after := uint64(0)
	if state != nil {
		after = state.Watermark.Sequence
		if sameWatermark(state.Watermark, target) {
			if !withinOutputBound(state.Value, query.MaxOutputs) {
				return Projection{}, newError(InvalidInputError, InvalidInput, nil)
			}
			service.storeCached(query, target, projection, checkpoint.CheckpointDigest)
			return projection, nil
		}
	}
	if target.Sequence-after > uint64(query.MaxFacts) {
		return Projection{}, newError(InvalidInputError, InvalidInput, nil)
	}
	facts, err := service.dependencies.Facts.LoadFacts(ctx, query.Scope, after, target.Sequence)
	if err != nil {
		return Projection{}, err
	}
	if uint64(len(facts)) != target.Sequence-after {
		return Projection{}, newError(ConflictError, IntegrityFailure, nil)
	}
	for _, fact := range facts {
		state, err = reducer.Reduce(ctx, state, fact, query.StateVersion)
		if err != nil {
			return Projection{}, err
		}
	}
	if state == nil {
		state, err = emptyReductionState(query, target)
		if err != nil {
			return Projection{}, err
		}
	}
	if !sameWatermark(state.Watermark, target) || state.StateVersion != query.StateVersion ||
		!withinOutputBound(state.Value, query.MaxOutputs) {
		return Projection{}, newError(ConflictError, IntegrityFailure, nil)
	}
	evidence, err := service.dependencies.Evidence.BuildProjectionEvidence(ctx, EvidenceRequest{Scope: query.Scope,
		Kind: query.Kind, StateVersion: query.StateVersion, Watermark: target, FactSetDigest: state.FactSetDigest})
	if err != nil {
		return Projection{}, err
	}
	candidate, candidateCheckpoint, err := buildRecords(ctx, state, evidence, previousCheckpointDigest)
	if err != nil {
		return Projection{}, err
	}
	committedProjection, committedCheckpoint, err := service.commitAndReconcile(ctx, previousCheckpointDigest,
		candidate, candidateCheckpoint)
	if err != nil {
		return Projection{}, err
	}
	if _, verifyErr := verifiedReductionState(ctx, committedProjection, committedCheckpoint); verifyErr != nil ||
		committedProjection.ProjectionDigest != candidate.ProjectionDigest ||
		committedCheckpoint.CheckpointDigest != candidateCheckpoint.CheckpointDigest {
		return Projection{}, newError(ConflictError, ProjectionDivergent, verifyErr)
	}
	service.storeCached(query, target, committedProjection, committedCheckpoint.CheckpointDigest)
	return committedProjection, nil
}

func withinOutputBound(value *Value, maximum uint32) bool {
	return value != nil && len(value.Claims) <= int(maximum) && len(value.Hypotheses) <= int(maximum) &&
		len(value.Timeline) <= int(maximum)
}

func (service *Service) commitAndReconcile(ctx context.Context, previous *string, projection Projection,
	checkpoint Checkpoint) (Projection, Checkpoint, error) {
	committedProjection, committedCheckpoint, err := service.dependencies.Checkpoints.Commit(ctx, previous, projection, checkpoint)
	if err == nil {
		return committedProjection, committedCheckpoint, nil
	}
	loadedProjection, loadedCheckpoint, found, loadErr := service.dependencies.Checkpoints.LoadLatest(ctx, projection.Scope, projection.Kind)
	if loadErr != nil {
		return Projection{}, Checkpoint{}, loadErr
	}
	if !found || loadedProjection.ProjectionDigest != projection.ProjectionDigest ||
		loadedCheckpoint.CheckpointDigest != checkpoint.CheckpointDigest {
		return Projection{}, Checkpoint{}, err
	}
	return loadedProjection, loadedCheckpoint, nil
}

func (service *Service) loadCached(query Query) (Projection, bool) {
	if query.Consistency != "current" {
		return Projection{}, false
	}
	service.mu.RLock()
	defer service.mu.RUnlock()
	entry, found := service.cache[query.QueryDigest]
	head, known := service.heads[query.Scope]
	return cloneProjection(entry.projection), found && known && entry.query == query &&
		entry.stateVersion == query.StateVersion && head.version == query.StateVersion &&
		digestPattern.MatchString(entry.checkpointDigest) && entry.projectionDigest == entry.projection.ProjectionDigest &&
		sameWatermark(head.watermark, entry.watermark)
}

func (service *Service) storeCached(query Query, watermark Watermark, projection Projection, checkpointDigest string) {
	if query.Consistency != "current" || !digestPattern.MatchString(checkpointDigest) {
		return
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	head, known := service.heads[query.Scope]
	if known && head.version == query.StateVersion && sameWatermark(head.watermark, watermark) {
		service.cache[query.QueryDigest] = cachedProjection{query: query, stateVersion: query.StateVersion,
			watermark: watermark, checkpointDigest: checkpointDigest, projectionDigest: projection.ProjectionDigest,
			projection: cloneProjection(projection)}
	}
}

func validateBoundQuery(ctx context.Context, query Query) error {
	if err := validateQuery(ctx, query); err != nil {
		return err
	}
	provided := query.QueryDigest
	query.QueryDigest = ""
	_, calculated, err := canonicalValue(query)
	if err != nil || provided != calculated {
		return newError(InvalidInputError, IntegrityFailure, err)
	}
	return nil
}

func emptyReductionState(query Query, target Watermark) (*ReductionState, error) {
	if target.Sequence != 0 || target.HeadFactDigest != nil {
		return nil, newError(ConflictError, IntegrityFailure, nil)
	}
	_, digest, err := canonicalValue([]string{})
	if err != nil {
		return nil, err
	}
	return &ReductionState{Scope: query.Scope, StateVersion: query.StateVersion, Watermark: target,
		FactSetDigest: digest, Value: &Value{Kind: query.Kind, Claims: []Claim{}, Hypotheses: []HypothesisValue{},
			Timeline: []TimelineEntry{}, Completeness: Completeness{Status: "unknown", QueriedSourceDigests: []string{},
				CompletedSourceDigests: []string{}, GapDigests: []string{}, NegativeEvidenceDigests: []string{},
				ConflictDigests: []string{}}}}, nil
}

func serviceError(ctx context.Context, err error) error {
	if ctxErr := checkContext(ctx); ctxErr != nil {
		return ctxErr
	}
	if Code(err) != "" {
		return err
	}
	return newError(UnavailableError, DependencyUnavailable, err)
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return slicesNilKind(reflected.Kind()) && reflected.IsNil()
}

func slicesNilKind(kind reflect.Kind) bool {
	return kind == reflect.Chan || kind == reflect.Func || kind == reflect.Interface || kind == reflect.Map ||
		kind == reflect.Pointer || kind == reflect.Slice
}

func sameWatermark(left, right Watermark) bool {
	return left.Sequence == right.Sequence && left.CommittedAt == right.CommittedAt &&
		left.AuthoritativeStateDigest == right.AuthoritativeStateDigest && (left.HeadFactDigest == nil && right.HeadFactDigest == nil ||
		left.HeadFactDigest != nil && right.HeadFactDigest != nil && *left.HeadFactDigest == *right.HeadFactDigest)
}

func deterministicUUID(seed string) string {
	value := sha256.Sum256([]byte(seed))
	value[6] = value[6]&0x0f | 0x70
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}
