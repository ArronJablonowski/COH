package contextcompact

import (
	"context"
	"time"
)

type Controller struct {
	store    Store
	resolver EvidenceResolver
	writer   SummaryWriter
	clock    Clock
}

func New(store Store, resolver EvidenceResolver, writer SummaryWriter, clock Clock) (*Controller, error) {
	if store == nil || resolver == nil || writer == nil || clock == nil {
		return nil, newError(InvalidInput, "compaction_dependencies", false, nil)
	}
	return &Controller{store: store, resolver: resolver, writer: writer, clock: clock}, nil
}

func (controller *Controller) Compact(ctx context.Context, request Request) (Result, error) {
	if controller == nil || controller.store == nil || controller.resolver == nil ||
		controller.writer == nil || controller.clock == nil {
		return Result{}, newError(Unavailable, "compaction_unavailable", true, nil)
	}
	if err := validateContext(ctx); err != nil {
		return Result{}, err
	}
	now := controller.clock.Now().UTC()
	if !validTime(now) {
		return Result{}, newError(Internal, "compaction_clock_unavailable", false, nil)
	}
	if err := validateRequest(request, now); err != nil {
		return Result{}, err
	}
	intent, idempotency, err := requestDigests(request)
	if err != nil {
		return Result{}, err
	}
	current, found, err := controller.store.Load(ctx, request.Intent.Case, request.Intent.CompactionID)
	if err != nil {
		return Result{}, mapStoreError(ctx, "compaction_store_load", err)
	}
	if found {
		return controller.replayOrRecover(ctx, request, current, intent, idempotency, now)
	}
	if !now.Before(request.Intent.Deadline) {
		return Result{}, newError(Timeout, "compaction_deadline_elapsed", false, nil)
	}
	if err := controller.resolveSources(ctx, request.Intent); err != nil {
		return Result{}, err
	}
	candidate, err := initialState(request, intent, idempotency, now)
	if err != nil {
		return Result{}, err
	}
	stored, replayed, err := controller.store.Begin(ctx, request.IdempotencyKey+":compaction", candidate)
	if err != nil {
		return Result{}, mapStoreError(ctx, "compaction_store_begin", err)
	}
	if replayed {
		return controller.replayOrRecover(ctx, request, stored, intent, idempotency, now)
	}
	if err := validateState(stored); err != nil || stored.ProvenanceDigest != candidate.ProvenanceDigest {
		return Result{}, newError(Denied, "compaction_store_result_invalid", false, nil)
	}
	return controller.writeSummary(ctx, request, stored)
}

func (controller *Controller) replayOrRecover(ctx context.Context, request Request, current State,
	intent, idempotency string, now time.Time) (Result, error) {
	if err := validateState(current); err != nil {
		return Result{}, err
	}
	if current.Case != request.Intent.Case || current.CompactionID != request.Intent.CompactionID ||
		current.IntentDigest != intent || current.IdempotencyDigest != idempotency {
		return Result{}, newError(Denied, "compaction_replay_binding", false, nil)
	}
	if current.Status == StatusCompleted {
		result := stateResult(current)
		result.Replayed = true
		return result, nil
	}
	if current.Status == StatusWriting {
		if now.Before(current.Deadline) {
			return stateResult(current), newError(Conflict, "compaction_in_progress", true, nil)
		}
		uncertain, err := controller.transition(ctx, request.IdempotencyKey+":recovery", current,
			StatusUncertain, "summary_outcome_uncertain", now)
		if err != nil {
			return stateResult(current), err
		}
		return stateResult(uncertain), newError(Conflict, "compaction_outcome_uncertain", false, nil)
	}
	result := stateResult(current)
	result.Replayed = true
	return result, newError(Conflict, "compaction_outcome_uncertain", false, nil)
}

func (controller *Controller) writeSummary(ctx context.Context, request Request, current State) (Result, error) {
	remaining := current.Deadline.Sub(current.UpdatedAt)
	if remaining <= 0 {
		return controller.failAfterWrite(ctx, request.IdempotencyKey, current, context.DeadlineExceeded)
	}
	// The persisted domain clock owns deadline semantics. Converting its
	// remaining budget to a duration avoids coupling an injected/replayed clock
	// to the process wall clock used internally by context.
	writeCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	summary, err := controller.writer.Write(writeCtx, SummaryRequest{CompactionID: current.CompactionID,
		RunID: current.RunID, TaskID: current.TaskID, Case: current.Case,
		Sources: cloneSources(current.Sources), Deadline: current.Deadline})
	if err != nil {
		return controller.failAfterWrite(writeCtx, request.IdempotencyKey, current, err)
	}
	if writeCtx.Err() != nil {
		return controller.failAfterWrite(writeCtx, request.IdempotencyKey, current, writeCtx.Err())
	}
	if !validArtifact(summary) {
		uncertain, transitionErr := controller.markUncertain(ctx, request.IdempotencyKey, current, "summary_reference_invalid")
		if transitionErr != nil {
			return stateResult(current), transitionErr
		}
		return stateResult(uncertain), newError(Denied, "compaction_summary_invalid", false, nil)
	}
	now := controller.clock.Now().UTC()
	if !validTime(now) {
		return stateResult(current), newError(Internal, "compaction_clock_unavailable", false, nil)
	}
	next := cloneState(current)
	next.Summary = summary
	if err := stampState(&next, current, StatusCompleted, "summary_completed", now); err != nil {
		return stateResult(current), err
	}
	stored, err := controller.store.Save(ctx, request.IdempotencyKey+":completed", current, next)
	if err != nil {
		return stateResult(current), mapStoreError(ctx, "compaction_store_save", err)
	}
	if err := validateState(stored); err != nil || stored.ProvenanceDigest != next.ProvenanceDigest {
		return stateResult(current), newError(Denied, "compaction_store_result_invalid", false, nil)
	}
	return stateResult(stored), nil
}

func (controller *Controller) failAfterWrite(ctx context.Context, key string, current State,
	writerErr error) (Result, error) {
	state, transitionErr := controller.markUncertain(ctx, key, current, writerReason(ctx, writerErr))
	if transitionErr != nil {
		return stateResult(current), transitionErr
	}
	if ctx != nil && ctx.Err() != nil {
		return stateResult(state), mapContext(ctx.Err())
	}
	return stateResult(state), newError(Unavailable, "compaction_writer_unavailable", true, nil)
}

func (controller *Controller) markUncertain(ctx context.Context, key string, current State,
	reason string) (State, error) {
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	now := controller.clock.Now().UTC()
	if !validTime(now) {
		return current, newError(Internal, "compaction_clock_unavailable", false, nil)
	}
	return controller.transition(persistCtx, key+":uncertain", current, StatusUncertain, reason, now)
}

func (controller *Controller) transition(ctx context.Context, key string, current State,
	status Status, reason string, now time.Time) (State, error) {
	next := cloneState(current)
	if err := stampState(&next, current, status, reason, now); err != nil {
		return current, err
	}
	stored, err := controller.store.Save(ctx, key, current, next)
	if err != nil {
		return current, mapStoreError(ctx, "compaction_store_save", err)
	}
	if err := validateState(stored); err != nil || stored.ProvenanceDigest != next.ProvenanceDigest {
		return current, newError(Denied, "compaction_store_result_invalid", false, nil)
	}
	return stored, nil
}

func initialState(request Request, intent, idempotency string, now time.Time) (State, error) {
	manifest, err := sourceManifestDigest(request.Intent.Sources)
	if err != nil {
		return State{}, err
	}
	value := State{SchemaVersion: request.Intent.SchemaVersion, ContractVersion: request.Intent.ContractVersion,
		CompactionID: request.Intent.CompactionID, RunID: request.Intent.RunID, TaskID: request.Intent.TaskID,
		Case: request.Intent.Case, PolicyDigest: request.Intent.PolicyDigest, ProviderRoute: request.Intent.ProviderRoute,
		Sources: cloneSources(request.Intent.Sources), SourceManifestDigest: manifest,
		IntentDigest: intent, IdempotencyDigest: idempotency,
		SummaryTrust: UntrustedEvidence, Status: StatusWriting, ReasonCode: "summary_writing", CreatedAt: request.Intent.CreatedAt,
		Deadline: request.Intent.Deadline, UpdatedAt: now, Revision: 1}
	provenance, err := provenanceDigest("", value.ReasonCode, value)
	if err != nil {
		return State{}, err
	}
	value.ProvenanceDigest = provenance
	if err := validateState(value); err != nil {
		return State{}, err
	}
	return value, nil
}

func stampState(next *State, prior State, status Status, reason string, now time.Time) error {
	if prior.Revision >= uint64(^uint64(0)>>1) {
		return newError(Denied, "compaction_revision_exhausted", false, nil)
	}
	next.Status = status
	next.ReasonCode = reason
	next.PreviousProvenanceDigest = prior.ProvenanceDigest
	next.UpdatedAt = now
	next.Revision = prior.Revision + 1
	provenance, err := provenanceDigest(prior.ProvenanceDigest, reason, *next)
	if err != nil {
		return err
	}
	next.ProvenanceDigest = provenance
	return validateState(*next)
}

func requestDigests(request Request) (string, string, error) {
	intent, err := intentDigest(request.Intent)
	if err != nil {
		return "", "", err
	}
	idempotency := compactDigest("COH-CONTEXT-COMPACTION-IDEMPOTENCY-V1\x00", []byte(request.IdempotencyKey))
	return intent, idempotency, nil
}

func stateResult(value State) Result {
	return Result{CompactionID: value.CompactionID, IntentDigest: value.IntentDigest, Summary: value.Summary,
		SummaryTrust: value.SummaryTrust,
		Sources:      cloneSources(value.Sources), SourceManifestDigest: value.SourceManifestDigest,
		Status: value.Status, ProvenanceDigest: value.ProvenanceDigest}
}

func writerReason(ctx context.Context, _ error) string {
	if ctx != nil && ctx.Err() == context.Canceled {
		return "summary_canceled"
	}
	if ctx != nil && ctx.Err() == context.DeadlineExceeded {
		return "summary_timeout"
	}
	return "summary_dependency_unavailable"
}

func mapStoreError(ctx context.Context, reason string, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return mapContext(ctx.Err())
	}
	if ErrorCode(err) != Unavailable {
		return err
	}
	return newError(Unavailable, reason, true, nil)
}

func (controller *Controller) resolveSources(ctx context.Context, intent Intent) error {
	for _, source := range intent.Sources {
		if err := controller.resolver.Resolve(ctx, EvidenceLookup{Case: intent.Case,
			EvidenceID: source.EvidenceID, EvidenceDigest: source.EvidenceDigest}); err != nil {
			if ctx != nil && ctx.Err() != nil {
				return mapContext(ctx.Err())
			}
			if ErrorCode(err) != Unavailable {
				return err
			}
			return newError(Unavailable, "compaction_evidence_unavailable", true, nil)
		}
	}
	return nil
}

var _ Compactor = (*Controller)(nil)
