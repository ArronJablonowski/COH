package recoverycontrol

import (
	"context"
	"time"
)

type Controller struct {
	store     Store
	work      WorkCoordinator
	children  ChildTaskCanceler
	jobs      ToolJobCanceler
	routes    RouteAuthority
	providers ProviderInvoker
	clock     Clock
}

func New(store Store, work WorkCoordinator, children ChildTaskCanceler, jobs ToolJobCanceler,
	routes RouteAuthority, providers ProviderInvoker, clock Clock) (*Controller, error) {
	if store == nil || work == nil || children == nil || jobs == nil || routes == nil || providers == nil || clock == nil {
		return nil, newError(InvalidInput, "dependencies_required", false, false, nil)
	}
	return &Controller{store: store, work: work, children: children, jobs: jobs,
		routes: routes, providers: providers, clock: clock}, nil
}

func (controller *Controller) now() (time.Time, error) {
	if controller == nil || controller.clock == nil {
		return time.Time{}, newError(Internal, "clock_unavailable", false, false, nil)
	}
	value := controller.clock.Now().UTC()
	if !validTime(value) {
		return time.Time{}, newError(Internal, "clock_unavailable", false, false, nil)
	}
	return value, nil
}

func (controller *Controller) load(ctx context.Context, record Record, intent, idempotency string) (Record, bool, error) {
	current, found, err := controller.store.Load(ctx, record.Case, record.ControlID)
	if err != nil {
		return Record{}, false, mapDependency(ctx, "store_load", err)
	}
	if !found {
		return Record{}, false, nil
	}
	if err := validateRecord(current); err != nil || current.Kind != record.Kind || current.Case != record.Case ||
		current.RunID != record.RunID || current.TaskID != record.TaskID || current.IntentDigest != intent ||
		current.IdempotencyDigest != idempotency {
		return Record{}, false, newError(DeniedCode, "replay_binding_invalid", false, false, nil)
	}
	return current, true, nil
}

func (controller *Controller) begin(ctx context.Context, key string, value Record) (Record, bool, error) {
	stored, replayed, err := controller.store.Begin(ctx, key, cloneRecord(value))
	if err != nil {
		return Record{}, false, mapDependency(ctx, "store_begin", err)
	}
	if err := validateRecord(stored); err != nil || stored.IntentDigest != value.IntentDigest ||
		stored.IdempotencyDigest != value.IdempotencyDigest {
		return Record{}, false, newError(DeniedCode, "store_result_invalid", false, false, nil)
	}
	return stored, replayed, nil
}

func sealInitial(value *Record) error {
	value.Revision = 1
	value.PreviousProvenanceDigest = ""
	digest, err := provenanceDigest("", value.ReasonCode, *value)
	if err != nil {
		return err
	}
	value.ProvenanceDigest = digest
	return validateRecord(*value)
}

func (controller *Controller) save(ctx context.Context, key string, current, next Record) (Record, error) {
	now, err := controller.now()
	if err != nil {
		return current, err
	}
	next.PreviousProvenanceDigest = current.ProvenanceDigest
	next.UpdatedAt = now
	next.Revision = current.Revision + 1
	digest, err := provenanceDigest(current.ProvenanceDigest, next.ReasonCode, next)
	if err != nil {
		return current, err
	}
	next.ProvenanceDigest = digest
	if err := validateRecord(next); err != nil {
		return current, err
	}
	stored, err := controller.store.Save(ctx, key, cloneRecord(current), cloneRecord(next))
	if err != nil {
		return current, mapDependency(ctx, "store_save", err)
	}
	if err := validateRecord(stored); err != nil || stored.ProvenanceDigest != next.ProvenanceDigest {
		return current, newError(DeniedCode, "store_result_invalid", false, false, nil)
	}
	return stored, nil
}

func mapDependency(ctx context.Context, reason string, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return mapContext(ctx.Err())
	}
	if ErrorCode(err) != Unavailable {
		return err
	}
	return newError(Unavailable, reason, true, Indeterminate(err), nil)
}

func resultFrom(value Record, replayed bool) Result {
	return Result{ControlID: value.ControlID, Kind: value.Kind, Status: value.Status,
		Work: value.ResultWork, Acknowledgments: cloneAcknowledgments(value.Acknowledgments),
		Route: value.Route, Attempts: append([]ProviderAttempt{}, value.Attempts...),
		Artifact: value.ResultArtifact, ProvenanceDigest: value.ProvenanceDigest, Replayed: replayed}
}

func idempotencyDigest(key string) string {
	return compactDigest("COH-RECOVERY-CONTROL-IDEMPOTENCY-V1\x00", []byte(key))
}

var _ Control = (*Controller)(nil)
