package agentloop

import (
	"context"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/workflow/recoverycontrol"
)

// IntentResolver returns the exact immutable tool intent previously bound to
// an action step. It returns no execution capability; Resume still routes the
// intent through the broker-owned ActionAuthority.
type IntentResolver interface {
	ResolveIntent(context.Context, domain.CaseRef, string) (domain.ToolIntent, error)
}

// RecoveryControlAdapter exposes only inspection, idempotent resume, and child
// cancellation. It cannot invoke a connector or executor directly.
type RecoveryControlAdapter struct {
	loop    *Loop
	intents IntentResolver
}

func NewRecoveryControlAdapter(loop *Loop, intents IntentResolver) (*RecoveryControlAdapter, error) {
	if loop == nil || intents == nil {
		return nil, newError(InvalidInput, "recovery_adapter", "dependencies_required", false, nil)
	}
	return &RecoveryControlAdapter{loop: loop, intents: intents}, nil
}

func (adapter *RecoveryControlAdapter) Inspect(ctx context.Context,
	lookup recoverycontrol.WorkLookup) (recoverycontrol.WorkSnapshot, error) {
	if adapter == nil || adapter.loop == nil {
		return recoverycontrol.WorkSnapshot{}, recoverycontrol.NewDependencyError(
			recoverycontrol.Internal, "agent_loop_unavailable", false, true)
	}
	snapshot, err := adapter.loop.load(ctx, lookup.Case, lookup.RunID)
	if err != nil {
		return recoverycontrol.WorkSnapshot{}, mapRecoveryError(err)
	}
	if snapshot.Step.StepID != lookup.TaskID {
		return recoverycontrol.WorkSnapshot{}, recoverycontrol.NewDependencyError(
			recoverycontrol.DeniedCode, "scope_or_task_mismatch", false, false)
	}
	return recoverySnapshot(snapshot), nil
}

func (adapter *RecoveryControlAdapter) Resume(ctx context.Context,
	request recoverycontrol.WorkResume) (recoverycontrol.WorkSnapshot, error) {
	if adapter == nil || adapter.loop == nil || adapter.intents == nil {
		return recoverycontrol.WorkSnapshot{}, recoverycontrol.NewDependencyError(
			recoverycontrol.Internal, "agent_loop_unavailable", false, true)
	}
	current, err := adapter.loop.load(ctx, request.Case, request.RunID)
	if err != nil {
		return recoverycontrol.WorkSnapshot{}, mapRecoveryError(err)
	}
	if current.Step.StepID != request.TaskID || current.Step.ProvenanceDigest != request.ExpectedProvenanceDigest ||
		current.Step.IntentDigest != request.IntentDigest {
		return recoverycontrol.WorkSnapshot{}, recoverycontrol.NewDependencyError(
			recoverycontrol.DeniedCode, "resume_binding_invalid", false, false)
	}
	var intent *domain.ToolIntent
	if current.Step.Kind == AuthorizedActionActivity {
		resolved, resolveErr := adapter.intents.ResolveIntent(ctx, request.Case, request.IntentDigest)
		if resolveErr != nil {
			return recoverycontrol.WorkSnapshot{}, recoverycontrol.NewDependencyError(
				recoverycontrol.Unavailable, "intent_unavailable", true, false)
		}
		intent = &resolved
	}
	result, err := adapter.loop.Resume(ctx, ResumeRequest{IdempotencyKey: request.IdempotencyKey,
		Case: request.Case, RunID: request.RunID, Intent: intent})
	if err != nil {
		return recoverycontrol.WorkSnapshot{}, mapRecoveryError(err)
	}
	return recoverySnapshot(result), nil
}

func (adapter *RecoveryControlAdapter) CancelChild(ctx context.Context,
	command recoverycontrol.CancelCommand) (recoverycontrol.CancellationAck, error) {
	if adapter == nil || adapter.loop == nil {
		return recoverycontrol.CancellationAck{}, recoverycontrol.NewDependencyError(
			recoverycontrol.Internal, "agent_loop_unavailable", false, true)
	}
	current, err := adapter.loop.load(ctx, command.Case, command.RunID)
	if err != nil {
		return recoverycontrol.CancellationAck{}, mapRecoveryError(err)
	}
	if command.Target.Kind != recoverycontrol.ChildTask || current.Step.StepID != command.Target.TargetID ||
		current.Step.ProvenanceDigest != command.Target.ExpectedProvenanceDigest || current.Step.StepID == command.RootTaskID {
		return recoverycontrol.CancellationAck{}, recoverycontrol.NewDependencyError(
			recoverycontrol.DeniedCode, "child_binding_invalid", false, false)
	}
	if current.Step.Status == StepDispatching {
		return recoverycontrol.CancellationAck{}, recoverycontrol.NewDependencyError(
			recoverycontrol.Conflict, "child_dispatch_outcome_uncertain", false, true)
	}
	alreadyTerminal := terminalStep(current.Step.Status)
	result, err := adapter.loop.Terminate(ctx, TerminateRequest{IdempotencyKey: command.IdempotencyKey,
		Case: command.Case, RunID: command.RunID, StepID: command.Target.TargetID,
		Outcome: TerminalCanceled, ReasonDigest: command.ReasonDigest})
	if err != nil {
		return recoverycontrol.CancellationAck{}, mapRecoveryError(err)
	}
	outcome := recoverycontrol.AckCanceled
	if alreadyTerminal {
		outcome = recoverycontrol.AckAlreadyTerminal
	}
	return recoverycontrol.CancellationAck{Sequence: command.Target.Sequence, Kind: command.Target.Kind,
		TargetID: command.Target.TargetID, Outcome: outcome,
		EvidenceDigest: result.Step.ProvenanceDigest, ProvenanceDigest: result.Run.ProvenanceDigest}, nil
}

func recoverySnapshot(value Snapshot) recoverycontrol.WorkSnapshot {
	sideEffect := recoverycontrol.NoSideEffect
	if value.Step.Status == StepDispatching {
		sideEffect = recoverycontrol.IndeterminateSideEffect
	} else if value.Step.ReceiptDigest != "" {
		sideEffect = recoverycontrol.ConfirmedSideEffect
	}
	terminalEvidence := ""
	if terminalStep(value.Step.Status) {
		terminalEvidence = value.Step.ProvenanceDigest
	}
	return recoverycontrol.WorkSnapshot{Case: value.Run.Case, RunID: value.Run.RunID, TaskID: value.Step.StepID,
		Status: recoveryStatus(value.Step.Status), SideEffect: sideEffect, IntentDigest: value.Step.IntentDigest,
		ReceiptDigest: value.Step.ReceiptDigest, ProvenanceDigest: value.Step.ProvenanceDigest,
		TerminalEvidence: terminalEvidence}
}

func recoveryStatus(value StepStatus) recoverycontrol.WorkStatus {
	switch value {
	case StepPending:
		return recoverycontrol.WorkPending
	case StepRunning, StepDispatching:
		return recoverycontrol.WorkRunning
	case StepSucceeded:
		return recoverycontrol.WorkWaiting
	case StepFailed:
		return recoverycontrol.WorkFailed
	case StepDenied:
		return recoverycontrol.WorkDenied
	case StepCanceled:
		return recoverycontrol.WorkCanceled
	case StepTimeout:
		return recoverycontrol.WorkTimeout
	default:
		return recoverycontrol.WorkUncertain
	}
}

func mapRecoveryError(err error) error {
	switch Code(err) {
	case Denied, InvalidInput:
		return recoverycontrol.NewDependencyError(recoverycontrol.DeniedCode, Reason(err), false, false)
	case Canceled:
		return recoverycontrol.NewDependencyError(recoverycontrol.CanceledCode, Reason(err), false, false)
	case Timeout:
		return recoverycontrol.NewDependencyError(recoverycontrol.Timeout, Reason(err), false, false)
	case Conflict:
		return recoverycontrol.NewDependencyError(recoverycontrol.Conflict, Reason(err), false, false)
	default:
		return recoverycontrol.NewDependencyError(recoverycontrol.Unavailable, Reason(err), true, false)
	}
}

var _ recoverycontrol.WorkCoordinator = (*RecoveryControlAdapter)(nil)
var _ recoverycontrol.ChildTaskCanceler = (*RecoveryControlAdapter)(nil)
