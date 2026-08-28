package modelsurface

import (
	"bytes"
	"context"
)

type ValidatedTransition = ValidatedDocument[Transition]

// TransitionStore provides atomic, append-only transition persistence.
type TransitionStore interface {
	CreateTransition(context.Context, string, ValidatedTransition) ([]byte, bool, error)
	CompareAndSwapTransition(context.Context, string, string, ValidatedTransition) ([]byte, bool, error)
	ReadLatestTransition(context.Context, string) ([]byte, bool, error)
	ReadTransition(context.Context, string) ([]byte, bool, error)
}

// RecoveryReader reloads the exact durable records referenced by a transition.
type RecoveryReader interface {
	ReadProjection(context.Context, string) ([]byte, bool, error)
	ReadBinding(context.Context, string) ([]byte, bool, error)
	ReadStreamEvent(context.Context, string, string, uint64) ([]byte, bool, error)
}

type ProjectionReplayer interface {
	Reproject(context.Context, Projection) (ProjectedSurface, error)
}

type RecoveryController struct {
	transitions TransitionStore
	records     RecoveryReader
	replayer    ProjectionReplayer
}

type AdvanceTransition struct {
	TransitionID    string
	Phase           string
	BindingDigest   string
	StreamCursor    uint64
	TerminalOutcome string
	UpdatedAt       string
}

type RecoveryState struct {
	Transition ValidatedTransition
	Directive  string
}

func NewRecoveryController(transitions TransitionStore, records RecoveryReader, replayer ProjectionReplayer) (*RecoveryController, error) {
	if transitions == nil || records == nil || replayer == nil {
		return nil, newError(InvalidInput, "recovery_dependencies")
	}
	return &RecoveryController{transitions: transitions, records: records, replayer: replayer}, nil
}

// Prepare is idempotent only for the exact same canonical transition.
func (controller *RecoveryController) Prepare(ctx context.Context, key string, transition Transition) (ValidatedTransition, bool, error) {
	if controller == nil || controller.transitions == nil || !validToken(key) || transition.Phase != "prepared" ||
		transition.Revision != 1 || transition.PreviousTransitionDigest != "" {
		return ValidatedTransition{}, false, newError(InvalidInput, "recovery_prepare")
	}
	validated, err := validatedTransition(ctx, transition)
	if err != nil {
		return ValidatedTransition{}, false, err
	}
	if err := controller.verifyReferences(ctx, validated.Value()); err != nil {
		return ValidatedTransition{}, false, err
	}
	stored, created, err := controller.transitions.CreateTransition(ctx, key, validated)
	if err != nil {
		return ValidatedTransition{}, false, mapRecoveryError(ctx, "transition_unavailable")
	}
	decoded, err := DecodeTransition(ctx, stored)
	if err != nil {
		return ValidatedTransition{}, false, newError(Denied, "transition_tamper")
	}
	if !bytes.Equal(decoded.CanonicalBytes(), validated.CanonicalBytes()) {
		return ValidatedTransition{}, false, newError(Denied, "changed_replay")
	}
	return decoded, !created, nil
}

func (controller *RecoveryController) Advance(ctx context.Context, key string, current ValidatedTransition, request AdvanceTransition) (ValidatedTransition, error) {
	if controller == nil || controller.transitions == nil || !validToken(key) || !validUUID7(request.TransitionID) || !validTimestamp(request.UpdatedAt) {
		return ValidatedTransition{}, newError(InvalidInput, "recovery_advance")
	}
	value, err := verifiedTransition(ctx, current)
	if err != nil {
		return ValidatedTransition{}, err
	}
	next := value
	next.TransitionID, next.Phase, next.Revision = request.TransitionID, request.Phase, value.Revision+1
	next.BindingDigest, next.StreamCursor, next.TerminalOutcome = request.BindingDigest, request.StreamCursor, request.TerminalOutcome
	next.PreviousTransitionDigest, next.TransitionDigest, next.UpdatedAt = value.TransitionDigest, "", request.UpdatedAt
	if !validTransitionAdvance(value, next) {
		return ValidatedTransition{}, newError(Denied, "transition_advance")
	}
	if err := controller.verifyReferences(ctx, next); err != nil {
		return ValidatedTransition{}, err
	}
	validated, err := validatedTransition(ctx, next)
	if err != nil {
		return ValidatedTransition{}, err
	}
	stored, swapped, err := controller.transitions.CompareAndSwapTransition(ctx, key, value.TransitionDigest, validated)
	if err != nil {
		return ValidatedTransition{}, mapRecoveryError(ctx, "transition_unavailable")
	}
	if !swapped {
		return ValidatedTransition{}, newError(Denied, "transition_conflict")
	}
	decoded, err := DecodeTransition(ctx, stored)
	if err != nil || !bytes.Equal(decoded.CanonicalBytes(), validated.CanonicalBytes()) {
		return ValidatedTransition{}, newError(Denied, "transition_tamper")
	}
	return decoded, nil
}

// Fork begins a new request lineage from an explicit terminal parent.
func (controller *RecoveryController) Fork(ctx context.Context, key string, parent ValidatedTransition, fork Transition) (ValidatedTransition, bool, error) {
	parentValue, err := verifiedTransition(ctx, parent)
	if err != nil {
		return ValidatedTransition{}, false, err
	}
	if parentValue.Phase != "terminal" || fork.Phase != "prepared" || fork.RequestID == parentValue.RequestID ||
		fork.AttemptID == parentValue.AttemptID || fork.Scope != parentValue.Scope || fork.Revision != parentValue.Revision+1 ||
		fork.PreviousTransitionDigest != parentValue.TransitionDigest || fork.ProviderAttempt != 1 {
		return ValidatedTransition{}, false, newError(Denied, "fork_lineage")
	}
	return controller.createBranch(ctx, key, fork)
}

// BeginFallback starts a new provider attempt only after an explicit failed
// terminal result and retains the exact request input lineage.
func (controller *RecoveryController) BeginFallback(ctx context.Context, key string, parent ValidatedTransition, fallback Transition) (ValidatedTransition, bool, error) {
	parentValue, err := verifiedTransition(ctx, parent)
	if err != nil {
		return ValidatedTransition{}, false, err
	}
	if parentValue.Phase != "terminal" || parentValue.TerminalOutcome != "failed" || fallback.Phase != "prepared" ||
		fallback.RequestID != parentValue.RequestID || fallback.AttemptID == parentValue.AttemptID || fallback.Scope != parentValue.Scope ||
		fallback.RunID != parentValue.RunID || fallback.ProjectionDigest != parentValue.ProjectionDigest ||
		fallback.ProviderRoute == parentValue.ProviderRoute || fallback.ProviderAttempt != parentValue.ProviderAttempt+1 ||
		fallback.Revision != parentValue.Revision+1 || fallback.PreviousTransitionDigest != parentValue.TransitionDigest {
		return ValidatedTransition{}, false, newError(Denied, "fallback_transition")
	}
	return controller.createBranch(ctx, key, fallback)
}

func (controller *RecoveryController) createBranch(ctx context.Context, key string, transition Transition) (ValidatedTransition, bool, error) {
	if controller == nil || controller.transitions == nil || !validToken(key) {
		return ValidatedTransition{}, false, newError(InvalidInput, "recovery_branch")
	}
	validated, err := validatedTransition(ctx, transition)
	if err != nil {
		return ValidatedTransition{}, false, err
	}
	if err := controller.verifyReferences(ctx, validated.Value()); err != nil {
		return ValidatedTransition{}, false, err
	}
	stored, created, err := controller.transitions.CreateTransition(ctx, key, validated)
	if err != nil {
		return ValidatedTransition{}, false, mapRecoveryError(ctx, "transition_unavailable")
	}
	decoded, err := DecodeTransition(ctx, stored)
	if err != nil {
		return ValidatedTransition{}, false, newError(Denied, "transition_tamper")
	}
	if !bytes.Equal(decoded.CanonicalBytes(), validated.CanonicalBytes()) {
		return ValidatedTransition{}, false, newError(Denied, "changed_replay")
	}
	return decoded, !created, nil
}

func (controller *RecoveryController) Recover(ctx context.Context, key string) (RecoveryState, error) {
	if controller == nil || controller.transitions == nil || controller.records == nil || controller.replayer == nil || !validToken(key) {
		return RecoveryState{}, newError(InvalidInput, "recovery_request")
	}
	raw, found, err := controller.transitions.ReadLatestTransition(ctx, key)
	if err != nil {
		return RecoveryState{}, mapRecoveryError(ctx, "transition_unavailable")
	}
	if !found {
		return RecoveryState{}, newError(Denied, "transition_missing")
	}
	latest, err := DecodeTransition(ctx, raw)
	if err != nil {
		return RecoveryState{}, newError(Denied, "transition_tamper")
	}
	if err := controller.verifyChain(ctx, latest); err != nil {
		return RecoveryState{}, err
	}
	if err := controller.verifyReferences(ctx, latest.Value()); err != nil {
		return RecoveryState{}, err
	}
	directive := map[string]string{"prepared": "verify", "verified": "dispatch", "dispatched": "mark_uncertain", "streaming": "resume_stream", "terminal": "complete"}[latest.Value().Phase]
	return RecoveryState{Transition: latest, Directive: directive}, nil
}

func (controller *RecoveryController) verifyChain(ctx context.Context, latest ValidatedTransition) error {
	child := latest.Value()
	for steps := 0; child.Revision > 1; steps++ {
		if steps >= MaximumItems {
			return newError(Denied, "transition_chain_size")
		}
		raw, found, err := controller.transitions.ReadTransition(ctx, child.PreviousTransitionDigest)
		if err != nil {
			return mapRecoveryError(ctx, "transition_unavailable")
		}
		if !found {
			return newError(Denied, "transition_chain_missing")
		}
		parentDoc, err := DecodeTransition(ctx, raw)
		if err != nil || parentDoc.Digest() != child.PreviousTransitionDigest {
			return newError(Denied, "transition_chain_tamper")
		}
		parent := parentDoc.Value()
		if parent.Revision+1 != child.Revision || !validTransitionRelation(parent, child) {
			return newError(Denied, "transition_chain")
		}
		child = parent
	}
	if child.PreviousTransitionDigest != "" {
		return newError(Denied, "transition_chain")
	}
	return nil
}

func (controller *RecoveryController) verifyReferences(ctx context.Context, transition Transition) error {
	rawProjection, found, err := controller.records.ReadProjection(ctx, transition.ProjectionDigest)
	if err != nil {
		return mapRecoveryError(ctx, "projection_unavailable")
	}
	if !found {
		return newError(Denied, "projection_missing")
	}
	projection, err := DecodeProjection(ctx, rawProjection)
	if err != nil || projection.Digest() != transition.ProjectionDigest || projection.Value().Scope != transition.Scope || projection.Value().RunID != transition.RunID {
		return newError(Denied, "recovery_projection")
	}
	replayed, replayErr := controller.replayer.Reproject(ctx, projection.Value())
	if replayErr != nil || replayed.Projection().ProjectionDigest != projection.Digest() ||
		replayed.Projection().SurfaceDigest != projection.Value().SurfaceDigest {
		return newError(Denied, "recovery_reprojection")
	}
	if transition.BindingDigest != "" {
		rawBinding, bindingFound, readErr := controller.records.ReadBinding(ctx, transition.BindingDigest)
		if readErr != nil {
			return mapRecoveryError(ctx, "binding_unavailable")
		}
		if !bindingFound {
			return newError(Denied, "binding_missing")
		}
		binding, decodeErr := DecodeBinding(ctx, rawBinding)
		value := binding.Value()
		if decodeErr != nil || binding.Digest() != transition.BindingDigest || value.RequestID != transition.RequestID ||
			value.AttemptID != transition.AttemptID || value.Scope != transition.Scope || value.RunID != transition.RunID ||
			value.ProjectionDigest != transition.ProjectionDigest || value.ProviderID != transition.ProviderRoute {
			return newError(Denied, "recovery_binding")
		}
	}
	if transition.StreamCursor > 0 {
		rawEvent, eventFound, readErr := controller.records.ReadStreamEvent(ctx, transition.RequestID, transition.AttemptID, transition.StreamCursor)
		if readErr != nil {
			return mapRecoveryError(ctx, "stream_unavailable")
		}
		if !eventFound {
			return newError(Denied, "stream_missing")
		}
		event, decodeErr := DecodeStreamEvent(ctx, rawEvent)
		value := event.Value()
		if decodeErr != nil || value.Sequence != transition.StreamCursor || value.RequestID != transition.RequestID ||
			value.AttemptID != transition.AttemptID || value.BindingDigest != transition.BindingDigest ||
			value.ProjectionDigest != transition.ProjectionDigest || transition.Phase == "terminal" &&
			(value.Kind != "terminal" || value.Outcome != transition.TerminalOutcome) {
			return newError(Denied, "recovery_stream")
		}
	}
	if oneOf(transition.Phase, "streaming", "terminal") && transition.StreamCursor == 0 {
		return newError(Denied, "recovery_stream")
	}
	return nil
}

func validatedTransition(ctx context.Context, value Transition) (ValidatedTransition, error) {
	raw, _, err := CanonicalTransition(ctx, value)
	if err != nil {
		return ValidatedTransition{}, err
	}
	return DecodeTransition(ctx, raw)
}
func verifiedTransition(ctx context.Context, value ValidatedTransition) (Transition, error) {
	decoded, err := DecodeTransition(ctx, value.CanonicalBytes())
	if err != nil || decoded.Digest() != value.Digest() {
		return Transition{}, newError(Denied, "transition_tamper")
	}
	return decoded.Value(), nil
}
func validTransitionAdvance(current, next Transition) bool {
	if next.Revision != current.Revision+1 || next.PreviousTransitionDigest != current.TransitionDigest || next.CreatedAt != current.CreatedAt ||
		next.RequestID != current.RequestID || next.AttemptID != current.AttemptID || next.Scope != current.Scope || next.RunID != current.RunID ||
		next.ProjectionDigest != current.ProjectionDigest || next.ProviderRoute != current.ProviderRoute || next.ProviderAttempt != current.ProviderAttempt {
		return false
	}
	switch current.Phase {
	case "prepared":
		return next.Phase == "verified"
	case "verified":
		return next.Phase == "dispatched"
	case "dispatched":
		return oneOf(next.Phase, "streaming", "terminal")
	case "streaming":
		return oneOf(next.Phase, "streaming", "terminal") && next.StreamCursor > current.StreamCursor
	default:
		return false
	}
}
func validTransitionRelation(parent, child Transition) bool {
	if child.RequestID == parent.RequestID && child.AttemptID == parent.AttemptID {
		return validTransitionAdvance(parent, child)
	}
	if parent.Phase != "terminal" || child.Phase != "prepared" || child.Scope != parent.Scope {
		return false
	}
	if child.RequestID != parent.RequestID {
		return child.AttemptID != parent.AttemptID && child.ProviderAttempt == 1
	}
	return parent.TerminalOutcome == "failed" && child.AttemptID != parent.AttemptID && child.RunID == parent.RunID &&
		child.ProjectionDigest == parent.ProjectionDigest && child.ProviderRoute != parent.ProviderRoute &&
		child.ProviderAttempt == parent.ProviderAttempt+1
}
func mapRecoveryError(ctx context.Context, reason string) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	return newError(Unavailable, reason)
}
