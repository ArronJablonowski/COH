package profileactivation

import (
	"context"
)

type Controller struct {
	store Store
	gate  MaintenanceGate
	clock Clock
}

func NewController(store Store, gate MaintenanceGate, clock Clock) (*Controller, error) {
	if store == nil || gate == nil || clock == nil {
		return nil, newError(InvalidInput, "dependencies")
	}
	return &Controller{store: store, gate: gate, clock: clock}, nil
}

// Activate is also the restart recovery entrypoint. Callers must reconstruct
// Request from newly verified immutable profile inputs on every invocation.
func (controller *Controller) Activate(ctx context.Context, request Request) (Result, error) {
	if err := contextError(ctx); err != nil {
		return Result{}, err
	}
	if controller == nil || controller.store == nil || controller.gate == nil || controller.clock == nil {
		return Result{}, newError(InvalidInput, "controller")
	}
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	intent, err := intentDigest(request)
	if err != nil {
		return Result{}, newError(InvalidInput, "activation_intent")
	}
	transition, found, err := controller.store.LoadTransition(ctx, request.TransitionID)
	if err != nil {
		return Result{}, normalizeDependency(err, "transition_load")
	}
	replayed := found
	if found {
		if transition.IntentDigest != intent || transition.Candidate != request.Candidate ||
			transition.Mode != request.Mode || transition.MaxDrainDurationMS != request.MaxDrainDurationMS ||
			transition.ExpectedActiveRevision != request.ExpectedActiveRevision ||
			transition.ExpectedCompositionDigest != request.ExpectedCompositionDigest {
			return Result{}, newError(Denied, "transition_replay_drift")
		}
	} else {
		if err := controller.validateCurrent(ctx, request); err != nil {
			return Result{}, err
		}
		now := formatTime(controller.clock.Now())
		transition = Transition{SchemaVersion: TransitionSchema, ContractVersion: ContractVersion,
			TransitionID: request.TransitionID, IntentDigest: intent, Mode: request.Mode,
			MaxDrainDurationMS: request.MaxDrainDurationMS, Candidate: request.Candidate,
			ExpectedActiveRevision:    request.ExpectedActiveRevision,
			ExpectedCompositionDigest: request.ExpectedCompositionDigest, Phase: Prepared, Sequence: 1,
			CreatedAt: now, UpdatedAt: now}
		transition, err = controller.store.CreateTransition(ctx, transition)
		if err != nil {
			return Result{}, normalizeDependency(err, "transition_create")
		}
	}
	return controller.continueActivation(ctx, transition, replayed)
}

func (controller *Controller) validateCurrent(ctx context.Context, request Request) error {
	active, found, err := controller.store.LoadActive(ctx, request.Candidate.ProfileID, request.Candidate.Target)
	if err != nil {
		return normalizeDependency(err, "active_load")
	}
	if !found {
		if request.ExpectedActiveRevision != 0 || request.ExpectedCompositionDigest != "" {
			return newError(Denied, "active_lineage")
		}
		return nil
	}
	if request.Mode == Startup {
		return newError(Denied, "startup_replacement")
	}
	if active.ProfileRevision != request.ExpectedActiveRevision ||
		active.CompositionDigest != request.ExpectedCompositionDigest {
		return newError(Denied, "active_lineage")
	}
	if active.CompositionDigest == request.Candidate.CompositionDigest {
		return newError(Denied, "already_active")
	}
	return nil
}

func (controller *Controller) continueActivation(ctx context.Context, transition Transition, replayed bool) (Result, error) {
	plan := QuiescencePlan{TransitionID: transition.TransitionID, ProfileID: transition.Candidate.ProfileID,
		CompositionDigest: transition.Candidate.CompositionDigest, Mode: transition.Mode,
		MaxDrainDurationMS: transition.MaxDrainDurationMS}
	for steps := 0; steps < 4; steps++ {
		if err := contextError(ctx); err != nil {
			return Result{}, err
		}
		switch transition.Phase {
		case Prepared:
			attestation, err := controller.gate.Quiesce(ctx, plan)
			if err != nil {
				return Result{}, normalizeDependency(err, "quiescence")
			}
			if !validAttestation(attestation, transition.TransitionID) {
				return Result{}, newError(Denied, "quiescence_attestation")
			}
			transition, err = controller.store.AdvanceTransition(ctx, transition.TransitionID,
				transition.Sequence, transition.TransitionDigest, Quiescent, attestation.AttestationDigest)
			if err != nil {
				return Result{}, normalizeDependency(err, "quiescence_commit")
			}
		case Quiescent:
			attestation, err := controller.gate.Quiesce(ctx, plan)
			if err != nil {
				return Result{}, normalizeDependency(err, "quiescence_recovery")
			}
			if !validAttestation(attestation, transition.TransitionID) ||
				attestation.AttestationDigest != transition.QuiescenceDigest {
				return Result{}, newError(Denied, "quiescence_drift")
			}
			active := activeFromTransition(transition, formatTime(controller.clock.Now()))
			transition, err = controller.store.Publish(ctx, transition.TransitionID, transition.Sequence,
				transition.TransitionDigest, active, attestation.AttestationDigest)
			if err != nil {
				return Result{}, normalizeDependency(err, "publication")
			}
		case Published:
			attestation, err := controller.gate.Quiesce(ctx, plan)
			if err != nil {
				return Result{}, normalizeDependency(err, "release_recovery")
			}
			if !validAttestation(attestation, transition.TransitionID) ||
				attestation.AttestationDigest != transition.QuiescenceDigest {
				return Result{}, newError(Denied, "quiescence_drift")
			}
			if err := controller.gate.Release(ctx, attestation); err != nil {
				return Result{}, normalizeDependency(err, "release")
			}
			transition, err = controller.store.AdvanceTransition(ctx, transition.TransitionID,
				transition.Sequence, transition.TransitionDigest, Active, transition.QuiescenceDigest)
			if err != nil {
				return Result{}, normalizeDependency(err, "activation_commit")
			}
		case Active:
			profile, found, err := controller.store.LoadActive(ctx, transition.Candidate.ProfileID, transition.Candidate.Target)
			if err != nil {
				return Result{}, normalizeDependency(err, "active_recovery")
			}
			if !found || profile.TransitionID != transition.TransitionID ||
				profile.CompositionDigest != transition.Candidate.CompositionDigest {
				return Result{}, newError(Denied, "active_publication_drift")
			}
			return Result{Transition: transition, Profile: profile, Replayed: replayed}, nil
		default:
			return Result{}, newError(Denied, "transition_phase")
		}
	}
	return Result{}, newError(Unavailable, "transition_steps")
}

func activeFromTransition(value Transition, activatedAt string) ActiveProfile {
	candidate := value.Candidate
	return ActiveProfile{SchemaVersion: ActiveProfileSchema, ContractVersion: ContractVersion,
		ProfileID: candidate.ProfileID, ProfileRevision: candidate.ProfileRevision, Target: candidate.Target,
		ProfileBindingDigest: candidate.ProfileBindingDigest, CompositionDigest: candidate.CompositionDigest,
		CapabilityGraphDigest: candidate.CapabilityGraphDigest, InspectionDigest: candidate.InspectionDigest,
		TransitionID: value.TransitionID, ActivatedAt: activatedAt}
}

func normalizeDependency(err error, reason string) error {
	if err == nil {
		return nil
	}
	if code := Code(err); code != "" {
		return err
	}
	return newError(Unavailable, reason)
}
