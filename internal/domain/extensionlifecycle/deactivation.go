package extensionlifecycle

import (
	"bytes"
	"context"
	"fmt"
)

type DeactivationController struct {
	store   ActivationStore
	effects EffectPort
	audit   ActivationAuditPort
	gate    DeactivationGate
	clock   Clock
}

func NewDeactivationController(store ActivationStore, effects EffectPort, audit ActivationAuditPort, gate DeactivationGate, clock Clock) (*DeactivationController, error) {
	if store == nil || effects == nil || audit == nil || gate == nil || clock == nil {
		return nil, newError(InvalidInput, "deactivation_dependencies")
	}
	return &DeactivationController{store: store, effects: effects, audit: audit, gate: gate, clock: clock}, nil
}

func (controller *DeactivationController) Deactivate(ctx context.Context, admission ValidatedAdmission) (DeactivationResult, error) {
	if controller == nil || controller.store == nil || controller.effects == nil || controller.audit == nil || controller.gate == nil || controller.clock == nil {
		return DeactivationResult{}, newError(InvalidInput, "deactivation_controller")
	}
	if err := contextError(ctx); err != nil {
		return DeactivationResult{}, err
	}
	manifest, intent := admission.Envelope().Value().Manifest, admission.Intent().Value()
	if manifest.ExtensionID == "" || intent.Operation != "deactivate" || intent.ManifestDigest != admission.Envelope().ManifestDigest() {
		return DeactivationResult{}, newError(Denied, "deactivation_admission")
	}
	transition, found, err := controller.store.LoadTransition(ctx, intent.RequestID)
	if err != nil {
		return DeactivationResult{}, dependencyError(err, "transition_load")
	}
	replayed := found
	if found {
		if transition.IntentDigest != intent.IntentDigest || transition.ManifestDigest != intent.ManifestDigest || transition.Direction != DeactivateDirection {
			return DeactivationResult{}, newError(Denied, "transition_replay_drift")
		}
	} else {
		storedManifest, manifestFound, manifestErr := controller.store.LoadManifest(ctx, intent.ManifestDigest)
		if manifestErr != nil || !manifestFound || !bytes.Equal(storedManifest, admission.Envelope().CanonicalBytes()) {
			return DeactivationResult{}, newError(Denied, "durable_manifest_binding")
		}
		active, activeFound, loadErr := controller.store.LoadActive(ctx, intent.ExtensionID, intent.OrganizationID, intent.TenantID)
		if loadErr != nil {
			return DeactivationResult{}, dependencyError(loadErr, "active_load")
		}
		if !activeFound || active.ManifestDigest != intent.ManifestDigest || active.LifecycleRevision != intent.ExpectedLifecycleRevision ||
			active.RegistryRevision != intent.ExpectedRegistryRevision || active.ActiveProfileRevision != intent.ActiveProfileRevision ||
			active.ProfileBindingDigest != intent.ProfileBindingDigest || active.CompositionDigest != intent.CompositionDigest ||
			active.CapabilityGraphDigest != intent.CapabilityGraphDigest {
			return DeactivationResult{}, newError(Denied, "active_binding")
		}
		now := formatLifecycleTime(controller.clock.Now())
		transition = Transition{SchemaVersion: TransitionSchema, ContractVersion: ContractVersion, TransitionID: intent.RequestID,
			IntentDigest: intent.IntentDigest, ExtensionID: intent.ExtensionID, ManifestDigest: intent.ManifestDigest,
			OrganizationID: intent.OrganizationID, TenantID: intent.TenantID, Direction: DeactivateDirection,
			Phase: PreparedPhase, Sequence: 1, ExpectedLifecycleRevision: intent.ExpectedLifecycleRevision,
			RegistryRevision: intent.ExpectedRegistryRevision, NextApplyOrdinal: uint64(len(active.RegistrationReceiptDigests)),
			NextRevokeOrdinal: -1, RegistrationReceiptDigests: append([]string(nil), active.RegistrationReceiptDigests...),
			CreatedAt: now, UpdatedAt: now}
		transition, err = SealTransition(ctx, transition)
		if err != nil {
			return DeactivationResult{}, err
		}
		transition, err = controller.store.CreateTransition(ctx, transition)
		if err != nil {
			return DeactivationResult{}, dependencyError(err, "transition_create")
		}
	}
	return controller.continueDeactivation(ctx, admission, transition, replayed)
}

func (controller *DeactivationController) continueDeactivation(ctx context.Context, admission ValidatedAdmission, transition Transition, replayed bool) (DeactivationResult, error) {
	manifest, intent := admission.Envelope().Value().Manifest, admission.Intent().Value()
	for steps := 0; steps < len(manifest.Registrations)+8; steps++ {
		switch transition.Phase {
		case PreparedPhase:
			next := transition
			next.Phase, next.Sequence, next.UpdatedAt, next.TransitionDigest = DrainingPhase, transition.Sequence+1, formatLifecycleTime(controller.clock.Now()), ""
			sealed, err := SealTransition(ctx, next)
			if err != nil {
				return DeactivationResult{}, err
			}
			transition, err = controller.store.AdvanceTransition(ctx, transition, sealed)
			if err != nil {
				return DeactivationResult{}, dependencyError(err, "draining_begin")
			}
		case DrainingPhase:
			attestation, err := controller.gate.CloseAdmissionsAndDrain(ctx, DrainRequest{TransitionID: transition.TransitionID,
				ExtensionID: transition.ExtensionID, ManifestDigest: transition.ManifestDigest, OrganizationID: transition.OrganizationID,
				TenantID: transition.TenantID, MaximumDurationMS: intent.MaximumDrainDurationMS})
			if err != nil {
				return DeactivationResult{}, dependencyError(err, "drain")
			}
			if attestation.TransitionID != transition.TransitionID || !attestation.AdmissionsClosed || !attestation.Durable ||
				attestation.ActiveWork != 0 || !validDigest(attestation.TerminalOutcomesDigest) {
				return DeactivationResult{}, newError(Denied, "drain_attestation")
			}
			next := transition
			next.Phase, next.Sequence, next.NextRevokeOrdinal = RevokingPhase, transition.Sequence+1, int64(len(transition.RegistrationReceiptDigests))-1
			next.AdmissionClosed, next.ActiveWorkCount, next.TerminalWorkDigest = true, 0, attestation.TerminalOutcomesDigest
			next.UpdatedAt, next.TransitionDigest = formatLifecycleTime(controller.clock.Now()), ""
			sealed, sealErr := SealTransition(ctx, next)
			if sealErr != nil {
				return DeactivationResult{}, sealErr
			}
			transition, err = controller.store.AdvanceTransition(ctx, transition, sealed)
			if err != nil {
				return DeactivationResult{}, dependencyError(err, "drain_commit")
			}
		case RevokingPhase:
			if transition.NextRevokeOrdinal < 0 {
				auditDigest, err := controller.audit.CommitDeactivation(ctx, transition.TransitionID, transition.ManifestDigest, transition.TerminalWorkDigest, transition.RegistrationReceiptDigests)
				if err != nil {
					return DeactivationResult{}, dependencyError(err, "deactivation_audit")
				}
				if !validDigest(auditDigest) {
					return DeactivationResult{}, newError(Denied, "deactivation_audit")
				}
				active, activeFound, loadErr := controller.store.LoadActive(ctx, intent.ExtensionID, intent.OrganizationID, intent.TenantID)
				if loadErr != nil || !activeFound || active.ManifestDigest != transition.ManifestDigest {
					return DeactivationResult{}, newError(Denied, "active_removal_binding")
				}
				next := transition
				next.Phase, next.Sequence, next.TerminalAuditDigest = InactivePhase, transition.Sequence+1, auditDigest
				next.UpdatedAt, next.TransitionDigest = formatLifecycleTime(controller.clock.Now()), ""
				sealed, sealErr := SealTransition(ctx, next)
				if sealErr != nil {
					return DeactivationResult{}, sealErr
				}
				transition, err = controller.store.RemoveActive(ctx, transition, active, sealed)
				if err != nil {
					return DeactivationResult{}, dependencyError(err, "active_removal")
				}
				return DeactivationResult{Transition: transition, Replayed: replayed}, nil
			}
			ordinal := transition.NextRevokeOrdinal
			digest := transition.RegistrationReceiptDigests[ordinal]
			receipt, receiptFound, err := controller.store.LoadReceipt(ctx, digest)
			if err != nil || !receiptFound || receipt.State != "registered" || receipt.ExtensionID != transition.ExtensionID ||
				receipt.ManifestDigest != transition.ManifestDigest || receipt.RegistrationOrdinal != uint64(ordinal) {
				return DeactivationResult{}, newError(Denied, "owned_receipt")
			}
			registration := manifest.Registrations[ordinal]
			request := EffectRequest{EffectKey: digestBytes("COH-EXTENSION-DEACTIVATION-EFFECT-V1\x00", []byte(intent.IntentDigest+fmt.Sprint(ordinal))),
				TransitionID: receipt.TransitionID, ManifestDigest: receipt.ManifestDigest, ExtensionID: receipt.ExtensionID,
				OrganizationID: receipt.OrganizationID, TenantID: receipt.TenantID, ScopeDigest: receipt.ScopeDigest,
				Registration: registration, Ordinal: uint64(ordinal), RegistryRevision: receipt.RegistryRevision}
			revocation, err := controller.effects.Revoke(ctx, request, receipt.RevocationHandle)
			if err != nil {
				return DeactivationResult{}, dependencyError(err, "effect_revoke")
			}
			if !validTimestampString(revocation.RevokedAt) || !validDigest(revocation.EffectAuditDigest) {
				return DeactivationResult{}, newError(Denied, "revocation_result")
			}
			revoked := receipt
			revoked.State, revoked.RevokedAt, revoked.EffectAuditDigest, revoked.ReceiptDigest = "revoked", revocation.RevokedAt, revocation.EffectAuditDigest, ""
			revoked, err = SealReceipt(ctx, revoked)
			if err != nil {
				return DeactivationResult{}, err
			}
			next := transition
			next.Sequence, next.NextRevokeOrdinal = transition.Sequence+1, ordinal-1
			next.RegistrationReceiptDigests = append([]string(nil), transition.RegistrationReceiptDigests...)
			next.RegistrationReceiptDigests[ordinal] = revoked.ReceiptDigest
			next.UpdatedAt, next.TransitionDigest = formatLifecycleTime(controller.clock.Now()), ""
			sealed, sealErr := SealTransition(ctx, next)
			if sealErr != nil {
				return DeactivationResult{}, sealErr
			}
			transition, err = controller.store.CommitRevocation(ctx, transition, receipt, revoked, sealed)
			if err != nil {
				return DeactivationResult{}, dependencyError(err, "revocation_commit")
			}
		case InactivePhase:
			if _, activeFound, err := controller.store.LoadActive(ctx, intent.ExtensionID, intent.OrganizationID, intent.TenantID); err != nil || activeFound {
				return DeactivationResult{}, newError(Denied, "inactive_publication_drift")
			}
			return DeactivationResult{Transition: transition, Replayed: true}, nil
		default:
			return DeactivationResult{}, newError(Denied, "deactivation_phase")
		}
	}
	return DeactivationResult{}, newError(Unavailable, "deactivation_steps")
}
