package extensionlifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

type ActivationController struct {
	store   ActivationStore
	effects EffectPort
	audit   ActivationAuditPort
	clock   Clock
}

func NewActivationController(store ActivationStore, effects EffectPort, audit ActivationAuditPort, clock Clock) (*ActivationController, error) {
	if store == nil || effects == nil || audit == nil || clock == nil {
		return nil, newError(InvalidInput, "activation_dependencies")
	}
	return &ActivationController{store: store, effects: effects, audit: audit, clock: clock}, nil
}

func (controller *ActivationController) Activate(ctx context.Context, admission ValidatedAdmission) (ActivationResult, error) {
	if controller == nil || controller.store == nil || controller.effects == nil || controller.audit == nil || controller.clock == nil {
		return ActivationResult{}, newError(InvalidInput, "activation_controller")
	}
	if err := contextError(ctx); err != nil {
		return ActivationResult{}, err
	}
	manifest := admission.Envelope().Value().Manifest
	intent := admission.Intent().Value()
	if manifest.ExtensionID == "" || intent.Operation != "activate" || intent.ManifestDigest != admission.Envelope().ManifestDigest() {
		return ActivationResult{}, newError(Denied, "activation_admission")
	}
	transition, found, err := controller.store.LoadTransition(ctx, intent.RequestID)
	if err != nil {
		return ActivationResult{}, dependencyError(err, "transition_load")
	}
	replayed := found
	if found {
		if transition.IntentDigest != intent.IntentDigest || transition.ManifestDigest != intent.ManifestDigest ||
			transition.ExtensionID != intent.ExtensionID || transition.Direction != ActivateDirection {
			return ActivationResult{}, newError(Denied, "transition_replay_drift")
		}
	} else {
		if err := controller.validateNoActive(ctx, intent); err != nil {
			return ActivationResult{}, err
		}
		if err := controller.store.PutManifest(ctx, manifest.ExtensionID, admission.Envelope().ManifestDigest(), admission.Envelope().CanonicalBytes()); err != nil {
			return ActivationResult{}, dependencyError(err, "manifest_persist")
		}
		now := formatLifecycleTime(controller.clock.Now())
		transition = Transition{SchemaVersion: TransitionSchema, ContractVersion: ContractVersion, TransitionID: intent.RequestID,
			IntentDigest: intent.IntentDigest, ExtensionID: intent.ExtensionID, ManifestDigest: intent.ManifestDigest,
			OrganizationID: intent.OrganizationID, TenantID: intent.TenantID, Direction: ActivateDirection, Phase: PreparedPhase,
			Sequence: 1, ExpectedLifecycleRevision: intent.ExpectedLifecycleRevision, RegistryRevision: intent.ExpectedRegistryRevision,
			NextRevokeOrdinal: -1, RegistrationReceiptDigests: []string{}, CreatedAt: now, UpdatedAt: now}
		transition, err = SealTransition(ctx, transition)
		if err != nil {
			return ActivationResult{}, err
		}
		transition, err = controller.store.CreateTransition(ctx, transition)
		if err != nil {
			return ActivationResult{}, dependencyError(err, "transition_create")
		}
	}
	return controller.continueActivation(ctx, admission, transition, replayed)
}

func (controller *ActivationController) validateNoActive(ctx context.Context, intent ActivationIntent) error {
	_, found, err := controller.store.LoadActive(ctx, intent.ExtensionID, intent.OrganizationID, intent.TenantID)
	if err != nil {
		return dependencyError(err, "active_load")
	}
	if found {
		return newError(Denied, "active_requires_deactivation")
	}
	if intent.Mode != "upgrade" && intent.Mode != "rollback" {
		if intent.ExpectedLifecycleRevision != 0 {
			return newError(Denied, "lifecycle_lineage")
		}
		return nil
	}
	if intent.ExpectedLifecycleRevision == 0 || intent.ExpectedPredecessorManifestDigest == "" {
		return newError(Denied, "lifecycle_lineage")
	}
	predecessor, found, err := controller.store.LoadInactivePredecessor(ctx, intent.ExtensionID, intent.OrganizationID,
		intent.TenantID, intent.ExpectedPredecessorManifestDigest, intent.ExpectedLifecycleRevision)
	if err != nil {
		return dependencyError(err, "predecessor_load")
	}
	if !found || predecessor.Direction != DeactivateDirection || predecessor.Phase != InactivePhase ||
		predecessor.ManifestDigest != intent.ExpectedPredecessorManifestDigest ||
		predecessor.ExpectedLifecycleRevision != intent.ExpectedLifecycleRevision {
		return newError(Denied, "lifecycle_lineage")
	}
	return nil
}

func (controller *ActivationController) continueActivation(ctx context.Context, admission ValidatedAdmission, transition Transition, replayed bool) (ActivationResult, error) {
	manifest := admission.Envelope().Value().Manifest
	intent := admission.Intent().Value()
	for steps := 0; steps < 2*len(manifest.Registrations)+8; steps++ {
		switch transition.Phase {
		case PreparedPhase:
			next := transition
			next.Phase, next.Sequence, next.UpdatedAt = ApplyingPhase, transition.Sequence+1, formatLifecycleTime(controller.clock.Now())
			next.TransitionDigest = ""
			sealed, err := SealTransition(context.Background(), next)
			if err != nil {
				return ActivationResult{}, err
			}
			transition, err = controller.store.AdvanceTransition(context.Background(), transition, sealed)
			if err != nil {
				return ActivationResult{}, dependencyError(err, "transition_apply")
			}
		case ApplyingPhase:
			if int(transition.NextApplyOrdinal) == len(manifest.Registrations) {
				auditDigest, err := controller.audit.CommitActivation(ctx, transition.TransitionID, transition.ManifestDigest, transition.RegistrationReceiptDigests)
				if err != nil || !validDigest(auditDigest) {
					return controller.failAndUnwind(admission, transition, "activation_audit")
				}
				active := activeFromAdmission(admission, transition, auditDigest, formatLifecycleTime(controller.clock.Now()))
				active, err = SealActive(ctx, active)
				if err != nil {
					return controller.failAndUnwind(admission, transition, "active_record")
				}
				next := transition
				next.Phase, next.Sequence, next.ActivationAuditDigest = ActivePhase, transition.Sequence+1, auditDigest
				next.UpdatedAt, next.TransitionDigest = active.ActivatedAt, ""
				next, err = SealTransition(ctx, next)
				if err != nil {
					return controller.failAndUnwind(admission, transition, "active_transition")
				}
				transition, err = controller.store.PublishActive(ctx, transition, active, next)
				if err != nil {
					return ActivationResult{}, dependencyError(err, "active_publish")
				}
				return ActivationResult{Transition: transition, Active: active, Replayed: replayed}, nil
			}
			if err := contextError(ctx); err != nil {
				return controller.failAndUnwind(admission, transition, string(Code(err)))
			}
			registration := manifest.Registrations[transition.NextApplyOrdinal]
			request := effectRequest(intent, manifest, registration, transition.NextApplyOrdinal)
			result, found, err := controller.effects.Resolve(ctx, request)
			if err != nil {
				return controller.failAndUnwind(admission, transition, "effect_resolve")
			}
			if !found {
				result, err = controller.effects.Stage(ctx, request)
				if err != nil {
					var resolveErr error
					result, found, resolveErr = controller.effects.Resolve(context.Background(), request)
					if resolveErr != nil {
						return ActivationResult{}, newError(Unavailable, "effect_resolution_ambiguous")
					}
					if !found {
						return controller.failAndUnwind(admission, transition, "effect_stage")
					}
				}
			}
			receipt, err := receiptFromEffect(ctx, intent, registration, transition.NextApplyOrdinal, result)
			if err != nil {
				return controller.failAndUnwind(admission, transition, "effect_result")
			}
			next := transition
			next.Sequence, next.NextApplyOrdinal, next.NextRevokeOrdinal = transition.Sequence+1, transition.NextApplyOrdinal+1, int64(transition.NextApplyOrdinal)
			next.RegistrationReceiptDigests = append(append([]string(nil), transition.RegistrationReceiptDigests...), receipt.ReceiptDigest)
			next.UpdatedAt, next.TransitionDigest = formatLifecycleTime(controller.clock.Now()), ""
			next, err = SealTransition(ctx, next)
			if err != nil {
				return controller.failAndUnwind(admission, transition, "receipt_transition")
			}
			transition, err = controller.store.CommitReceipt(ctx, transition, receipt, next)
			if err != nil {
				return ActivationResult{}, dependencyError(err, "receipt_commit")
			}
		case UnwindingPhase:
			return controller.unwind(admission, transition)
		case ActivePhase:
			active, found, err := controller.store.LoadActive(ctx, intent.ExtensionID, intent.OrganizationID, intent.TenantID)
			if err != nil || !found || active.TransitionID != transition.TransitionID {
				return ActivationResult{}, newError(Denied, "active_publication_drift")
			}
			return ActivationResult{Transition: transition, Active: active, Replayed: true}, nil
		case InactivePhase:
			return ActivationResult{}, newError(Denied, "activation_unwound")
		default:
			return ActivationResult{}, newError(Denied, "activation_phase")
		}
	}
	return ActivationResult{}, newError(Denied, "activation_steps")
}

func (controller *ActivationController) failAndUnwind(admission ValidatedAdmission, transition Transition, reason string) (ActivationResult, error) {
	if transition.Phase != UnwindingPhase {
		next := transition
		next.Phase, next.Sequence, next.FailureCode = UnwindingPhase, transition.Sequence+1, reason
		next.NextRevokeOrdinal, next.UpdatedAt, next.TransitionDigest = int64(transition.NextApplyOrdinal)-1, formatLifecycleTime(controller.clock.Now()), ""
		sealed, err := SealTransition(context.Background(), next)
		if err != nil {
			return ActivationResult{}, err
		}
		transition, err = controller.store.AdvanceTransition(context.Background(), transition, sealed)
		if err != nil {
			return ActivationResult{}, dependencyError(err, "unwind_begin")
		}
	}
	return controller.unwind(admission, transition)
}

func (controller *ActivationController) unwind(admission ValidatedAdmission, transition Transition) (ActivationResult, error) {
	manifest := admission.Envelope().Value().Manifest
	intent := admission.Intent().Value()
	for transition.NextRevokeOrdinal >= 0 {
		ordinal := transition.NextRevokeOrdinal
		digest := transition.RegistrationReceiptDigests[ordinal]
		receipt, found, err := controller.store.LoadReceipt(context.Background(), digest)
		if err != nil || !found {
			return ActivationResult{}, newError(Denied, "unwind_receipt")
		}
		registration := manifest.Registrations[ordinal]
		request := effectRequest(intent, manifest, registration, uint64(ordinal))
		revocation, err := controller.effects.Revoke(context.Background(), request, receipt.RevocationHandle)
		if err != nil {
			return ActivationResult{}, dependencyError(err, "effect_revoke")
		}
		if !validTimestampString(revocation.RevokedAt) || !validDigest(revocation.EffectAuditDigest) {
			return ActivationResult{}, newError(Denied, "revocation_result")
		}
		revokedReceipt := receipt
		revokedReceipt.State, revokedReceipt.RevokedAt = "revoked", revocation.RevokedAt
		revokedReceipt.EffectAuditDigest, revokedReceipt.ReceiptDigest = revocation.EffectAuditDigest, ""
		revokedReceipt, err = SealReceipt(context.Background(), revokedReceipt)
		if err != nil {
			return ActivationResult{}, err
		}
		next := transition
		next.Sequence, next.NextRevokeOrdinal, next.UpdatedAt = transition.Sequence+1, ordinal-1, formatLifecycleTime(controller.clock.Now())
		next.RegistrationReceiptDigests = append([]string(nil), transition.RegistrationReceiptDigests...)
		next.RegistrationReceiptDigests[ordinal] = revokedReceipt.ReceiptDigest
		next.TransitionDigest = ""
		sealed, err := SealTransition(context.Background(), next)
		if err != nil {
			return ActivationResult{}, err
		}
		transition, err = controller.store.CommitRevocation(context.Background(), transition, receipt, revokedReceipt, sealed)
		if err != nil {
			return ActivationResult{}, dependencyError(err, "unwind_commit")
		}
	}
	next := transition
	next.Phase, next.Sequence, next.UpdatedAt, next.TransitionDigest = InactivePhase, transition.Sequence+1, formatLifecycleTime(controller.clock.Now()), ""
	sealed, err := SealTransition(context.Background(), next)
	if err != nil {
		return ActivationResult{}, err
	}
	if _, err = controller.store.AdvanceTransition(context.Background(), transition, sealed); err != nil {
		return ActivationResult{}, dependencyError(err, "unwind_complete")
	}
	return ActivationResult{}, newError(Denied, "activation_unwound")
}

func effectRequest(intent ActivationIntent, manifest Manifest, registration Registration, ordinal uint64) EffectRequest {
	return EffectRequest{EffectKey: digestBytes("COH-EXTENSION-EFFECT-V1\x00", []byte(intent.IntentDigest+fmt.Sprint(ordinal))), TransitionID: intent.RequestID,
		ManifestDigest: intent.ManifestDigest, ExtensionID: intent.ExtensionID, OrganizationID: intent.OrganizationID,
		TenantID: intent.TenantID, ScopeDigest: intent.RequestedScopeDigest, Registration: registration,
		Ordinal: ordinal, RegistryRevision: intent.ExpectedRegistryRevision}
}

func receiptFromEffect(ctx context.Context, intent ActivationIntent, registration Registration, ordinal uint64, result EffectResult) (RegistrationReceipt, error) {
	permissionsDigest, err := PermissionsDigest(registration.Permissions)
	if err != nil {
		return RegistrationReceipt{}, err
	}
	if !validUUID7(result.ReceiptID) || !validUUID7(result.HandleID) || result.Generation == 0 ||
		result.RegistryRevision != intent.ExpectedRegistryRevision || !validDigest(result.EffectAuditDigest) || !validTimestampString(result.RegisteredAt) {
		return RegistrationReceipt{}, newError(Denied, "effect_result")
	}
	handle := RevocationHandle{SchemaVersion: HandleSchema, ContractVersion: ContractVersion, HandleID: result.HandleID,
		ExtensionID: intent.ExtensionID, ManifestDigest: intent.ManifestDigest, TransitionID: intent.RequestID,
		RegistrationID: registration.RegistrationID, RegistrationOrdinal: ordinal, OrganizationID: intent.OrganizationID,
		TenantID: intent.TenantID, ScopeDigest: intent.RequestedScopeDigest, RegistryRevision: result.RegistryRevision,
		Generation: result.Generation, IssuedAt: result.RegisteredAt}
	handle, err = SealHandle(ctx, handle)
	if err != nil {
		return RegistrationReceipt{}, err
	}
	receipt := RegistrationReceipt{SchemaVersion: ReceiptSchema, ContractVersion: ContractVersion, ReceiptID: result.ReceiptID,
		IdempotencyKey: deterministicUUID7(intent.IdempotencyKey, ordinal), ExtensionID: intent.ExtensionID,
		ManifestDigest: intent.ManifestDigest, TransitionID: intent.RequestID, RegistrationID: registration.RegistrationID,
		RegistrationOrdinal: ordinal, Role: registration.Role, CapabilityID: registration.Capability.CapabilityID,
		CapabilityVersion: registration.Capability.CapabilityVersion, ProviderID: registration.ProviderID,
		OrganizationID: intent.OrganizationID, TenantID: intent.TenantID, ScopeDigest: intent.RequestedScopeDigest,
		PermissionsDigest: permissionsDigest, ResourceLimitsDigest: registration.ResourceLimitsDigest,
		RegistryRevision: result.RegistryRevision, Generation: result.Generation, State: "registered",
		RevocationHandle: handle, RegisteredAt: result.RegisteredAt, EffectAuditDigest: result.EffectAuditDigest}
	return SealReceipt(ctx, receipt)
}

func activeFromAdmission(admission ValidatedAdmission, transition Transition, auditDigest, activatedAt string) ActiveExtension {
	manifest, intent := admission.Envelope().Value().Manifest, admission.Intent().Value()
	return ActiveExtension{SchemaVersion: ActiveExtensionSchema, ContractVersion: ContractVersion, ExtensionID: manifest.ExtensionID,
		ExtensionName: manifest.ExtensionName, ExtensionVersion: manifest.ExtensionVersion, ManifestDigest: transition.ManifestDigest,
		TransitionID: transition.TransitionID, LifecycleRevision: intent.ExpectedLifecycleRevision + 1,
		RegistryRevision: transition.RegistryRevision, OrganizationID: intent.OrganizationID, TenantID: intent.TenantID,
		ActiveProfileRevision: intent.ActiveProfileRevision, ProfileBindingDigest: intent.ProfileBindingDigest,
		CompositionDigest: intent.CompositionDigest, CapabilityGraphDigest: intent.CapabilityGraphDigest,
		RegistrationReceiptDigests: append([]string(nil), transition.RegistrationReceiptDigests...),
		ActivationAuditDigest:      auditDigest, ActivatedAt: activatedAt}
}

func deterministicUUID7(seed string, ordinal uint64) string {
	sum := sha256.Sum256([]byte(seed + fmt.Sprint(ordinal)))
	sum[6] = (sum[6] & 0x0f) | 0x70
	sum[8] = (sum[8] & 0x3f) | 0x80
	hexText := hex.EncodeToString(sum[:16])
	return hexText[:8] + "-" + hexText[8:12] + "-" + hexText[12:16] + "-" + hexText[16:20] + "-" + hexText[20:32]
}

func formatLifecycleTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
}
func dependencyError(err error, reason string) error {
	if err == nil {
		return nil
	}
	var typed *Error
	if errors.As(err, &typed) {
		return err
	}
	return newError(Unavailable, reason)
}
