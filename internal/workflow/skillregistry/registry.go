package skillregistry

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"time"
	"unicode/utf8"
)

type Controller struct {
	store   Store
	auditor Auditor
	clock   Clock
}

func New(store Store, auditor Auditor, clock Clock) (*Controller, error) {
	if store == nil || auditor == nil || clock == nil {
		return nil, newError(InvalidInput, "dependencies_required", false, nil)
	}
	return &Controller{store: store, auditor: auditor, clock: clock}, nil
}

func (controller *Controller) Change(ctx context.Context, request ChangeRequest) (State, error) {
	if controller == nil || controller.store == nil || controller.auditor == nil || controller.clock == nil {
		return State{}, newError(Unavailable, "registry_unavailable", true, nil)
	}
	if err := contextError(ctx); err != nil {
		return State{}, err
	}
	if !validOpaque(request.IdempotencyKey, 1, 256) {
		return State{}, newError(InvalidInput, "idempotency_key_invalid", false, nil)
	}
	change, err := verifyChange(ctx, request.SignedCommand, request.Signer)
	if err != nil {
		return State{}, err
	}
	command := change.value.Command
	now, err := controller.now()
	if err != nil {
		return State{}, err
	}
	if command.CreatedAt.After(now) || !now.Before(command.Deadline) {
		return State{}, newError(Denied, "command_not_current", false, nil)
	}
	if err := validatePolicy(request.Policy, command, now); err != nil {
		return State{}, err
	}
	current, found, err := controller.loadState(ctx, command)
	if err != nil {
		return State{}, err
	}
	idempotency := idempotencyDigest(request.IdempotencyKey)
	if found && current.IdempotencyDigest == idempotency {
		if current.LastCommandDigest != change.value.CommandDigest {
			return State{}, newError(Denied, "changed_replay", false, nil)
		}
		return cloneState(current), nil
	}
	if err := bindExpectedState(command, current, found); err != nil {
		return State{}, err
	}
	version, manifest, persistVersion, err := controller.targetVersion(ctx, request, command, current, found, now)
	if err != nil {
		return State{}, err
	}
	event := changeAuditEvent(command, change.value.CommandDigest, request.Policy.DecisionDigest,
		manifest.ReviewEvidenceDigest, now)
	receipt, err := controller.appendAudit(ctx, event)
	if err != nil {
		return State{}, err
	}
	next, err := nextState(command, current, found, manifest, change.value.CommandDigest,
		idempotency, request.Policy.DecisionDigest, receipt.ReceiptDigest, now)
	if err != nil {
		return State{}, err
	}
	var expected *State
	if found {
		copy := cloneState(current)
		expected = &copy
	}
	var storedVersion *Version
	if persistVersion {
		copy := cloneVersion(version)
		storedVersion = &copy
	}
	stored, replayed, err := controller.store.Commit(ctx, request.IdempotencyKey, expected, next, storedVersion)
	if err != nil {
		return State{}, mapDependency(ctx, "store_commit_failed", err)
	}
	if err := validateState(stored); err != nil || !reflect.DeepEqual(stored, next) {
		return State{}, newError(Denied, "store_result_invalid", false, err)
	}
	if replayed && (stored.LastCommandDigest != change.value.CommandDigest ||
		stored.IdempotencyDigest != idempotency) {
		return State{}, newError(Denied, "store_replay_invalid", false, nil)
	}
	return cloneState(stored), nil
}

func (controller *Controller) Resolve(ctx context.Context, request ResolveRequest,
	access AccessDecision, authority ResolutionAuthority) (ResolvedSkill, error) {
	if controller == nil || controller.store == nil || controller.auditor == nil || controller.clock == nil {
		return ResolvedSkill{}, newError(Unavailable, "registry_unavailable", true, nil)
	}
	if err := contextError(ctx); err != nil {
		return ResolvedSkill{}, err
	}
	now, err := controller.now()
	if err != nil {
		return ResolvedSkill{}, err
	}
	if err := validateResolveRequest(request, now); err != nil {
		return ResolvedSkill{}, err
	}
	if err := validateAccess(access, request, now); err != nil {
		return ResolvedSkill{}, err
	}
	state, found, err := controller.store.LoadState(ctx, request.OrganizationID, request.TenantID, request.SkillName)
	if err != nil {
		return ResolvedSkill{}, mapDependency(ctx, "store_load_failed", err)
	}
	if !found {
		return ResolvedSkill{}, newError(NotFound, "skill_not_promoted", false, nil)
	}
	if err := validateState(state); err != nil || state.OrganizationID != request.OrganizationID ||
		state.TenantID != request.TenantID || state.SkillName != request.SkillName {
		return ResolvedSkill{}, newError(Denied, "stored_state_invalid", false, err)
	}
	if state.Status != Promoted || !constantDigest(state.CurrentManifestDigest, request.ExpectedManifestDigest) {
		return ResolvedSkill{}, newError(Denied, "promoted_version_mismatch", false, nil)
	}
	version, manifest, err := controller.loadVerifiedVersion(ctx, request.OrganizationID, request.TenantID,
		state.CurrentManifestDigest, authority.Publisher, authority.Reviewers, authority.Review, now)
	if err != nil {
		return ResolvedSkill{}, err
	}
	if version.ManifestDigest != request.ExpectedManifestDigest || manifest.SkillName != request.SkillName {
		return ResolvedSkill{}, newError(Denied, "version_binding_invalid", false, nil)
	}
	if _, found := slices.BinarySearch(manifest.Permissions, request.RequiredPermission); !found {
		return ResolvedSkill{}, newError(Denied, "permission_not_promoted", false, nil)
	}
	event := AuditEvent{
		EventID: request.RequestID, OrganizationID: request.OrganizationID, TenantID: request.TenantID,
		CaseID: request.CaseID, TaskID: request.TaskID, ActorID: request.ActorID, Action: Resolve,
		SkillName: request.SkillName, ManifestDigest: request.ExpectedManifestDigest,
		PolicyDigest: access.DecisionDigest, ReviewDigest: manifest.ReviewEvidenceDigest,
		Outcome: "allowed", OccurredAt: now,
	}
	if _, err := controller.appendAudit(ctx, event); err != nil {
		return ResolvedSkill{}, err
	}
	return cloneResolved(ResolvedSkill{
		SkillName: manifest.SkillName, SkillVersion: manifest.SkillVersion,
		ManifestDigest: version.ManifestDigest, ContentDigest: manifest.ContentDigest,
		Resources: append([]Resource(nil), manifest.Resources...), Permissions: append([]string(nil), manifest.Permissions...),
		OwnerActorID: manifest.OwnerActorID, ReviewID: manifest.ReviewID,
		ReviewRevision: manifest.ReviewRevision, ProvenanceDigest: state.ProvenanceDigest,
	}), nil
}

func (controller *Controller) targetVersion(ctx context.Context, request ChangeRequest, command ChangeCommand,
	current State, found bool, now time.Time) (Version, Manifest, bool, error) {
	if command.Action == Promote && len(request.SignedManifest) == 0 ||
		command.Action != Promote && len(request.SignedManifest) != 0 {
		return Version{}, Manifest{}, false, newError(InvalidInput, "signed_manifest_usage_invalid", false, nil)
	}
	if command.Action == Promote {
		verified, err := verifyEnvelope(ctx, request.SignedManifest, request.Publisher, request.Reviewers, request.Review)
		if err != nil {
			return Version{}, Manifest{}, false, err
		}
		manifest := verified.envelope.Manifest
		if err := bindTargetManifest(command, current, found, manifest, verified.envelope.ManifestDigest, now); err != nil {
			return Version{}, Manifest{}, false, err
		}
		version := Version{OrganizationID: command.OrganizationID, TenantID: command.TenantID,
			ManifestID: manifest.ManifestID, ManifestDigest: verified.envelope.ManifestDigest,
			Envelope: append([]byte(nil), verified.canonical...), CreatedAt: now}
		existing, exists, err := controller.store.LoadVersion(ctx, command.OrganizationID, command.TenantID, version.ManifestDigest)
		if err != nil {
			return Version{}, Manifest{}, false, mapDependency(ctx, "version_load_failed", err)
		}
		if exists {
			if existing.OrganizationID != version.OrganizationID || existing.TenantID != version.TenantID ||
				existing.ManifestID != version.ManifestID || existing.ManifestDigest != version.ManifestDigest ||
				!bytes.Equal(existing.Envelope, version.Envelope) {
				return Version{}, Manifest{}, false, newError(Denied, "immutable_version_collision", false, nil)
			}
			return cloneVersion(existing), cloneManifest(manifest), false, nil
		}
		return version, cloneManifest(manifest), true, nil
	}
	version, manifest, err := controller.loadVerifiedVersion(ctx, command.OrganizationID, command.TenantID,
		command.TargetManifestDigest, request.Publisher, request.Reviewers, request.Review, now)
	if err != nil {
		return Version{}, Manifest{}, false, err
	}
	if manifest.OwnerActorID != command.ActorID || manifest.SkillName != command.SkillName {
		return Version{}, Manifest{}, false, newError(Denied, "change_owner_mismatch", false, nil)
	}
	if command.Action == Revoke && command.TargetManifestDigest != current.CurrentManifestDigest ||
		command.Action == Rollback && (current.PreviousManifestDigest == "" ||
			command.TargetManifestDigest != current.PreviousManifestDigest) {
		return Version{}, Manifest{}, false, newError(Denied, "change_target_invalid", false, nil)
	}
	return version, manifest, false, nil
}

func (controller *Controller) loadVerifiedVersion(ctx context.Context, organizationID, tenantID, digest string,
	publisher SigningAuthority, reviewers []SigningAuthority, review ReviewAuthority, now time.Time) (Version, Manifest, error) {
	version, found, err := controller.store.LoadVersion(ctx, organizationID, tenantID, digest)
	if err != nil {
		return Version{}, Manifest{}, mapDependency(ctx, "version_load_failed", err)
	}
	if !found {
		return Version{}, Manifest{}, newError(NotFound, "skill_version_not_found", false, nil)
	}
	if version.OrganizationID != organizationID || version.TenantID != tenantID ||
		version.ManifestDigest != digest || len(version.Envelope) == 0 {
		return Version{}, Manifest{}, newError(Denied, "stored_version_invalid", false, nil)
	}
	verified, err := verifyEnvelope(ctx, version.Envelope, publisher, reviewers, review)
	if err != nil {
		return Version{}, Manifest{}, err
	}
	manifest := verified.envelope.Manifest
	if verified.envelope.ManifestDigest != digest || version.ManifestID != manifest.ManifestID ||
		now.Before(manifest.ValidFrom) || !now.Before(manifest.ValidUntil) {
		return Version{}, Manifest{}, newError(Denied, "skill_version_not_current", false, nil)
	}
	return cloneVersion(version), cloneManifest(manifest), nil
}

func (controller *Controller) loadState(ctx context.Context, command ChangeCommand) (State, bool, error) {
	state, found, err := controller.store.LoadState(ctx, command.OrganizationID, command.TenantID, command.SkillName)
	if err != nil {
		return State{}, false, mapDependency(ctx, "store_load_failed", err)
	}
	if !found {
		return State{}, false, nil
	}
	if err := validateState(state); err != nil || state.OrganizationID != command.OrganizationID ||
		state.TenantID != command.TenantID || state.SkillName != command.SkillName {
		return State{}, false, newError(Denied, "stored_state_invalid", false, err)
	}
	return cloneState(state), true, nil
}

func (controller *Controller) appendAudit(ctx context.Context, event AuditEvent) (AuditReceipt, error) {
	digest, err := auditEventDigest(event)
	if err != nil {
		return AuditReceipt{}, err
	}
	receipt, err := controller.auditor.Append(ctx, event)
	if err != nil {
		return AuditReceipt{}, mapDependency(ctx, "audit_append_failed", err)
	}
	if receipt.EventID != event.EventID || receipt.EventDigest != digest || !validDigest(receipt.ReceiptDigest) {
		return AuditReceipt{}, newError(Denied, "audit_receipt_invalid", false, nil)
	}
	return receipt, nil
}

func (controller *Controller) now() (time.Time, error) {
	value := controller.clock.Now().UTC()
	if !validTime(value) {
		return time.Time{}, newError(Unavailable, "clock_unavailable", true, nil)
	}
	return value, nil
}

func bindExpectedState(command ChangeCommand, current State, found bool) error {
	if !found {
		if command.ExpectedRevision != 0 || command.ExpectedCurrentDigest != "" || command.Action != Promote {
			return newError(Conflict, "expected_state_missing", false, nil)
		}
		return nil
	}
	if command.ExpectedRevision != current.Revision ||
		!constantDigest(command.ExpectedCurrentDigest, current.CurrentManifestDigest) {
		return newError(Conflict, "expected_state_stale", false, nil)
	}
	if current.Status == Revoked && command.Action != Promote {
		return newError(Denied, "revoked_state_requires_new_promotion", false, nil)
	}
	return nil
}

func bindTargetManifest(command ChangeCommand, current State, found bool, manifest Manifest,
	digest string, now time.Time) error {
	if manifest.OwnerActorID != command.ActorID || manifest.SkillName != command.SkillName ||
		digest != command.TargetManifestDigest || now.Before(manifest.ValidFrom) || !now.Before(manifest.ValidUntil) {
		return newError(Denied, "promotion_binding_invalid", false, nil)
	}
	if !found && manifest.PreviousManifestDigest != "" ||
		found && manifest.PreviousManifestDigest != current.CurrentManifestDigest {
		return newError(Denied, "promotion_lineage_invalid", false, nil)
	}
	return nil
}

func nextState(command ChangeCommand, current State, found bool, manifest Manifest, commandDigest,
	idempotency, policyDigest, auditDigest string, now time.Time) (State, error) {
	next := State{
		SchemaVersion: StateSchemaVersion, ContractVersion: ContractVersion,
		OrganizationID: command.OrganizationID, TenantID: command.TenantID, SkillName: command.SkillName,
		Status: Promoted, CurrentManifestDigest: command.TargetManifestDigest,
		LastAction: command.Action, LastCommandDigest: commandDigest, IdempotencyDigest: idempotency,
		PolicyDecisionDigest: policyDigest, ReviewEvidenceDigest: manifest.ReviewEvidenceDigest,
		AuditReceiptDigest: auditDigest, CreatedAt: now, UpdatedAt: now, Revision: 1,
	}
	if found {
		next.CreatedAt = current.CreatedAt
		next.PreviousProvenanceDigest = current.ProvenanceDigest
		next.Revision = current.Revision + 1
	}
	switch command.Action {
	case Promote:
		if found {
			next.PreviousManifestDigest = current.CurrentManifestDigest
		}
	case Rollback:
		next.PreviousManifestDigest = current.CurrentManifestDigest
	case Revoke:
		next.Status = Revoked
		next.PreviousManifestDigest = current.PreviousManifestDigest
	}
	digest, err := provenanceDigest(next)
	if err != nil {
		return State{}, err
	}
	next.ProvenanceDigest = digest
	if err := validateState(next); err != nil {
		return State{}, err
	}
	return next, nil
}

func changeAuditEvent(command ChangeCommand, commandDigest, policyDigest, reviewDigest string,
	now time.Time) AuditEvent {
	return AuditEvent{
		EventID: command.CommandID, OrganizationID: command.OrganizationID, TenantID: command.TenantID,
		CaseID: command.CaseID, TaskID: command.TaskID, ActorID: command.ActorID,
		Action: AuditAction(command.Action), SkillName: command.SkillName,
		ManifestDigest: command.TargetManifestDigest, CommandDigest: commandDigest,
		PolicyDigest: policyDigest, ReviewDigest: reviewDigest, Outcome: "allowed", OccurredAt: now,
	}
}

func validOpaque(value string, minimum, maximum int) bool {
	return utf8.ValidString(value) && len(value) >= minimum && len(value) <= maximum &&
		value == string([]byte(value))
}

func mapDependency(ctx context.Context, reason string, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return contextError(ctx)
	}
	var typed *Error
	if errors.As(err, &typed) {
		return err
	}
	return newError(Unavailable, reason, true, err)
}

var _ Registry = (*Controller)(nil)
