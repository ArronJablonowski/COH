package broker

import (
	"context"
	"crypto/subtle"
	"time"

	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/policy"
	"github.com/ArronJablonowski/COH/internal/policy/approvalfingerprint"
)

func (service *approvalService) grantApproval(ctx context.Context, command approvalTransitionCommand) (approvalResult, error) {
	return service.transition(ctx, "grant", command)
}

func (service *approvalService) rejectApproval(ctx context.Context, command approvalTransitionCommand) (approvalResult, error) {
	return service.transition(ctx, "reject", command)
}

func (service *approvalService) expireApproval(ctx context.Context, command approvalTransitionCommand) (approvalResult, error) {
	return service.transition(ctx, "expire", command)
}

func (service *approvalService) consumeApproval(ctx context.Context, command approvalTransitionCommand) (approvalResult, error) {
	return service.transition(ctx, "consume", command)
}

func (service *approvalService) revokeApproval(ctx context.Context, command approvalTransitionCommand) (approvalResult, error) {
	return service.transition(ctx, "revoke", command)
}

func (service *approvalService) transition(ctx context.Context, operation string, command approvalTransitionCommand) (approvalResult, error) {
	now := service.now()
	fingerprint := proofFingerprint(command.approvalProof)
	if err := contextError(ctx); err != nil {
		return approvalResult{}, service.failure(ctx, operation, command.ApprovalID, command.Actor, fingerprint, command.ExpectedRevision, err, now)
	}
	if err := validCommand(command.ApprovalID, command.IdempotencyKey, command.ReasonCode, command.ExpectedRevision); err != nil {
		return approvalResult{}, service.failure(ctx, operation, command.ApprovalID, command.Actor, fingerprint, command.ExpectedRevision, err, now)
	}
	material := operationMaterial{Operation: operation, ApprovalID: command.ApprovalID,
		IdempotencyKey: command.IdempotencyKey, ExpectedRevision: command.ExpectedRevision,
		ReasonCode: command.ReasonCode, Actor: command.Actor, Principal: command.Principal,
		GrantAuthorities: append([]approvalGrantAuthority(nil), command.GrantAuthorities...)}
	if command.approvalProof != nil {
		material.Proof = makeProofMaterial(*command.approvalProof)
	}
	digest, err := operationDigest(material)
	if err != nil {
		return approvalResult{}, service.failure(ctx, operation, command.ApprovalID, command.Actor, fingerprint, command.ExpectedRevision, err, now)
	}
	key := recordKey(command.Case.OrganizationID, command.Case.TenantID, command.Case.CaseID, command.ApprovalID)
	stored, err := service.store.Get(ctx, key)
	if err != nil {
		resultErr := mapStorageError(err)
		return approvalResult{}, service.failure(ctx, operation, command.ApprovalID, command.Actor, fingerprint, command.ExpectedRevision, resultErr, now)
	}
	current, err := decodeMetadata(stored)
	if err != nil {
		return approvalResult{}, service.failure(ctx, operation, command.ApprovalID, command.Actor, fingerprint, command.ExpectedRevision, err, now)
	}
	fingerprint = fingerprintFromRecord(current)
	if current.LastOperationDigest == digest && current.Revision == command.ExpectedRevision+1 {
		return approvalResult{Record: current, Replayed: true}, nil
	}
	if current.Revision != command.ExpectedRevision {
		resultErr := lifecycle.NewError(lifecycle.Conflict, "stale_revision")
		return approvalResult{}, service.failure(ctx, operation, command.ApprovalID, command.Actor, fingerprint, current.Revision, resultErr, now)
	}
	if err := validateTransitionActor(operation, command.Actor, current); err != nil {
		return approvalResult{}, service.failure(ctx, operation, command.ApprovalID, command.Actor, fingerprint, current.Revision, err, now)
	}
	if err := service.validateOperation(ctx, operation, command, current, now); err != nil {
		return approvalResult{}, service.failure(ctx, operation, command.ApprovalID, command.Actor, fingerprint, current.Revision, err, now)
	}
	next := current
	next.Revision++
	next.ReasonCode = command.ReasonCode
	next.LastActorID = command.Actor.ActorID
	next.LastActorRevision = command.Actor.Revision
	next.LastOperationDigest = digest
	next.UpdatedAt = formatTime(now)
	eventID, err := service.newEventID(now)
	if err != nil {
		return approvalResult{}, service.failure(ctx, operation, command.ApprovalID, command.Actor, fingerprint, current.Revision, err, now)
	}
	next.LastEventID = eventID
	applyTransition(operation, command, &next, now)
	if err := lifecycle.ValidateTransition(current, next); err != nil {
		return approvalResult{}, service.failure(ctx, operation, command.ApprovalID, command.Actor, fingerprint, current.Revision, err, now)
	}
	return service.commit(ctx, operation, command.IdempotencyKey, current.Revision, next, command.Actor, fingerprint, now)
}

func validateTransitionActor(operation string, actor policy.ActorAuthority, record lifecycle.Record) error {
	permission := "approval.decide"
	if operation == "consume" {
		permission = "action.request"
	} else if operation == "expire" {
		permission = "service.invoke"
	}
	if err := validateActor(actor, record.OrganizationID, record.TenantID, record.CaseID, permission); err != nil {
		return err
	}
	if operation == "grant" && actor.ActorID == record.RequestorActorID {
		return lifecycle.NewError(lifecycle.Denied, "self_approval")
	}
	if operation == "consume" && actor.ActorID != record.ActionOwnerActorID {
		return lifecycle.NewError(lifecycle.Denied, "action_owner_mismatch")
	}
	return nil
}

func (service *approvalService) validateOperation(ctx context.Context, operation string, command approvalTransitionCommand, record lifecycle.Record, now time.Time) error {
	validFrom, fromErr := time.Parse(timestampLayout, record.ValidFrom)
	validUntil, untilErr := time.Parse(timestampLayout, record.ValidUntil)
	if fromErr != nil || untilErr != nil {
		return lifecycle.NewError(lifecycle.Denied, "stored_record_invalid")
	}
	switch operation {
	case "grant":
		if record.State != lifecycle.Requested || now.Before(validFrom) || !now.Before(validUntil) {
			return lifecycle.NewError(lifecycle.Denied, "approval_not_current")
		}
		if command.Principal == nil {
			return lifecycle.NewError(lifecycle.InvalidInput, "approver_authority_required")
		}
		if err := validateApproverPrincipal(command.Actor, *command.Principal, record); err != nil {
			return err
		}
		return service.verifyProof(ctx, command.approvalProof, record)
	case "reject":
		if record.State != lifecycle.Requested {
			return lifecycle.NewError(lifecycle.Denied, "transition_denied")
		}
	case "expire":
		if record.State != lifecycle.Requested && record.State != lifecycle.Granted || now.Before(validUntil) {
			return lifecycle.NewError(lifecycle.Denied, "expiration_not_due")
		}
	case "consume":
		if record.State != lifecycle.Granted || now.Before(validFrom) || !now.Before(validUntil) {
			return lifecycle.NewError(lifecycle.Denied, "approval_not_current")
		}
		if err := validateGrantAuthorities(command.GrantAuthorities, record); err != nil {
			return err
		}
		return service.verifyProof(ctx, command.approvalProof, record)
	case "revoke":
		if record.State != lifecycle.Requested && record.State != lifecycle.Granted {
			return lifecycle.NewError(lifecycle.Denied, "transition_denied")
		}
	default:
		return lifecycle.NewError(lifecycle.InvalidInput, "operation_invalid")
	}
	return nil
}

func (service *approvalService) verifyProof(ctx context.Context, proof *approvalProof, record lifecycle.Record) error {
	if proof == nil {
		return lifecycle.NewError(lifecycle.InvalidInput, "fingerprint_proof_required")
	}
	verified, err := service.verifier.verifyApproval(ctx, proof.Fingerprint, proof.Manifest, proof.Signer, proof.Decision)
	if err != nil || verified.ActionTier != record.ActionTier || !fingerprintMatches(verified.Fingerprint, record) {
		return lifecycle.NewError(lifecycle.Denied, "fingerprint_authority")
	}
	return nil
}

func validateGrantAuthorities(authorities []approvalGrantAuthority, record lifecycle.Record) error {
	if len(authorities) != len(record.Grants) || len(authorities) != int(record.RequiredGrantCount) {
		return lifecycle.NewError(lifecycle.Denied, "approver_enrollment_incomplete")
	}
	for index, grant := range record.Grants {
		authority := authorities[index]
		if authority.Actor.ActorID != grant.ActorID || authority.Principal.PrincipalID != grant.PrincipalID ||
			authority.Actor.Revision < grant.ActorRevision || authority.Principal.EnrollmentRevision < grant.EnrollmentRevision {
			return lifecycle.NewError(lifecycle.Denied, "approver_authority_changed")
		}
		if err := validateApproverPrincipal(authority.Actor, authority.Principal, record); err != nil {
			return err
		}
	}
	return nil
}

func fingerprintMatches(value approvalfingerprint.Fingerprint, record lifecycle.Record) bool {
	left := value.FingerprintDigest + value.ManifestDigest + value.PolicyDecisionDigest + value.OrganizationID + value.TenantID +
		value.CaseID + value.RequestorActorID + value.ActionOwnerActorID + value.ValidFrom + value.ValidUntil + uintText(uint64(value.MaximumUseCount))
	right := record.FingerprintDigest + record.ManifestDigest + record.PolicyDecisionDigest + record.OrganizationID + record.TenantID +
		record.CaseID + record.RequestorActorID + record.ActionOwnerActorID + record.ValidFrom + record.ValidUntil + uintText(uint64(record.MaximumUseCount))
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func applyTransition(operation string, command approvalTransitionCommand, next *lifecycle.Record, now time.Time) {
	switch operation {
	case "grant":
		next.Grants = append(append([]lifecycle.Grant(nil), next.Grants...), lifecycle.Grant{
			ActorID: command.Actor.ActorID, ActorRevision: command.Actor.Revision,
			PrincipalID: command.Principal.PrincipalID, EnrollmentRevision: command.Principal.EnrollmentRevision,
			GrantedAt: formatTime(now)})
		if len(next.Grants) == int(next.RequiredGrantCount) {
			next.State = lifecycle.Granted
		}
	case "reject":
		next.State = lifecycle.Rejected
	case "expire":
		next.State = lifecycle.Expired
	case "consume":
		next.UseCount++
		if next.UseCount == next.MaximumUseCount {
			next.State = lifecycle.Consumed
		}
	case "revoke":
		next.State = lifecycle.Revoked
	}
}

func fingerprintFromRecord(record lifecycle.Record) approvalfingerprint.Fingerprint {
	return approvalfingerprint.Fingerprint{SchemaVersion: approvalfingerprint.SchemaVersion,
		ContractVersion: approvalfingerprint.ContractVersion, FingerprintDigest: record.FingerprintDigest,
		ManifestDigest: record.ManifestDigest, PolicyDecisionDigest: record.PolicyDecisionDigest,
		OrganizationID: record.OrganizationID, TenantID: record.TenantID, CaseID: record.CaseID,
		RequestorActorID: record.RequestorActorID, ActionOwnerActorID: record.ActionOwnerActorID,
		ValidFrom: record.ValidFrom, ValidUntil: record.ValidUntil, MaximumUseCount: record.MaximumUseCount}
}
