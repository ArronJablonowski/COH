package broker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/policy"
	"github.com/ArronJablonowski/COH/internal/policy/approvalfingerprint"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

const timestampLayout = "2006-01-02T15:04:05.000000000Z"

type operationMaterial struct {
	Operation        string                `json:"operation"`
	ApprovalID       string                `json:"approval_id"`
	IdempotencyKey   string                `json:"idempotency_key"`
	ExpectedRevision uint64                `json:"expected_revision"`
	ReasonCode       string                `json:"reason_code"`
	Actor            policy.ActorAuthority `json:"actor"`
	Proof            *proofMaterial        `json:"proof,omitempty"`
}

type proofMaterial struct {
	Fingerprint       approvalfingerprint.Fingerprint `json:"fingerprint"`
	EnvelopeDigest    string                          `json:"envelope_digest"`
	SignerActorID     string                          `json:"signer_actor_id"`
	SignerKeyID       string                          `json:"signer_key_id"`
	SignerKeyRevision uint64                          `json:"signer_key_revision"`
	SignerActive      bool                            `json:"signer_active"`
	SignerKeyDigest   string                          `json:"signer_key_digest"`
	Decision          policy.Decision                 `json:"decision"`
}

func (service *approvalService) requestApproval(ctx context.Context, command approvalRequestCommand) (approvalResult, error) {
	now := service.now()
	if err := contextError(ctx); err != nil {
		return approvalResult{}, service.failure(ctx, "request", command.ApprovalID, command.Requestor, command.approvalProof.Fingerprint, 0, err, now)
	}
	if err := validCommand(command.ApprovalID, command.IdempotencyKey, "approval_requested", 1); err != nil {
		return approvalResult{}, service.failure(ctx, "request", command.ApprovalID, command.Requestor, command.approvalProof.Fingerprint, 0, err, now)
	}
	fingerprint := command.approvalProof.Fingerprint
	if err := validateActor(command.Requestor, fingerprint.OrganizationID, fingerprint.TenantID, fingerprint.CaseID, "action.request"); err != nil {
		return approvalResult{}, service.failure(ctx, "request", command.ApprovalID, command.Requestor, fingerprint, 0, err, now)
	}
	if command.Requestor.ActorID != fingerprint.RequestorActorID {
		err := lifecycle.NewError(lifecycle.Denied, "requestor_binding")
		return approvalResult{}, service.failure(ctx, "request", command.ApprovalID, command.Requestor, fingerprint, 0, err, now)
	}
	digest, err := operationDigest(operationMaterial{Operation: "request", ApprovalID: command.ApprovalID,
		IdempotencyKey: command.IdempotencyKey, ExpectedRevision: 0, ReasonCode: "approval_requested",
		Actor: command.Requestor, Proof: makeProofMaterial(command.approvalProof)})
	if err != nil {
		return approvalResult{}, service.failure(ctx, "request", command.ApprovalID, command.Requestor, fingerprint, 0, err, now)
	}
	key := recordKey(fingerprint.OrganizationID, fingerprint.TenantID, fingerprint.CaseID, command.ApprovalID)
	if stored, getErr := service.store.Get(ctx, key); getErr == nil {
		record, decodeErr := decodeMetadata(stored)
		if decodeErr == nil && record.LastOperationDigest == digest {
			return approvalResult{Record: record, Replayed: true}, nil
		}
		resultErr := lifecycle.NewError(lifecycle.Conflict, "approval_exists")
		return approvalResult{}, service.failure(ctx, "request", command.ApprovalID, command.Requestor, fingerprint, stored.Revision, resultErr, now)
	} else if workflow.StorageCode(getErr) != workflow.StorageNotFound {
		resultErr := mapStorageError(getErr)
		return approvalResult{}, service.failure(ctx, "request", command.ApprovalID, command.Requestor, fingerprint, 0, resultErr, now)
	}
	verified, err := service.verifier.Verify(ctx, fingerprint, command.approvalProof.Manifest, command.approvalProof.Signer, command.approvalProof.Decision)
	if err != nil || verified.FingerprintDigest != fingerprint.FingerprintDigest {
		resultErr := lifecycle.NewError(lifecycle.Denied, "fingerprint_authority")
		return approvalResult{}, service.failure(ctx, "request", command.ApprovalID, command.Requestor, fingerprint, 0, resultErr, now)
	}
	eventID, err := service.newEventID(now)
	if err != nil {
		return approvalResult{}, service.failure(ctx, "request", command.ApprovalID, command.Requestor, fingerprint, 0, err, now)
	}
	record := lifecycle.Record{SchemaVersion: lifecycle.SchemaVersion, ContractVersion: lifecycle.ContractVersion,
		ApprovalID: command.ApprovalID, OrganizationID: fingerprint.OrganizationID, TenantID: fingerprint.TenantID,
		CaseID: fingerprint.CaseID, FingerprintDigest: fingerprint.FingerprintDigest, ManifestDigest: fingerprint.ManifestDigest,
		PolicyDecisionDigest: fingerprint.PolicyDecisionDigest, RequestorActorID: fingerprint.RequestorActorID,
		RequestorRevision: command.Requestor.Revision, ActionOwnerActorID: fingerprint.ActionOwnerActorID,
		State: lifecycle.Requested, Revision: 1, RequestedAt: formatTime(now), ValidFrom: fingerprint.ValidFrom,
		ValidUntil: fingerprint.ValidUntil, RequiredGrantCount: 1, Grants: []lifecycle.Grant{},
		MaximumUseCount: fingerprint.MaximumUseCount, UseCount: 0, ReasonCode: "approval_requested",
		LastActorID: command.Requestor.ActorID, LastActorRevision: command.Requestor.Revision,
		LastOperationDigest: digest, LastEventID: eventID, UpdatedAt: formatTime(now)}
	return service.commit(ctx, "request", command.IdempotencyKey, 0, record, command.Requestor, fingerprint, now)
}

func makeProofMaterial(proof approvalProof) *proofMaterial {
	envelopeSum := sha256.Sum256(proof.Manifest.CanonicalEnvelopeBytes())
	keySum := sha256.Sum256(proof.Signer.PublicKey)
	return &proofMaterial{Fingerprint: proof.Fingerprint, EnvelopeDigest: "sha256:" + hex.EncodeToString(envelopeSum[:]),
		SignerActorID: proof.Signer.ActorID, SignerKeyID: proof.Signer.KeyID, SignerKeyRevision: proof.Signer.KeyRevision,
		SignerActive: proof.Signer.Active, SignerKeyDigest: "sha256:" + hex.EncodeToString(keySum[:]), Decision: proof.Decision}
}

func (service *approvalService) now() time.Time {
	if service == nil || service.clock == nil {
		return time.Time{}
	}
	return service.clock.Now().UTC()
}

func (service *approvalService) newEventID(now time.Time) (string, error) {
	if service == nil || service.random == nil || now.IsZero() {
		return "", lifecycle.NewError(lifecycle.Unavailable, "event_identity_unavailable")
	}
	id, err := newID(now, service.random)
	if err != nil {
		return "", lifecycle.NewError(lifecycle.Unavailable, "event_identity_unavailable")
	}
	return id, nil
}

func formatTime(value time.Time) string { return value.UTC().Format(timestampLayout) }

func proofFingerprint(proof *approvalProof) approvalfingerprint.Fingerprint {
	if proof == nil {
		return approvalfingerprint.Fingerprint{}
	}
	return proof.Fingerprint
}
