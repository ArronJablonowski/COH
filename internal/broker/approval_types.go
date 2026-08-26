// Package broker keeps approval lifecycle authority private to the sole action boundary.
package broker

import (
	"context"
	"io"
	"time"

	"github.com/ArronJablonowski/COH/internal/domain"
	"github.com/ArronJablonowski/COH/internal/domain/actionmanifest"
	lifecycle "github.com/ArronJablonowski/COH/internal/domain/approvallifecycle"
	"github.com/ArronJablonowski/COH/internal/policy"
	"github.com/ArronJablonowski/COH/internal/policy/approvalfingerprint"
	"github.com/ArronJablonowski/COH/internal/workflow"
)

type approvalClock interface{ Now() time.Time }

type approvalAuditSink interface {
	AppendApprovalLifecycleEvent(context.Context, lifecycle.Event) error
}

type approvalFingerprintVerifier interface {
	verifyApproval(context.Context, approvalfingerprint.Fingerprint, actionmanifest.VerifiedEnvelope, actionmanifest.SignerAuthority, policy.Decision) (approvalVerifiedProof, error)
}

type approvalVerifiedProof struct {
	Fingerprint approvalfingerprint.Fingerprint
	ActionTier  string
}

type approvalProof struct {
	Fingerprint approvalfingerprint.Fingerprint
	Manifest    actionmanifest.VerifiedEnvelope
	Signer      actionmanifest.SignerAuthority
	Decision    policy.Decision
}

// approvalPrincipalAuthority is a fresh enrollment-directory result. The
// stable principal identity prevents one human using multiple actor accounts.
type approvalPrincipalAuthority struct {
	ActorID            string `json:"actor_id"`
	ActorRevision      uint64 `json:"actor_revision"`
	PrincipalID        string `json:"principal_id"`
	IdentityKind       string `json:"identity_kind"`
	EnrollmentRevision uint64 `json:"enrollment_revision"`
	Enrolled           bool   `json:"enrolled"`
}

type approvalGrantAuthority struct {
	Actor     policy.ActorAuthority      `json:"actor"`
	Principal approvalPrincipalAuthority `json:"principal"`
}

type approvalRequestCommand struct {
	ApprovalID     string
	IdempotencyKey string
	Requestor      policy.ActorAuthority
	Principal      approvalPrincipalAuthority
	approvalProof  approvalProof
}

type approvalTransitionCommand struct {
	ApprovalID       string
	IdempotencyKey   string
	ExpectedRevision uint64
	Case             domain.CaseRef
	Actor            policy.ActorAuthority
	Principal        *approvalPrincipalAuthority
	GrantAuthorities []approvalGrantAuthority
	ReasonCode       string
	approvalProof    *approvalProof
}

type approvalResult struct {
	Record   lifecycle.Record
	Replayed bool
}

type approvalService struct {
	store    workflow.MetadataStore
	verifier approvalFingerprintVerifier
	audit    approvalAuditSink
	clock    approvalClock
	random   io.Reader
}

func newApprovalServiceWithDependencies(store workflow.MetadataStore, verifier approvalFingerprintVerifier, audit approvalAuditSink, clock approvalClock, random io.Reader) (*approvalService, error) {
	if store == nil || verifier == nil || audit == nil || clock == nil || random == nil {
		return nil, lifecycle.NewError(lifecycle.InvalidInput, "service_configuration")
	}
	return &approvalService{store: store, verifier: verifier, audit: audit, clock: clock, random: random}, nil
}
